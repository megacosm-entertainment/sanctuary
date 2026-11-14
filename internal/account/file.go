package account

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// FileStore keeps accounts as JSON files: DIR/accounts/<key>.json, and
// invites as DIR/invites/<hash>.json. It is the zero-dependency default
// (design §03); one host only (design §04, "Distributed deployment").
//
// Every change happens under an exclusive lock on DIR/.lock, held across
// processes, so the running gateway and a staff command can both write
// safely. Files are written atomically (temporary file, fsync, rename,
// fsync of the directory), so a crash leaves the old or the new record,
// never half of one. Files are mode 0600 in 0700 directories: they hold
// password hashes.
type FileStore struct {
	dir string
	// Names is the policy new account names must meet; the zero value is
	// DefaultNames. Set it before use, from the server's settings.
	Names Names
}

// maxRecord bounds an account file read back, so a damaged or tampered
// file cannot make a login allocate without limit.
const maxRecord = 64 << 10

// OpenFileStore opens (creating if needed) a store in dir.
func OpenFileStore(dir string) (*FileStore, error) {
	for _, d := range []string{dir, filepath.Join(dir, "accounts"), filepath.Join(dir, "invites")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) accountPath(name string) (string, error) {
	// Only names that pass CheckName's character rules reach the disk,
	// so a key can never contain a path separator or "..".
	k := Key(name)
	for _, c := range []byte(k) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return "", ErrNotFound
		}
	}
	if k == "" || len(k) > MaxName {
		return "", ErrNotFound
	}
	return filepath.Join(s.dir, "accounts", k+".json"), nil
}

// lock takes the store's cross-process lock; the returned func releases it.
func (s *FileStore) lock(ctx context.Context) (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (s *FileStore) Get(ctx context.Context, name string) (*Account, error) {
	p, err := s.accountPath(name)
	if err != nil {
		return nil, err
	}
	return readAccount(p)
}

func readAccount(p string) (*Account, error) {
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxRecord {
		return nil, fmt.Errorf("account: %s is larger than %d bytes", filepath.Base(p), maxRecord)
	}
	var a Account
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("account: %s: %w", filepath.Base(p), err)
	}
	if a.Schema < 1 || a.Schema > Schema {
		return nil, fmt.Errorf("account: %s has schema %d; this engine reads 1 to %d", filepath.Base(p), a.Schema, Schema)
	}
	return &a, nil
}

func (s *FileStore) Create(ctx context.Context, a *Account) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.createLocked(a)
}

func (s *FileStore) createLocked(a *Account) error {
	if err := s.Names.Check(a.Name); err != nil {
		return err
	}
	p, err := s.accountPath(a.Name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	a.Schema, a.Revision = Schema, 1
	return writeAtomic(p, a)
}

func (s *FileStore) CreateWithInvite(ctx context.Context, a *Account, code string) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	// Check the name first: a taken name must not use up the invite.
	if err := s.Names.Check(a.Name); err != nil {
		return err
	}
	if p, err := s.accountPath(a.Name); err != nil {
		return err
	} else if _, err := os.Stat(p); err == nil {
		return ErrExists
	}
	ip := s.invitePath(code)
	inv, err := readInvite(ip)
	if err != nil || time.Now().After(inv.Expires) {
		return ErrInviteInvalid
	}
	if err := s.createLocked(a); err != nil {
		return err
	}
	return os.Remove(ip)
}

func (s *FileStore) Update(ctx context.Context, a *Account) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	p, err := s.accountPath(a.Name)
	if err != nil {
		return err
	}
	cur, err := readAccount(p)
	if err != nil {
		return err
	}
	if cur.Revision != a.Revision || cur.ID != a.ID {
		return ErrConflict
	}
	next := *a
	next.Revision++
	if err := writeAtomic(p, &next); err != nil {
		return err
	}
	a.Revision = next.Revision
	return nil
}

// ── Invites ─────────────────────────────────────────────────

type invite struct {
	Created time.Time `json:"created"`
	By      string    `json:"by"`
	Expires time.Time `json:"expires"`
}

// invitePath names an invite by a hash of its code, so a copy of the
// directory does not reveal usable codes.
func (s *FileStore) invitePath(code string) string {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("invite:" + norm))
	return filepath.Join(s.dir, "invites", hex.EncodeToString(sum[:])+".json")
}

func (s *FileStore) AddInvite(ctx context.Context, code, by string, expires time.Time) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return writeAtomic(s.invitePath(code), &invite{Created: time.Now().UTC(), By: by, Expires: expires.UTC()})
}

func readInvite(p string) (*invite, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var inv invite
	if err := json.Unmarshal(b, &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

// NewInviteCode returns a fresh code in the same unambiguous alphabet as
// recovery codes.
func NewInviteCode() (string, error) {
	codes, _, err := NewRecoveryCodes()
	if err != nil {
		return "", err
	}
	return codes[0], nil
}

// ── Atomic writes ───────────────────────────────────────────

func writeAtomic(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
