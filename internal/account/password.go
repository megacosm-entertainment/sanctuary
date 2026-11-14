package account

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id (RFC 9106) is the password hash: memory-hard, so guessing on
// GPUs is expensive. It comes from golang.org/x/crypto because the
// standard library has no memory-hard KDF; see docs/coding.md §3.

// Params are Argon2id cost parameters. They are written into every hash,
// so raising them later affects new hashes, and NeedsRehash tells the
// caller to upgrade an old one at the next successful login.
type Params struct {
	MemoryKiB uint32 // memory per hash
	Passes    uint32 // time cost
	Lanes     uint8  // parallelism
}

// DefaultParams: 64 MiB, 2 passes, 2 lanes, within RFC 9106 §4 and the
// OWASP password storage guidance, about 100-200 ms on current hardware.
var DefaultParams = Params{MemoryKiB: 64 * 1024, Passes: 2, Lanes: 2}

const (
	saltLen = 16 // RFC 9106 recommends 16 bytes
	keyLen  = 32
	// MinPassword and MaxPassword bound a new password (NIST SP 800-63B:
	// length is the useful rule, composition rules are not). The maximum
	// keeps hashing input bounded; it is far beyond any passphrase.
	MinPassword = 10
	MaxPassword = 1024
)

// Errors from the password functions.
var (
	ErrPasswordTooShort = fmt.Errorf("account: a password needs at least %d characters", MinPassword)
	ErrPasswordTooLong  = fmt.Errorf("account: a password may be at most %d bytes", MaxPassword)
	ErrBusy             = errors.New("account: too many logins are being checked; try again in a moment")
	ErrBadHash          = errors.New("account: stored password hash is not a valid argon2id hash")
)

// CheckNewPassword applies the length rule to a password being set.
func CheckNewPassword(pw string) error {
	if len(pw) > MaxPassword {
		return ErrPasswordTooLong
	}
	if utf8.RuneCountInString(pw) < MinPassword {
		return ErrPasswordTooShort
	}
	return nil
}

// Hasher hashes and checks passwords with a bound on how many run at once:
// each Argon2id call holds MemoryKiB of memory, so a flood of logins must
// queue (or be told the server is busy), never exhaust memory.
type Hasher struct {
	Params Params
	slots  chan struct{}
	dummy  string // a hash checked when the account does not exist
}

// NewHasher returns a hasher allowing max concurrent hashes (default 4).
func NewHasher(p Params, max int) *Hasher {
	if p == (Params{}) {
		p = DefaultParams
	}
	if max <= 0 {
		max = 4
	}
	h := &Hasher{Params: p, slots: make(chan struct{}, max)}
	h.dummy = h.encode(make([]byte, saltLen), make([]byte, keyLen), p)
	return h
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrBusy
	}
}

func (h *Hasher) release() { <-h.slots }

// Hash returns a PHC-format Argon2id hash of pw with a fresh random salt.
func (h *Hasher) Hash(ctx context.Context, pw string) (string, error) {
	if len(pw) > MaxPassword {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	key := argon2.IDKey([]byte(pw), salt, h.Params.Passes, h.Params.MemoryKiB, h.Params.Lanes, keyLen)
	return h.encode(salt, key, h.Params), nil
}

// Verify reports whether pw matches the stored hash, comparing in constant
// time. An empty stored hash (an unknown account) is checked against a
// dummy hash at the current cost, so the time taken does not reveal
// whether an account exists.
func (h *Hasher) Verify(ctx context.Context, stored, pw string) (bool, error) {
	if len(pw) > MaxPassword {
		pw = pw[:MaxPassword] // still spend the time; it cannot match a valid hash
	}
	unknown := stored == ""
	if unknown {
		stored = h.dummy
	}
	p, salt, want, err := decode(stored)
	if err != nil {
		return false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(pw), salt, p.Passes, p.MemoryKiB, p.Lanes, uint32(len(want)))
	ok := subtle.ConstantTimeCompare(got, want) == 1
	return ok && !unknown, nil
}

// NeedsRehash reports whether stored was made with weaker parameters than
// the hasher's, so a successful login should store a fresh hash.
func (h *Hasher) NeedsRehash(stored string) bool {
	p, _, _, err := decode(stored)
	if err != nil {
		return true
	}
	return p.MemoryKiB < h.Params.MemoryKiB || p.Passes < h.Params.Passes || p.Lanes < h.Params.Lanes
}

var b64 = base64.RawStdEncoding

func (h *Hasher) encode(salt, key []byte, p Params) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Passes, p.Lanes, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// Bounds on decoded parameters: a corrupt or hostile stored hash must not
// make one login allocate gigabytes or run for minutes.
const (
	maxMemoryKiB = 1 << 20 // 1 GiB
	maxPasses    = 16
)

func decode(s string) (Params, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Params{}, nil, nil, ErrBadHash
	}
	var p Params
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil {
			return Params{}, nil, nil, ErrBadHash
		}
		switch k {
		case "m":
			p.MemoryKiB = uint32(n)
		case "t":
			p.Passes = uint32(n)
		case "p":
			if n > 255 {
				return Params{}, nil, nil, ErrBadHash
			}
			p.Lanes = uint8(n)
		default:
			return Params{}, nil, nil, ErrBadHash
		}
	}
	if p.MemoryKiB < 8*uint32(p.Lanes) || p.MemoryKiB > maxMemoryKiB || p.Passes < 1 || p.Passes > maxPasses || p.Lanes < 1 {
		return Params{}, nil, nil, ErrBadHash
	}
	salt, err1 := b64.DecodeString(parts[4])
	key, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 || len(key) > 64 {
		return Params{}, nil, nil, ErrBadHash
	}
	return p, salt, key, nil
}
