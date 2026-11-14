package account

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	return s, dir
}

func newAccount(t *testing.T, name string) *Account {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	return &Account{ID: id, Name: name, Created: time.Now().UTC(), Password: "$argon2id$placeholder"}
}

var ctx = context.Background()

func TestCreateAndGetIgnoringCase(t *testing.T) {
	s, _ := newStore(t)
	a := newAccount(t, "Mara")
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, name := range []string{"Mara", "mara", "MARA"} {
		got, err := s.Get(ctx, name)
		if err != nil || got.ID != a.ID || got.Name != "Mara" || got.Revision != 1 || got.Schema != Schema {
			t.Fatalf("Get(%q) = %+v, %v", name, got, err)
		}
	}
	if err := s.Create(ctx, newAccount(t, "MARA")); !errors.Is(err, ErrExists) {
		t.Fatalf("Create(MARA) after Mara = %v, want ErrExists", err)
	}
	if _, err := s.Get(ctx, "Teo"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(unknown) = %v, want ErrNotFound", err)
	}
}

func TestNamesRefused(t *testing.T) {
	s, _ := newStore(t)
	for _, name := range []string{"ab", "1abc", "a b", "ab-c", "abcdefghijklmnopqrstu", "Mára", "../../etc", "new", "Admin"} {
		if err := s.Create(ctx, newAccount(t, name)); !errors.Is(err, ErrBadName) && !errors.Is(err, ErrReservedName) {
			t.Errorf("Create(%q) = %v, want a bad or reserved name", name, err)
		}
	}
	// A hostile name passed to Get cannot reach outside the store.
	for _, name := range []string{"../../etc/passwd", "a/b", "..", ""} {
		if _, err := s.Get(ctx, name); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = %v, want ErrNotFound", name, err)
		}
	}
}

// Two writers that read the same revision: the second is refused rather
// than silently overwriting the first (a staff reset racing a login).
func TestUpdateRefusesStaleRevision(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Create(ctx, newAccount(t, "Mara")); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Get(ctx, "mara")
	b, _ := s.Get(ctx, "mara")
	a.Email = "first@example.invalid"
	if err := s.Update(ctx, a); err != nil || a.Revision != 2 {
		t.Fatalf("first Update = %v, revision %d; want nil, 2", err, a.Revision)
	}
	b.Email = "second@example.invalid"
	if err := s.Update(ctx, b); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale Update = %v, want ErrConflict", err)
	}
	got, _ := s.Get(ctx, "mara")
	if got.Email != "first@example.invalid" {
		t.Fatalf("after the refused update, email = %q, want the first writer's", got.Email)
	}
}

// Many writers at once, as goroutines and through separate store handles
// (as the gateway and a staff command would be): every update lands on a
// revision it read, none is lost to a race.
func TestConcurrentUpdatesSerialise(t *testing.T) {
	s, dir := newStore(t)
	if err := s.Create(ctx, newAccount(t, "Mara")); err != nil {
		t.Fatal(err)
	}
	const writers = 8
	var wg sync.WaitGroup
	wins := make(chan int64, writers*20)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other, err := OpenFileStore(dir) // a second handle on the same directory
			if err != nil {
				return
			}
			for j := 0; j < 20; j++ {
				a, err := other.Get(ctx, "mara")
				if err != nil {
					return
				}
				if other.Update(ctx, a) == nil {
					wins <- a.Revision
				}
			}
		}()
	}
	wg.Wait()
	close(wins)
	seen := map[int64]bool{}
	for r := range wins {
		if seen[r] {
			t.Fatalf("two writers both produced revision %d: an update was lost", r)
		}
		seen[r] = true
	}
	final, _ := s.Get(ctx, "mara")
	if int(final.Revision) != len(seen)+1 {
		t.Fatalf("final revision %d after %d successful updates, want %d", final.Revision, len(seen), len(seen)+1)
	}
}

func TestFilesArePrivate(t *testing.T) {
	s, dir := newStore(t)
	if err := s.Create(ctx, newAccount(t, "Mara")); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{
		dir:                            0o700,
		filepath.Join(dir, "accounts"): 0o700,
		filepath.Join(dir, "accounts", "mara.json"): 0o600,
	} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", p, st.Mode().Perm(), want)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "accounts", ".tmp-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// A record from a newer engine, or a damaged one, is refused rather than
// half-read.
func TestUnreadableRecordsRefused(t *testing.T) {
	s, dir := newStore(t)
	p := filepath.Join(dir, "accounts", "mara.json")
	for name, content := range map[string]string{
		"newer schema": `{"schema": 99, "id": "x", "name": "Mara"}`,
		"no schema":    `{"id": "x", "name": "Mara"}`,
		"not JSON":     `garbage`,
		"too large":    `{"schema":1,"name":"Mara","email":"` + string(make([]byte, maxRecord)) + `"}`,
	} {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if a, err := s.Get(ctx, "mara"); err == nil {
			t.Errorf("%s: Get = %+v, want an error", name, a)
		}
	}
}

func TestInvites(t *testing.T) {
	s, dir := newStore(t)
	code, err := NewInviteCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddInvite(ctx, code, "staff1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("AddInvite: %v", err)
	}
	// The directory holds only a hash of the code.
	files, _ := filepath.Glob(filepath.Join(dir, "invites", "*"))
	for _, f := range files {
		if b, _ := os.ReadFile(f); len(b) > 0 && (contains(f, code) || contains(string(b), code)) {
			t.Fatal("the invite code itself is stored")
		}
	}
	if err := s.Create(ctx, newAccount(t, "Mara")); err != nil {
		t.Fatal(err)
	}
	// A taken name does not use up the invite.
	if err := s.CreateWithInvite(ctx, newAccount(t, "mara"), code); !errors.Is(err, ErrExists) {
		t.Fatalf("CreateWithInvite(taken name) = %v, want ErrExists", err)
	}
	if err := s.CreateWithInvite(ctx, newAccount(t, "Teo"), lower(code)); err != nil {
		t.Fatalf("CreateWithInvite(code typed in lower case) = %v", err)
	}
	if err := s.CreateWithInvite(ctx, newAccount(t, "Ana"), code); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("second use of an invite = %v, want ErrInviteInvalid", err)
	}
	expired, _ := NewInviteCode()
	s.AddInvite(ctx, expired, "staff1", time.Now().Add(-time.Minute))
	if err := s.CreateWithInvite(ctx, newAccount(t, "Ana"), expired); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("expired invite = %v, want ErrInviteInvalid", err)
	}
	if _, err := s.Get(ctx, "ana"); !errors.Is(err, ErrNotFound) {
		t.Fatal("an account was created from an invalid invite")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
func lower(s string) string       { return strings.ToLower(s) }

// A name crafted to climb out of the accounts directory must not read a
// record placed beside it.
func TestTraversalCannotReadOutsideStore(t *testing.T) {
	s, dir := newStore(t)
	outside := `{"schema":1,"id":"planted","name":"Planted","password":"x"}`
	if err := os.WriteFile(filepath.Join(dir, "planted.json"), []byte(outside), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../planted", "..\\planted", "./../planted"} {
		if a, err := s.Get(ctx, name); err == nil {
			t.Fatalf("Get(%q) read %+v from outside the accounts directory", name, a)
		}
	}
}

// The size cap on its own refuses an oversize record that is otherwise
// valid JSON.
func TestOversizeRecordRefused(t *testing.T) {
	s, dir := newStore(t)
	big := `{"schema":1,"id":"x","name":"Mara","password":"p","email":"` + strings.Repeat("a", maxRecord) + `"}`
	if err := os.WriteFile(filepath.Join(dir, "accounts", "mara.json"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := s.Get(ctx, "mara"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Get(oversize record) = %+v, %v; want the size refusal", a, err)
	}
}

// A server's own reserved names are merged with the built-in ones by
// default, or replace them; the words the login prompt uses stay reserved
// either way.
func TestServerReservedNames(t *testing.T) {
	merged, err := NewNames([]string{"Aldric", " Vesper "}, false)
	if err != nil {
		t.Fatalf("NewNames: %v", err)
	}
	for name, want := range map[string]bool{"aldric": true, "VESPER": true, "admin": true, "new": true, "Mara": false} {
		if merged.Reserved(name) != want {
			t.Errorf("merged policy: Reserved(%q) = %v, want %v", name, !want, want)
		}
	}
	replaced, err := NewNames([]string{"Aldric"}, true)
	if err != nil {
		t.Fatalf("NewNames: %v", err)
	}
	for name, want := range map[string]bool{"aldric": true, "admin": false, "staff": false, "new": true, "quit": true, "help": true} {
		if replaced.Reserved(name) != want {
			t.Errorf("replacing policy: Reserved(%q) = %v, want %v", name, !want, want)
		}
	}
	// A typo in the setting is an error, not a silently useless entry.
	if _, err := NewNames([]string{"Lord Aldric"}, false); err == nil {
		t.Error("NewNames accepted a reserved name with a space in it")
	}

	s, _ := newStore(t)
	s.Names = merged
	if err := s.Create(ctx, newAccount(t, "Aldric")); !errors.Is(err, ErrReservedName) {
		t.Fatalf("Create(Aldric) under a policy reserving it = %v, want ErrReservedName", err)
	}
	code, _ := NewInviteCode()
	s.AddInvite(ctx, code, "staff1", time.Now().Add(time.Hour))
	if err := s.CreateWithInvite(ctx, newAccount(t, "Vesper"), code); !errors.Is(err, ErrReservedName) {
		t.Fatalf("CreateWithInvite(Vesper) = %v, want ErrReservedName", err)
	}
	if err := s.CreateWithInvite(ctx, newAccount(t, "Teo"), code); err != nil {
		t.Fatalf("the invite was used up by the refused reserved name: %v", err)
	}
	s2, _ := newStore(t)
	s2.Names = replaced
	if err := s2.Create(ctx, newAccount(t, "Admin")); err != nil {
		t.Fatalf("Create(Admin) when the built-in list is replaced = %v, want allowed", err)
	}
}
