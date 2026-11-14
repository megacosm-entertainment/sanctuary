package account

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Tests use a cheap cost; the format and logic are the same.
var testParams = Params{MemoryKiB: 64, Passes: 1, Lanes: 1}

func TestHashAndVerify(t *testing.T) {
	h := NewHasher(testParams, 2)
	ctx := context.Background()
	stored, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(stored, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("hash %q is not PHC argon2id with the parameters recorded", stored)
	}
	for pw, want := range map[string]bool{
		"correct horse battery staple": true,
		"correct horse battery stapl":  false,
		"Correct horse battery staple": false,
		"":                             false,
	} {
		ok, err := h.Verify(ctx, stored, pw)
		if err != nil || ok != want {
			t.Errorf("Verify(%q) = %v, %v; want %v", pw, ok, err, want)
		}
	}
	again, _ := h.Hash(ctx, "correct horse battery staple")
	if again == stored {
		t.Fatal("two hashes of one password are identical: the salt is not random")
	}
}

// An unknown account (empty stored hash) is never a match, and costs a
// real hash, so timing does not reveal which names exist.
func TestUnknownAccountNeverMatches(t *testing.T) {
	h := NewHasher(testParams, 1)
	for _, pw := range []string{"", "anything", strings.Repeat("x", 2000)} {
		ok, err := h.Verify(context.Background(), "", pw)
		if err != nil || ok {
			t.Fatalf("Verify(no account, %q) = %v, %v; want false, nil", pw, ok, err)
		}
	}
}

func TestCheckNewPassword(t *testing.T) {
	cases := map[string]error{
		"short":                   ErrPasswordTooShort,
		"ninechars":               ErrPasswordTooShort,
		"tencharsok":              nil,
		"日本語のパスワードです":             nil, // ten characters, more bytes
		strings.Repeat("x", 1025): ErrPasswordTooLong,
	}
	for pw, want := range cases {
		if err := CheckNewPassword(pw); !errors.Is(err, want) && err != want {
			t.Errorf("CheckNewPassword(%d chars) = %v, want %v", len([]rune(pw)), err, want)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	weak, _ := NewHasher(testParams, 1).Hash(context.Background(), "a password here")
	strong := NewHasher(Params{MemoryKiB: 128, Passes: 2, Lanes: 1}, 1)
	if !strong.NeedsRehash(weak) {
		t.Fatal("a hash with weaker parameters was not flagged for rehash")
	}
	fresh, _ := strong.Hash(context.Background(), "a password here")
	if strong.NeedsRehash(fresh) {
		t.Fatal("a hash at the current parameters was flagged for rehash")
	}
}

// A corrupt or hostile stored hash must be refused, not run with absurd
// parameters (1 TiB of memory, a million passes).
func TestBadStoredHashRefused(t *testing.T) {
	h := NewHasher(testParams, 1)
	for _, bad := range []string{
		"plaintext",
		"$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=16$m=64,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=1073741824,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=64,t=1000000,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=64,t=1,p=0$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=64,t=1,p=1,x=2$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=64,t=1,p=1$!!$a2V5a2V5a2V5a2V5a2V5aw",
	} {
		if ok, err := h.Verify(context.Background(), bad, "x"); !errors.Is(err, ErrBadHash) || ok {
			t.Errorf("Verify(%q) = %v, %v; want ErrBadHash", bad, ok, err)
		}
	}
}

// At most max hashes run at once; past that a caller waits, and gives up
// with ErrBusy when its context ends.
func TestHasherBoundsConcurrency(t *testing.T) {
	h := NewHasher(testParams, 1)
	h.slots <- struct{}{} // the one slot is taken
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "a password here"); !errors.Is(err, ErrBusy) {
		t.Fatalf("Hash with no free slot = %v, want ErrBusy", err)
	}
	if _, err := h.Verify(ctx, "", "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("Verify with no free slot = %v, want ErrBusy", err)
	}
	<-h.slots
	if _, err := h.Hash(context.Background(), "a password here"); err != nil {
		t.Fatalf("Hash once the slot is free: %v", err)
	}
}

// Each parameter on its own triggers a rehash, not only all of them
// together.
func TestNeedsRehashEachParameter(t *testing.T) {
	base := Params{MemoryKiB: 64, Passes: 1, Lanes: 1}
	stored, _ := NewHasher(base, 1).Hash(context.Background(), "a password here")
	for name, p := range map[string]Params{
		"more memory": {MemoryKiB: 128, Passes: 1, Lanes: 1},
		"more passes": {MemoryKiB: 64, Passes: 2, Lanes: 1},
		"more lanes":  {MemoryKiB: 64, Passes: 1, Lanes: 2},
	} {
		if !NewHasher(p, 1).NeedsRehash(stored) {
			t.Errorf("%s: a hash with the old setting was not flagged for rehash", name)
		}
	}
}
