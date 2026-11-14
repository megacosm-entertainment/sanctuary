package account

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseKey(t *testing.T) {
	text, err := NewKeyText()
	if err != nil {
		t.Fatal(err)
	}
	b64, err := ParseKey([]byte("  " + text + "\n"))
	if err != nil {
		t.Fatalf("base64 key: %v", err)
	}
	raw := make([]byte, KeyLen)
	for i := range raw {
		raw[i] = byte(i)
	}
	if _, err := ParseKey([]byte(hex.EncodeToString(raw))); err != nil {
		t.Fatalf("hex key: %v", err)
	}
	// A secret sealed with one form opens with the same key in the other.
	sealed, _ := b64.Seal([]byte("s"), "id")
	if _, err := b64.Open(sealed, "id"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "short", hex.EncodeToString(raw[:16]), strings.Repeat("z", 64)} {
		_, err := ParseKey([]byte(bad))
		if err == nil {
			t.Errorf("ParseKey(%q) accepted", bad)
		} else if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("error %q repeats the key text", err)
		}
	}
}

func TestLoadOrCreateKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "account.key")
	k1, created, err := LoadOrCreateKeyFile(p)
	if err != nil || !created {
		t.Fatalf("first load: created %v, %v", created, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", st.Mode().Perm())
	}
	k2, created, err := LoadOrCreateKeyFile(p)
	if err != nil || created {
		t.Fatalf("second load: created %v, %v", created, err)
	}
	sealed, _ := k1.Seal([]byte("secret"), "id")
	if _, err := k2.Open(sealed, "id"); err != nil {
		t.Fatal("the key read back is not the key written")
	}
	os.WriteFile(p, []byte("not a key"), 0o600)
	if _, _, err := LoadOrCreateKeyFile(p); err == nil {
		t.Fatal("a damaged key file was accepted (it must not be replaced: secrets sealed with it would be lost)")
	}
}
