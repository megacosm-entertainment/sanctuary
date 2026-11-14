package account

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (SHA-1, 8 digits there; the last 6
// digits of each are the 6-digit code for the same step).
func TestTOTPMatchesRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}
	for unix, eight := range vectors {
		step := unix / 30
		if got, want := totpAt(secret, step), eight[2:]; got != want {
			t.Errorf("code at %d = %s, want %s (RFC 6238 vector %s)", unix, got, want, eight)
		}
		if got := TOTPCode(secret, time.Unix(unix, 0)); got != eight[2:] {
			t.Errorf("TOTPCode at %d = %s, want %s", unix, got, eight[2:])
		}
	}
}

func TestCheckTOTP(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	step := now.Unix() / 30
	code := totpAt(secret, step)
	got, ok := CheckTOTP(secret, code, now, 0)
	if !ok || got != step {
		t.Fatalf("CheckTOTP(current code) = %d, %v; want %d, true", got, ok, step)
	}
	if _, ok := CheckTOTP(secret, code[:3]+" "+code[3:], now, 0); !ok {
		t.Error("a code typed with a space was refused")
	}
	// One step of clock drift either way is accepted, two is not.
	if _, ok := CheckTOTP(secret, totpAt(secret, step-1), now, 0); !ok {
		t.Error("the previous step's code was refused")
	}
	if _, ok := CheckTOTP(secret, totpAt(secret, step+2), now, 0); ok {
		t.Error("a code two steps ahead was accepted")
	}
	// RFC 6238 §5.2: a code, once used, cannot be used again.
	if _, ok := CheckTOTP(secret, code, now, step); ok {
		t.Error("a replayed code was accepted")
	}
	if _, ok := CheckTOTP(secret, totpAt(secret, step-1), now, step); ok {
		t.Error("an older code was accepted after a newer one")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := CheckTOTP(secret, bad, now, 0); ok {
			t.Errorf("CheckTOTP(%q) accepted", bad)
		}
	}
}

func TestTOTPDisplayAndURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	if got := TOTPDisplay(secret); got != "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ" {
		t.Errorf("TOTPDisplay = %q", got)
	}
	uri := TOTPURI("Sanctuary", "Mara", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/Sanctuary:Mara?") {
		t.Errorf("TOTPURI = %q", uri)
	}
	for _, p := range []string{"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer=Sanctuary", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(uri, p) {
			t.Errorf("TOTPURI = %q, missing %s", uri, p)
		}
	}
}

func TestSealedSecrets(t *testing.T) {
	key, err := NewSecretKey(bytes.Repeat([]byte{7}, KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("12345678901234567890")
	sealed, err := key.Seal(secret, "acct-1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "GEZD") || bytes.Contains([]byte(sealed), secret) {
		t.Fatal("sealed value contains the secret")
	}
	got, err := key.Open(sealed, "acct-1")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	// Copied to another account: refused.
	if _, err := key.Open(sealed, "acct-2"); !errors.Is(err, ErrSealed) {
		t.Fatalf("Open with another account's id = %v, want ErrSealed", err)
	}
	other, _ := NewSecretKey(bytes.Repeat([]byte{8}, KeyLen))
	if _, err := other.Open(sealed, "acct-1"); !errors.Is(err, ErrSealed) {
		t.Fatalf("Open with another key = %v, want ErrSealed", err)
	}
	if _, err := NewSecretKey([]byte("short")); !errors.Is(err, ErrBadKey) {
		t.Fatalf("NewSecretKey(short) = %v, want ErrBadKey", err)
	}
}

func TestRecoveryCodes(t *testing.T) {
	shown, stored, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(shown) != RecoveryCodes || len(stored) != RecoveryCodes {
		t.Fatalf("got %d codes, %d hashes; want %d", len(shown), len(stored), RecoveryCodes)
	}
	for i, c := range shown {
		if len(c) != 11 || c[5] != '-' || strings.ContainsAny(c, "01ILO") {
			t.Errorf("code %q is not two groups of five from the unambiguous alphabet", c)
		}
		if strings.Contains(stored[i], c) || strings.Contains(stored[i], strings.ReplaceAll(c, "-", "")) {
			t.Error("a stored entry contains the code itself")
		}
	}
	// Typed in lower case without the dash: still accepted, once.
	typed := strings.ToLower(strings.ReplaceAll(shown[3], "-", ""))
	rest, ok := UseRecoveryCode(stored, typed)
	if !ok || len(rest) != RecoveryCodes-1 {
		t.Fatalf("UseRecoveryCode(valid) = %v with %d left", ok, len(rest))
	}
	if _, ok := UseRecoveryCode(rest, typed); ok {
		t.Fatal("a recovery code worked twice")
	}
	if _, ok := UseRecoveryCode(stored, "ZZZZZ-ZZZZZ"); ok {
		t.Fatal("an invented code was accepted")
	}
}

// Every letter of the alphabet is about equally likely (no modulo bias).
func TestUniformIndex(t *testing.T) {
	const n, draws = 31, 31 * 4000
	counts := make([]int, n)
	for i := 0; i < draws; i++ {
		c, err := uniformIndex(n)
		if err != nil {
			t.Fatal(err)
		}
		counts[c]++
	}
	// Expected 4000 each. byte % 31 would give the first 8 letters 9 chances
	// in 256 instead of 8, 12.5% more (about 4500): far outside 6 standard
	// deviations (about 380) either way, which is the tolerance here.
	for i, c := range counts {
		if c < 3620 || c > 4380 {
			t.Fatalf("index %d drawn %d times of %d, want about 4000", i, c, draws)
		}
	}
}

func TestTOTPTruncated(t *testing.T) {
	secret := []byte("12345678901234567890")
	full := b32.EncodeToString(secret)
	now := time.Unix(1_700_000_000, 0)
	for _, n := range []int{16, 21, 26, 31} {
		short, err := b32.DecodeString(full[:n])
		if err != nil {
			continue
		}
		got, of, ok := TOTPTruncated(secret, TOTPCode(short, now), now)
		if !ok || got != n || of != len(full) {
			t.Errorf("key cut to %d: TOTPTruncated = %d of %d, %v", n, got, of, ok)
		}
	}
	// The right code, or a wrong one, is not a truncation.
	if _, _, ok := TOTPTruncated(secret, TOTPCode(secret, now), now); ok {
		t.Error("the full key's own code reported as truncated")
	}
	if _, _, ok := TOTPTruncated(secret, "000000", now); ok {
		t.Error("000000 reported as truncated")
	}
}
