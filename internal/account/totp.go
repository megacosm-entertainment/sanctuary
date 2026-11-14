package account

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTP is RFC 6238 with the parameters every authenticator app supports:
// HMAC-SHA1, 30-second steps, 6 digits. SHA-1's weaknesses do not affect
// HMAC-SHA1 as used here (RFC 6238 §5.2 and RFC 2104).
const (
	totpStep   = 30 * time.Second
	totpDigits = 6
	totpSkew   = 1  // steps accepted either side of now, for clock drift
	secretLen  = 20 // 160 bits, RFC 4226 §4's recommendation
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh random secret.
func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, secretLen)
	_, err := rand.Read(s)
	return s, err
}

// TOTPDisplay is the secret as people type it into an authenticator app:
// base32 in groups of four, for reading aloud or through a screen reader.
func TOTPDisplay(secret []byte) string {
	s := b32.EncodeToString(secret)
	var groups []string
	for len(s) > 4 {
		groups, s = append(groups, s[:4]), s[4:]
	}
	return strings.Join(append(groups, s), " ")
}

// TOTPURI is the otpauth:// URI an app reads from a QR code or a link.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	// Every parameter is spelled out, though these are the defaults: some
	// apps (Authy among them) otherwise guess, and guess 7 digits.
	q := url.Values{
		"secret":    {b32.EncodeToString(secret)},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {strconv.Itoa(totpDigits)},
		"period":    {strconv.Itoa(int(totpStep / time.Second))},
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpAt is the code for one time step (RFC 4226 §5.3 dynamic truncation).
func totpAt(secret []byte, step int64) string {
	mac := hmac.New(sha1.New, secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1_000_000)
}

// CheckTOTP checks code against the secret at time now. lastStep is the
// step of the last code accepted for this account: a code for that step
// or an earlier one is refused, so an observed code cannot be replayed
// (RFC 6238 §5.2). It returns the step to record when the code is good.
func CheckTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / int64(totpStep/time.Second)
	for d := -totpSkew; d <= totpSkew; d++ {
		step := cur + int64(d)
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// ── Encryption at rest ──────────────────────────────────────

// SecretKey encrypts TOTP secrets in the account store, so a copy of the
// account files alone (a backup, a misplaced directory) does not let
// anyone generate codes. It is a secret setting, kept apart from the store.
type SecretKey struct{ aead cipher.AEAD }

// KeyLen is the key size: AES-256.
const KeyLen = 32

// ErrBadKey reports a key of the wrong size.
var ErrBadKey = fmt.Errorf("account: the secret key must be %d bytes", KeyLen)

// NewSecretKey wraps a 32-byte key.
func NewSecretKey(key []byte) (*SecretKey, error) {
	if len(key) != KeyLen {
		return nil, ErrBadKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretKey{aead: aead}, nil
}

// Seal encrypts secret for the account with id (the id is bound in as
// additional data, so a sealed secret copied to another account fails to
// open).
func (k *SecretKey) Seal(secret []byte, id string) (string, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.aead.Seal(nonce, nonce, secret, []byte(id))), nil
}

// ErrSealed reports a sealed value that does not open with this key and id.
var ErrSealed = errors.New("account: sealed secret does not open (wrong key, wrong account, or corrupt)")

// Open decrypts a value from Seal.
func (k *SecretKey) Open(sealed, id string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(raw) < k.aead.NonceSize() {
		return nil, ErrSealed
	}
	n := k.aead.NonceSize()
	out, err := k.aead.Open(nil, raw[:n], raw[n:], []byte(id))
	if err != nil {
		return nil, ErrSealed
	}
	return out, nil
}

// ── Recovery codes ──────────────────────────────────────────

// RecoveryCodes is how many are issued at TOTP enrolment.
const RecoveryCodes = 10

// recoveryAlphabet avoids characters people confuse when reading or
// hearing them (0/O, 1/I/L), which also suits screen readers.
const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NewRecoveryCodes returns fresh codes to show the player once, and the
// hashes to store. Each code has 10 characters from a 31-letter alphabet
// (about 50 bits), shown as two groups of five.
func NewRecoveryCodes() (shown, stored []string, err error) {
	for i := 0; i < RecoveryCodes; i++ {
		var b strings.Builder
		for j := 0; j < 10; j++ {
			if j == 5 {
				b.WriteByte('-')
			}
			c, err := uniformIndex(len(recoveryAlphabet))
			if err != nil {
				return nil, nil, err
			}
			b.WriteByte(recoveryAlphabet[c])
		}
		code := b.String()
		shown = append(shown, code)
		stored = append(stored, hashRecovery(code))
	}
	return shown, stored, nil
}

// hashRecovery: SHA-256 suffices, unlike for passwords, because a code is
// random and long, not chosen by a person (nothing to guess from a list).
func hashRecovery(code string) string {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(norm))
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

// UseRecoveryCode checks code against the stored hashes and returns the
// list without the one used (each code works once), and whether it matched.
func UseRecoveryCode(stored []string, code string) ([]string, bool) {
	h := hashRecovery(code)
	for i, s := range stored {
		if subtle.ConstantTimeCompare([]byte(s), []byte(h)) == 1 {
			rest := append(append([]string(nil), stored[:i]...), stored[i+1:]...)
			return rest, true
		}
	}
	return stored, false
}

// uniformIndex returns a uniformly random index below n (n <= 256), by
// rejecting the bytes in the uneven tail rather than taking byte % n,
// which would favour the first 256 % n letters.
func uniformIndex(n int) (int, error) {
	limit := 256 - 256%n
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}

// TOTPCode is the code an authenticator shows at time now: for checking
// enrolment ("type the code your app shows") and for tests.
func TOTPCode(secret []byte, now time.Time) string {
	return totpAt(secret, now.Unix()/int64(totpStep/time.Second))
}

// TOTPDigits is how many digits a code has.
const TOTPDigits = totpDigits

// TOTPTruncated reports whether code, refused for secret, is what an app
// holding only the first n characters of the displayed key would show at
// now: a key cut short when typed or pasted into the app. It is a
// diagnosis for a code already refused, never a way to accept one.
func TOTPTruncated(secret []byte, code string, now time.Time) (n, of int, ok bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, 0, false
	}
	full := b32.EncodeToString(secret)
	cur := now.Unix() / int64(totpStep/time.Second)
	// Longest first: HMAC pads keys with zeros, so a cut key ending in a
	// zero byte equals a shorter one; report where it was really cut.
	for n := len(full) - 1; n >= 16; n-- { // shorter keys are under 80 bits: not ours
		k, err := b32.DecodeString(full[:n])
		// Only lengths a base32 string can end at (n mod 8 is 0, 2, 4, 5
		// or 7): the unpadded decoder quietly drops any other tail, so 17
		// or 22 characters would decode as 16.
		if r := n % 8; r == 1 || r == 3 || r == 6 {
			continue
		}
		if err != nil {
			continue // not a length base32 can end at
		}
		for d := -totpSkew; d <= totpSkew; d++ {
			if subtle.ConstantTimeCompare([]byte(totpAt(k, cur+int64(d))), []byte(code)) == 1 {
				return n, len(full), true
			}
		}
	}
	return 0, 0, false
}
