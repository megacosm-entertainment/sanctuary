package account

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ParseKey reads a SecretKey written as text: 32 bytes in base64 (44
// characters) or hex (64), surrounding space ignored. The error never
// includes the text, which is a secret.
func ParseKey(text []byte) (*SecretKey, error) {
	s := strings.TrimSpace(string(text))
	var raw []byte
	var err error
	switch len(s) {
	case 2 * KeyLen:
		raw, err = hex.DecodeString(s)
	default:
		raw, err = base64.StdEncoding.DecodeString(s)
	}
	if err != nil || len(raw) != KeyLen {
		return nil, fmt.Errorf("account: the secret key must be %d bytes as base64 or hex", KeyLen)
	}
	return NewSecretKey(raw)
}

// NewKeyText returns a fresh key, base64-encoded for a setting or file.
func NewKeyText() (string, error) {
	raw := make([]byte, KeyLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// LoadOrCreateKeyFile reads the key at path, creating it (mode 0600) if
// it does not exist. created reports that it did. For a server without a
// secrets manager: the key then lives beside the data it protects, which
// still keeps TOTP secrets out of a copy of the accounts directory alone.
func LoadOrCreateKeyFile(path string) (k *SecretKey, created bool, err error) {
	b, err := os.ReadFile(path)
	if err == nil {
		k, err := ParseKey(b)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	text, err := NewKeyText()
	if err != nil {
		return nil, false, err
	}
	// O_EXCL: two processes starting at once must not each write a key.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateKeyFile(path)
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := f.WriteString(text + "\n"); err != nil {
		f.Close()
		return nil, false, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, false, err
	}
	if err := f.Close(); err != nil {
		return nil, false, err
	}
	k, err = ParseKey([]byte(text))
	return k, true, err
}
