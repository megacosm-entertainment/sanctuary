// Package gmcp parses and formats GMCP messages ("Package.Name <json>"), the
// same payload whether it arrives in a telnet subnegotiation or a WebSocket
// text frame.
package gmcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// MaxPayload caps a single GMCP message.
const MaxPayload = 32 << 10

var (
	ErrEmpty       = errors.New("gmcp: empty message")
	ErrTooLarge    = errors.New("gmcp: message too large")
	ErrBadPackage  = errors.New("gmcp: invalid package name")
	ErrInvalidJSON = errors.New("gmcp: malformed JSON payload")
)

// Parse splits and validates a GMCP message. Package names are 1-64
// characters of letters, digits, '.', '_' and '-'. A payload, when present,
// must be valid JSON; malformed messages are rejected here so nothing behind
// the gateway ever sees them.
func Parse(b []byte) (pkg string, data json.RawMessage, err error) {
	if len(b) == 0 {
		return "", nil, ErrEmpty
	}
	if len(b) > MaxPayload {
		return "", nil, ErrTooLarge
	}
	name, rest, _ := bytes.Cut(b, []byte{' '})
	if !validPackage(name) {
		return "", nil, ErrBadPackage
	}
	rest = bytes.TrimSpace(rest)
	if len(rest) == 0 {
		return string(name), nil, nil
	}
	if !json.Valid(rest) {
		return "", nil, ErrInvalidJSON
	}
	return string(name), json.RawMessage(bytes.Clone(rest)), nil
}

// ValidPackage reports whether pkg is an acceptable GMCP package name: 1-64
// characters of letters, digits, '.', '_' and '-'. Anything that carries a
// GMCP package name (the realm protocol, for one) uses this same rule.
func ValidPackage(pkg string) bool { return validPackage([]byte(pkg)) }

func validPackage(b []byte) bool {
	if len(b) == 0 || len(b) > 64 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// Format renders a GMCP message for the wire.
func Format(pkg string, data json.RawMessage) ([]byte, error) {
	if !validPackage([]byte(pkg)) {
		return nil, fmt.Errorf("%w: %q", ErrBadPackage, pkg)
	}
	if len(data) == 0 {
		return []byte(pkg), nil
	}
	var buf bytes.Buffer
	buf.WriteString(pkg)
	buf.WriteByte(' ')
	if err := json.Compact(&buf, data); err != nil {
		return nil, ErrInvalidJSON
	}
	return buf.Bytes(), nil
}
