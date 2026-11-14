// Package sanitize strips control sequences from untrusted text before it is
// sent to any client. Player input, bridged messages and client-reported
// identity strings are all untrusted.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

// Untrusted returns s as single-line, valid UTF-8 with every terminal
// control removed:
//
//   - ANSI/VT escape sequences (CSI, OSC, DCS, SOS, PM, APC and two-byte
//     ESC sequences) are removed whole, including their parameters, so
//     nothing can recolour, move the cursor, retitle the window, emit OSC 8
//     links or query the terminal.
//   - Remaining C0 controls (including CR, LF and BEL) and DEL are removed;
//     TAB becomes a space.
//   - C1 controls (U+0080..U+009F, including 8-bit CSI) are removed.
//   - Bidirectional overrides and isolates (U+202A..U+202E,
//     U+2066..U+2069) are removed, so text cannot visually reorder what
//     follows it.
//   - Invalid UTF-8 becomes U+FFFD.
func Untrusted(s string) string {
	if isClean(s) {
		return s
	}
	return clean(s, false)
}

// Server cleans server-authored output, such as text a realm sends through
// the gateway, before it reaches a client. It is Untrusted with three things
// kept, because server output legitimately uses them:
//
//   - line breaks (LF; CR is still removed, and transports add it back),
//   - TAB, kept as TAB,
//   - 7-bit SGR colour and style sequences (ESC [ digits ; : m, at most
//     maxSGR bytes). Every other escape, 8-bit CSI included, is removed.
//
// Player text a realm embeds should already have been through Untrusted;
// Server is the gateway's second line of defence against a realm that
// forgot, or one that has been compromised.
func Server(s string) string { return clean(s, true) }

// maxSGR caps one kept SGR sequence; longer ones are dropped as suspect.
// A full truecolour foreground and background, ESC[38;2;255;255;255;48;2;255;255;255m,
// is 37 bytes.
const maxSGR = 64

// isSGR reports whether seq, one whole escape sequence, is ESC [ params m
// with only digits, ';' and ':' as parameters.
func isSGR(seq string) bool {
	if len(seq) < 3 || len(seq) > maxSGR || seq[1] != '[' || seq[len(seq)-1] != 'm' {
		return false
	}
	for i := 2; i < len(seq)-1; i++ {
		if c := seq[i]; !(c >= '0' && c <= '9' || c == ';' || c == ':') {
			return false
		}
	}
	return true
}

func clean(s string, server bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		switch {
		case r == 0x1b:
			n := escapeLen(s[i:])
			if server && isSGR(s[i:i+n]) {
				b.WriteString(s[i : i+n])
			}
			i += n
			continue
		case server && (r == '\n' || r == '\t'):
			b.WriteByte(byte(r))
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// drop
		case r == 0x9b: // 8-bit CSI: skip its parameters too
			i += size
			i += csiBodyLen(s[i:])
			continue
		case r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f: // OSC, DCS, SOS, PM, APC
			i += size
			i += stringBodyLen(s[i:])
			continue
		case r >= 0x80 && r <= 0x9f:
			// drop other C1
		case isBidiControl(r):
			// drop
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func isClean(s string) bool {
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			if c < 0x20 || c == 0x7f {
				return false
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || (r >= 0x80 && r <= 0x9f) || isBidiControl(r) {
			return false
		}
		i += size
	}
	return true
}

func isBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// escapeLen returns the length of the escape sequence starting at s[0]==ESC.
func escapeLen(s string) int {
	if len(s) < 2 {
		return len(s)
	}
	switch s[1] {
	case '[':
		return 2 + csiBodyLen(s[2:])
	case ']', 'P', 'X', '^', '_': // OSC, DCS, SOS, PM, APC
		return 2 + stringBodyLen(s[2:])
	default:
		// Two-byte sequence (ESC c, ESC 7, ...), possibly with
		// intermediates (ESC ( B).
		n := 1
		for n < len(s) && s[n] >= 0x20 && s[n] <= 0x2f {
			n++
		}
		if n < len(s) {
			n++
		}
		return n
	}
}

// csiBodyLen returns the length of CSI parameters, intermediates and the
// final byte. An unterminated sequence consumes to the end of the parameters.
func csiBodyLen(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x40 && c <= 0x7e {
			return i + 1
		}
		if c < 0x20 || c > 0x7e { // not a parameter or intermediate byte
			return i
		}
	}
	return len(s)
}

// stringBodyLen returns the length of a control string up to and including
// its terminator (BEL, ESC \ or 8-bit ST). Unterminated strings run to the end.
func stringBodyLen(s string) int {
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == 0x07:
			return i + 1
		case s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\':
			return i + 2
		case s[i] == 0xc2 && i+1 < len(s) && s[i+1] == 0x9c: // U+009C ST
			return i + 2
		}
	}
	return len(s)
}

// UntrustedLine cleans one line of untrusted input with Untrusted and then
// caps it at max bytes, cutting at a character boundary. Cleaning comes
// first because it can lengthen text (an invalid byte becomes the 3-byte
// U+FFFD): capping first let a 4096-byte line clean to 12288 bytes, which
// the realm protocol then refused (RT-3-2).
func UntrustedLine(s string, max int) string {
	s = Untrusted(s)
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
