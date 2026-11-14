// Package charset adapts text to what a client can display. Clients that
// have not claimed UTF-8 (MTTS bit 4, a CHARSET negotiation or MNES CHARSET)
// get plain ASCII instead (docs/status.md, stage 02 decisions).
package charset

import (
	"strings"
	"unicode/utf8"
)

// ASCII returns s with every non-ASCII character replaced by its nearest
// ASCII spelling: accented Latin letters lose their accents, typographic
// quotes and dashes become plain ones, box drawing becomes + - |, and
// anything without a sensible spelling becomes '?'. ASCII text, including
// ANSI escape sequences, passes through unchanged. Combining marks are
// dropped, so decomposed text ("e" + U+0301) folds like composed text.
func ASCII(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < utf8.RuneSelf:
			b.WriteRune(r)
		case r >= 0x0300 && r <= 0x036f: // combining diacritical marks
		case r >= 0x2500 && r <= 0x257f: // box drawing
			b.WriteByte(boxChar(r))
		default:
			if t, ok := fold[r]; ok {
				b.WriteString(t)
			} else {
				b.WriteByte('?')
			}
		}
	}
	return b.String()
}

// boxChar maps box-drawing characters to + - |, so ASCII maps and frames
// keep their shape.
func boxChar(r rune) byte {
	switch r {
	case '─', '━', '═', '╌', '╍', '┄', '┅', '┈', '┉', '╴', '╶', '╸', '╺', '╼', '╾':
		return '-'
	case '│', '┃', '║', '╎', '╏', '┆', '┇', '┊', '┋', '╵', '╷', '╹', '╻', '╽', '╿':
		return '|'
	}
	return '+'
}

var fold = func() map[rune]string {
	m := map[rune]string{
		// Spaces.
		'\u00a0': " ", '\u2002': " ", '\u2003': " ", '\u2009': " ", '\u200a': " ", '\u202f': " ",
		'\u200b': "", '\u200c': "", '\u200d': "", '\ufeff': "", '\u00ad': "", // zero-width, BOM, soft hyphen
		// Punctuation.
		'‘': "'", '’': "'", '‚': "'", '‛': "'", '′': "'",
		'“': `"`, '”': `"`, '„': `"`, '‟': `"`, '″': `"`,
		'‹': "<", '›': ">", '«': "<<", '»': ">>",
		'‐': "-", '‑': "-", '‒': "-", '–': "-", '—': "--", '―': "--", '−': "-",
		'…': "...", '•': "*", '·': ".", '¡': "!", '¿': "?", '¦': "|", '§': "S", '¶': "P",
		// Symbols.
		'©': "(c)", '®': "(R)", '™': "(TM)", '°': " deg", '±': "+/-", '×': "x", '÷': "/",
		'½': "1/2", '¼': "1/4", '¾': "3/4", '¹': "1", '²': "2", '³': "3", 'µ': "u",
		'€': "EUR", '£': "GBP", '¥': "JPY", '¢': "c",
		'→': "->", '←': "<-", '↑': "^", '↓': "v", '↔': "<->", '⇒': "=>", '⇐': "<=",
		'≤': "<=", '≥': ">=", '≠': "!=", '≈': "~", '∞': "inf",
		'✓': "v", '✔': "v", '✗': "x", '✘': "x", '★': "*", '☆': "*",
		// Latin letters that do not fold to a single base letter.
		'Æ': "AE", 'æ': "ae", 'Œ': "OE", 'œ': "oe", 'ß': "ss", 'ẞ': "SS",
		'Þ': "Th", 'þ': "th", 'Ð': "D", 'ð': "d", 'Đ': "D", 'đ': "d",
		'Ł': "L", 'ł': "l", 'Ø': "O", 'ø': "o", 'Ħ': "H", 'ħ': "h", 'ı': "i",
		'Ĳ': "IJ", 'ĳ': "ij", 'Ŋ': "N", 'ŋ': "n", 'ſ': "s",
	}
	// Accented Latin letters: each base letter and the precomposed forms
	// of it in Latin-1 Supplement and Latin Extended-A.
	for base, forms := range map[string]string{
		"A": "ÀÁÂÃÄÅĀĂĄ", "a": "àáâãäåāăą", "C": "ÇĆĈĊČ", "c": "çćĉċč",
		"D": "Ď", "d": "ď", "E": "ÈÉÊËĒĔĖĘĚ", "e": "èéêëēĕėęě",
		"G": "ĜĞĠĢ", "g": "ĝğġģ", "H": "Ĥ", "h": "ĥ", "I": "ÌÍÎÏĨĪĬĮİ", "i": "ìíîïĩīĭį",
		"J": "Ĵ", "j": "ĵ", "K": "Ķ", "k": "ķĸ", "L": "ĹĻĽĿ", "l": "ĺļľŀ",
		"N": "ÑŃŅŇ", "n": "ñńņňŉ", "O": "ÒÓÔÕÖŌŎŐ", "o": "òóôõöōŏő",
		"R": "ŔŖŘ", "r": "ŕŗř", "S": "ŚŜŞŠ", "s": "śŝşš", "T": "ŢŤŦ", "t": "ţťŧ",
		"U": "ÙÚÛÜŨŪŬŮŰŲ", "u": "ùúûüũūŭůűų", "W": "Ŵ", "w": "ŵ",
		"Y": "ÝŶŸ", "y": "ýÿŷ", "Z": "ŹŻŽ", "z": "źżž",
	} {
		for _, r := range forms {
			m[r] = base
		}
	}
	return m
}()
