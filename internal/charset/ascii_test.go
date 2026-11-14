package charset

import (
	"testing"
	"unicode/utf8"
)

func TestASCII(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain text unchanged", "You hit the orc.", "You hit the orc."},
		{"ANSI colour unchanged", "\x1b[31mred\x1b[0m", "\x1b[31mred\x1b[0m"},
		{"accents dropped", "Café crème, naïve Zoë", "Cafe creme, naive Zoe"},
		{"Latin Extended-A", "Łódź, Škoda, Ærø", "Lodz, Skoda, AEro"},
		{"decomposed accent", "été", "ete"},
		{"typographic quotes", "“Hello,” she said. ‘Fine.’", `"Hello," she said. 'Fine.'`},
		{"dashes and ellipsis", "wait — no… 1–2", "wait -- no... 1-2"},
		{"non-breaking space", "10 gold", "10 gold"},
		{"zero-width removed", "a​b", "ab"},
		{"box drawing keeps its shape", "┌─┐\n│x│\n└─┘", "+-+\n|x|\n+-+"},
		{"arrows", "north → south", "north -> south"},
		{"no ASCII spelling", "日本 🐉", "?? ?"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ASCII(c.in); got != c.want {
				t.Fatalf("ASCII(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// The property the fallback depends on: whatever goes in, only ASCII comes
// out, and folding twice changes nothing.
func TestASCIIOutputIsAlwaysASCII(t *testing.T) {
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue // surrogates are not valid in UTF-8 strings
		}
		in := string(r)
		out := ASCII(in)
		for i := 0; i < len(out); i++ {
			if out[i] >= utf8.RuneSelf {
				t.Fatalf("ASCII(%U) = %q contains a non-ASCII byte", r, out)
			}
		}
		if ASCII(out) != out {
			t.Fatalf("ASCII not idempotent on %U", r)
		}
	}
}
