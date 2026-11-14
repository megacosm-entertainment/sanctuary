package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUntrusted(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"héllo wörld ✓", "héllo wörld ✓"},
		{"\x1b[1;31mred\x1b[0m", "red"},
		{"\x1b[2J\x1b[H", ""},
		{"\x1b]0;title\x07after", "after"},
		{"\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\", "link"},
		{"\x1bPdcs\x1b\\ok", "ok"},
		{"\x1b(Bok", "ok"},
		{"\x1bc", ""},
		{"bell\x07\x08\x7f", "bell"},
		{"tab\there", "tab here"},
		{"cr\r\nlf", "crlf"},
		{"\u009b31mc1csi", "c1csi"},
		{"\u009d0;t\u009cafter", "after"},
		{"\u0085nel", "nel"},
		{"abc‮dcba⁦x⁩", "abcdcbax"},
		{"bad\xffutf8", "bad�utf8"},
		{"\x1b", ""},
		// 8-bit string introducers: DCS, SOS, PM, APC, each up to ST.
		{"\u0090dcs\u009cok", "ok"},
		{"\u0098sos\u009cok", "ok"},
		{"\u009epm\u009cok", "ok"},
		{"\u009fapc\u009cok", "ok"},
		// 7-bit SOS, PM and APC strings.
		{"\x1bXsos\x1b\\ok", "ok"},
		{"\x1b^pm\x1b\\ok", "ok"},
		{"\x1b_apc\x1b\\ok", "ok"},
		// A CSI cut short by a non-ASCII byte ends there; the byte is kept.
		{"\x1b[1éx", "éx"},
		{"\x1b[31", ""},
	}
	for _, c := range cases {
		if got := Untrusted(c.in); got != c.want {
			t.Errorf("Untrusted(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func FuzzUntrusted(f *testing.F) {
	f.Add("\x1b[31mx")
	f.Add("\u009b‮\xff")
	f.Fuzz(func(t *testing.T, s string) {
		out := Untrusted(s)
		for _, r := range out {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r) {
				t.Fatalf("Untrusted(%q) left control %U", s, r)
			}
		}
		if Untrusted(out) != out {
			t.Fatalf("not idempotent on %q", s)
		}
	})
}

// Server keeps what realm output legitimately uses (line breaks, tabs, SGR
// colour) and removes everything else Untrusted removes.
func TestServer(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain lines kept", "line one\nline two\n", "line one\nline two\n"},
		{"tab kept", "a\tb", "a\tb"},
		{"SGR colour kept", "\x1b[1;31mred\x1b[0m", "\x1b[1;31mred\x1b[0m"},
		{"256-colour SGR kept", "\x1b[38;5;208mx", "\x1b[38;5;208mx"},
		{"truecolour SGR with colons kept", "\x1b[38:2::255:0:0mx", "\x1b[38:2::255:0:0mx"},
		{"CR removed", "a\r\nb", "a\nb"},
		{"cursor movement removed", "\x1b[2J\x1b[Hx", "x"},
		{"private-mode CSI removed", "\x1b[?25lx", "x"},
		{"OSC 8 link removed", "\x1b]8;;http://evil\x07link\x1b]8;;\x07", "link"},
		{"window title removed", "\x1b]0;pwned\x07x", "x"},
		{"terminal reset removed", "\x1bcx", "x"},
		{"8-bit CSI SGR removed", "\u009b31mx", "x"},
		{"bell removed", "a\x07b", "ab"},
		{"bidi override removed", "‮txt", "txt"},
		// A huge parameter list is not something a realm needs to send.
		{"oversize SGR removed", "\x1b[" + strings.Repeat("1;", 40) + "1mx", "x"},
		{"invalid UTF-8 replaced", "a\xffb", "a�b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Server(c.in); got != c.want {
				t.Fatalf("Server(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// Untrusted must not change behaviour now that it shares a loop with Server.
func TestUntrustedStillStripsWhatServerKeeps(t *testing.T) {
	in := "a\n\x1b[31mb\tc"
	if got, want := Untrusted(in), "ab c"; got != want {
		t.Fatalf("Untrusted(%q) = %q, want %q", in, got, want)
	}
}

// FuzzServer checks the property that matters: the only escapes left are
// short SGR sequences, the only controls left are LF and TAB, and cleaning
// is idempotent.
func FuzzServer(f *testing.F) {
	f.Add("\x1b[1;31mred\x1b[0m\nnext")
	f.Add("\x1b]8;;x\x07y\x1b[2J")
	f.Add("\x1b\x1b[31m\u009b31m‮\xff\r")
	f.Fuzz(func(t *testing.T, s string) {
		out := Server(s)
		for i := 0; i < len(out); {
			if out[i] == 0x1b {
				n := escapeLen(out[i:])
				if !isSGR(out[i : i+n]) {
					t.Fatalf("Server(%q) left a non-SGR escape %q", s, out[i:i+n])
				}
				i += n
				continue
			}
			r, size := utf8.DecodeRuneInString(out[i:])
			if r == utf8.RuneError && size == 1 {
				t.Fatalf("Server(%q) left invalid UTF-8", s)
			}
			if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r) {
				t.Fatalf("Server(%q) left control %U", s, r)
			}
			i += size
		}
		if Server(out) != out {
			t.Fatalf("Server not idempotent on %q: %q then %q", s, out, Server(out))
		}
	})
}

// RT-3-2: a line of invalid bytes grows threefold when cleaned; the cap
// must hold after cleaning, at a character boundary.
func TestUntrustedLineCapsAfterCleaning(t *testing.T) {
	in := strings.Repeat("\x80", 3000) // 3000 invalid bytes → 9000 bytes of U+FFFD
	got := UntrustedLine(in, 4096)
	if len(got) > 4096 {
		t.Fatalf("UntrustedLine = %d bytes, want at most 4096", len(got))
	}
	if !utf8.ValidString(got) || len(got) != 4095 { // 1365 whole U+FFFD
		t.Fatalf("UntrustedLine = %d bytes (valid %v), want 4095 bytes of whole characters", len(got), utf8.ValidString(got))
	}
	if UntrustedLine("short", 4096) != "short" {
		t.Fatal("UntrustedLine changed a short clean line")
	}
}
