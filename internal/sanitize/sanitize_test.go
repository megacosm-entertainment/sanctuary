package sanitize

import "testing"

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
