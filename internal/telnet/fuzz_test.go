package telnet

import "testing"

// FuzzProcess feeds arbitrary client bytes through the parser and option
// negotiation. It must never panic, and output must stay proportional to
// input (no negotiation amplification).
func FuzzProcess(f *testing.F) {
	f.Add([]byte{IAC, WILL, OptTTYPE, IAC, SB, OptTTYPE, 0, 'x', IAC, SE})
	f.Add([]byte{IAC, DO, OptMCCP2, IAC, DONT, OptMCCP2, IAC, DO, OptGMCP, IAC, SB, OptGMCP, 'A', ' ', '{', IAC, SE})
	f.Add([]byte{IAC, SB, OptCharset, CharsetRequest, '[', 'T', 'T', 'A', 'B', 'L', 'E', ']', 1, ';', 'U', IAC, SE})
	f.Add([]byte{IAC, WILL, OptNewEnviron, IAC, SB, OptNewEnviron, EnvIs, EnvVar, EnvEsc, IAC, IAC, EnvVal, IAC, SE})
	f.Fuzz(func(t *testing.T, data []byte) {
		c, rw := newTestConn(t)
		feed(c, data...)
		// Bound: each 3-byte negotiation command can earn at most one
		// 3-byte reply, but a few inputs legitimately trigger larger
		// replies (MSSP, the MNES request, the AYT answer), hence the
		// generous per-byte factor plus a constant for one-off replies.
		if out := rw.takeSent(); len(out) > 64*len(data)+4096 {
			t.Fatalf("%d input bytes produced %d output bytes", len(data), len(out))
		}
	})
}
