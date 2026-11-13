package telnet

// White-box tests: the fixture drives Conn.process directly so each test
// controls exactly which client bytes arrive and when. Assertions are on
// what the connection emits (bytes written, events produced), not on its
// internal fields.

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"sentience/internal/session"
)

// ---------------------------------------------------------------- fixture

// MTTS values reported by real clients, used across tests.
const (
	mudletMTTS        = 2349 // Mudlet 5.1: SSL 2048 + truecolor 256 + OSC 32 + 256 colours 8 + UTF-8 4 + ANSI 1
	tintinTTYPEMTTS   = 271  // TinTin++ 2.02 over TTYPE: truecolor 256 + 8 + 4 + VT100 2 + 1
	tintinMNESMTTS    = 783  // the same over MNES, plus the MNES bit 512
	screenReaderMTTS  = 2893 // SSL 2048 + MNES 512 + truecolor 256 + screen reader 64 + 8 + 4 + 1
	unsupportedOption = 99   // an option number the gateway has no handler for
)

// fakeRW is an in-memory byte stream: tests push client bytes into in and
// collect what the server wrote with takeSent.
type fakeRW struct {
	mu       sync.Mutex
	out      bytes.Buffer
	in       chan []byte
	closed   bool
	deadline time.Time // last write deadline set
}

func (f *fakeRW) SetWriteDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline = t
	return nil
}

func (f *fakeRW) lastDeadline() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadline
}

func (f *fakeRW) Read(p []byte) (int, error) {
	b, ok := <-f.in
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}

func (f *fakeRW) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.Write(p)
}

func (f *fakeRW) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.in)
	}
	return nil
}

// takeSent returns and clears everything the server has written.
func (f *fakeRW) takeSent() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := bytes.Clone(f.out.Bytes())
	f.out.Reset()
	return b
}

var discardLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func testMSSP() []MSSPVar {
	return []MSSPVar{{"NAME", []string{"Test"}}, {"PLAYERS", []string{"3"}}, {"WEBSOCKET_SUBPROTOCOLS", []string{"a", "b"}}}
}

// newTestConn returns a started Conn with its initial offers already
// discarded, so tests see only what their own input causes.
func newTestConn(t testing.TB) (*Conn, *fakeRW) {
	t.Helper()
	f := &fakeRW{in: make(chan []byte, 16)}
	c := NewConn(f, Config{Meta: session.Meta{Kind: "test"}, MSSP: testMSSP, Log: discardLog})
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.takeSent()
	return c, f
}

// feed processes client bytes as ReadEvent would and returns the events
// they produced.
func feed(c *Conn, b ...byte) []session.Inbound {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.process(b)
	c.flush()
	ev := c.pending
	c.pending = nil
	return ev
}

// write calls WriteEvent, failing the test on error.
func write(t *testing.T, c *Conn, o session.Outbound) {
	t.Helper()
	if err := c.WriteEvent(o); err != nil {
		t.Fatalf("WriteEvent(%#v): %v", o, err)
	}
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// cmd is IAC <command> <option>.
func cmd(command, opt byte) []byte { return []byte{IAC, command, opt} }

// sb is IAC SB <option> <payload> IAC SE. The payload is used as given:
// double any IAC in it yourself.
func sb(opt byte, payload ...byte) []byte { return cat([]byte{IAC, SB, opt}, payload, []byte{IAC, SE}) }

func ttypeIs(v string) []byte { return sb(OptTTYPE, append([]byte{TTypeIs}, v...)...) }

// envVar is one NEW-ENVIRON variable. Defined false sends "VAR name" with
// no VAL, which RFC 1572 defines as "the client does not have this".
type envVar struct {
	name, value string
	defined     bool
}

func def(name, value string) envVar { return envVar{name, value, true} }
func undef(name string) envVar      { return envVar{name: name} }

// mnes builds a NEW-ENVIRON subnegotiation; kind is EnvIs or EnvInfo.
func mnes(kind byte, vars ...envVar) []byte {
	p := []byte{kind}
	for _, v := range vars {
		p = append(p, EnvVar)
		p = append(p, v.name...)
		if v.defined {
			p = append(p, EnvVal)
			p = append(p, v.value...)
		}
	}
	return sb(OptNewEnviron, p...)
}

// wantSent fails unless the server wrote exactly want.
func wantSent(t *testing.T, f *fakeRW, want []byte) {
	t.Helper()
	if got := f.takeSent(); !bytes.Equal(got, want) {
		t.Fatalf("server sent %s\n          want %s", Describe(got), Describe(want))
	}
}

// lastUpdate returns the newest ClientUpdate in evs.
func lastUpdate(t *testing.T, evs []session.Inbound) session.ClientInfo {
	t.Helper()
	for i := len(evs) - 1; i >= 0; i-- {
		if cu, ok := evs[i].(session.ClientUpdate); ok {
			return cu.Info
		}
	}
	t.Fatalf("no ClientUpdate among %#v", evs)
	return session.ClientInfo{}
}

// clientInfo returns the snapshot the next ClientUpdate would carry. Use
// it when the input under test may not produce an update of its own.
func clientInfo(c *Conn) session.ClientInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshot()
}

// linesIn returns the text of every Line event.
func linesIn(evs []session.Inbound) []string {
	var out []string
	for _, e := range evs {
		if l, ok := e.(session.Line); ok {
			out = append(out, l.Text)
		}
	}
	return out
}

// ---------------------------------------------------------------- offers and refusals

func TestStartOffersAdoptedOptions(t *testing.T) {
	f := &fakeRW{in: make(chan []byte, 1)}
	c := NewConn(f, Config{MSSP: testMSSP, Log: discardLog})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	sent := f.takeSent()
	for _, want := range [][]byte{
		cmd(DO, OptTTYPE), cmd(DO, OptNAWS), cmd(DO, OptNewEnviron),
		cmd(WILL, OptCharset), cmd(WILL, OptEOR), cmd(WILL, OptGMCP),
		cmd(WILL, OptMSSP), cmd(WILL, OptMCCP2),
	} {
		if !bytes.Contains(sent, want) {
			t.Errorf("offers lack %s; sent %s", Describe(want), Describe(sent))
		}
	}
	// WILL ECHO is only for hidden input, and WILL SGA without WILL ECHO
	// puts classic line-mode telnet clients into character mode.
	for _, bad := range [][]byte{cmd(WILL, OptEcho), cmd(WILL, OptSGA)} {
		if bytes.Contains(sent, bad) {
			t.Errorf("offers include %s", Describe(bad))
		}
	}
}

func TestStartWithoutMSSPProviderDoesNotOfferMSSP(t *testing.T) {
	f := &fakeRW{in: make(chan []byte, 1)}
	c := NewConn(f, Config{Log: discardLog})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); bytes.Contains(sent, cmd(WILL, OptMSSP)) {
		t.Fatalf("offered MSSP with no provider: %s", Describe(sent))
	}
}

func TestRefusesUnrequestedOptions(t *testing.T) {
	tests := []struct {
		name      string
		in, reply []byte
	}{
		// A client asking us to echo everything it types is refused; ECHO
		// is enabled only at our request, for hidden input.
		{"unsolicited DO ECHO", cmd(DO, OptEcho), cmd(WONT, OptEcho)},
		// The client echoing for us would mean the server never sees typed
		// characters as they are typed; MUD clients echo locally anyway.
		{"client WILL ECHO", cmd(WILL, OptEcho), cmd(DONT, OptEcho)},
		{"unknown WILL", cmd(WILL, unsupportedOption), cmd(DONT, unsupportedOption)},
		{"unknown DO", cmd(DO, unsupportedOption), cmd(WONT, unsupportedOption)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, f := newTestConn(t)
			feed(c, tt.in...)
			wantSent(t, f, tt.reply)
		})
	}
}

// ---------------------------------------------------------------- RFC 1143 (Q method)

// The point of RFC 1143 is that no sequence of peer messages can make the
// two sides negotiate forever.
func TestQMethod(t *testing.T) {
	t.Run("repeated request for an enabled option is not answered", func(t *testing.T) {
		c, f := newTestConn(t)
		feed(c, cmd(DO, OptEOR)...) // enables EOR; we offered it, so no reply
		wantSent(t, f, nil)
		for i := 0; i < 100; i++ {
			feed(c, cmd(DO, OptEOR)...)
		}
		wantSent(t, f, nil)
	})

	t.Run("flapping client gets exactly one reply per change", func(t *testing.T) {
		c, f := newTestConn(t)
		// We asked DO NAWS at Start. The first WILL acknowledges it (no
		// reply); every later change of state is answered once.
		feed(c, cmd(WILL, OptNAWS)...)
		wantSent(t, f, nil)
		feed(c, cmd(WONT, OptNAWS)...)
		wantSent(t, f, cmd(DONT, OptNAWS))
		for i := 0; i < 20; i++ {
			feed(c, cmd(WILL, OptNAWS)...)
			wantSent(t, f, cmd(DO, OptNAWS))
			feed(c, cmd(WONT, OptNAWS)...)
			wantSent(t, f, cmd(DONT, OptNAWS))
		}
	})

	t.Run("queue bit absorbs a change of mind before the reply", func(t *testing.T) {
		c, f := newTestConn(t)
		write(t, c, session.InputMode{Hidden: true})
		wantSent(t, f, cmd(WILL, OptEcho))
		// Unhide then hide again before the client answers: the queue bit
		// records it without sending anything more.
		write(t, c, session.InputMode{Hidden: false})
		write(t, c, session.InputMode{Hidden: true})
		wantSent(t, f, nil)
		feed(c, cmd(DO, OptEcho)...)
		wantSent(t, f, nil)
		if opts := strings.Join(clientInfo(c).Options, ","); !strings.Contains(opts, "ECHO") {
			t.Fatalf("ECHO not enabled after DO; options %s", opts)
		}
	})

	t.Run("change of mind is sent once the reply arrives", func(t *testing.T) {
		c, f := newTestConn(t)
		write(t, c, session.InputMode{Hidden: true})
		write(t, c, session.InputMode{Hidden: false}) // queued: OPPOSITE
		wantSent(t, f, cmd(WILL, OptEcho))
		feed(c, cmd(DO, OptEcho)...)
		wantSent(t, f, cmd(WONT, OptEcho))
		feed(c, cmd(DONT, OptEcho)...)
		wantSent(t, f, nil)
	})
}

func TestInputModeTogglesEcho(t *testing.T) {
	c, f := newTestConn(t)
	write(t, c, session.InputMode{Hidden: true})
	wantSent(t, f, cmd(WILL, OptEcho))
	feed(c, cmd(DO, OptEcho)...)
	wantSent(t, f, nil) // an acknowledgement is never answered
	write(t, c, session.InputMode{Hidden: false})
	wantSent(t, f, cmd(WONT, OptEcho))
	feed(c, cmd(DONT, OptEcho)...)
	wantSent(t, f, nil)
}

// ---------------------------------------------------------------- TTYPE / MTTS

func TestMTTSCycle(t *testing.T) {
	c, f := newTestConn(t)
	send := sb(OptTTYPE, TTypeSend)

	feed(c, cmd(WILL, OptTTYPE)...)
	wantSent(t, f, send)
	feed(c, ttypeIs("MUDLET")...)
	wantSent(t, f, send)
	feed(c, ttypeIs("ANSI-TRUECOLOR")...)
	wantSent(t, f, send)
	evs := feed(c, ttypeIs(fmt.Sprintf("MTTS %d", screenReaderMTTS))...)
	wantSent(t, f, nil) // the cycle ends at the MTTS reply

	info := lastUpdate(t, evs)
	if info.Name != "MUDLET" || info.Terminal != "ANSI-TRUECOLOR" || info.MTTS != screenReaderMTTS {
		t.Fatalf("got name %q terminal %q mtts %d, want MUDLET ANSI-TRUECOLOR %d",
			info.Name, info.Terminal, info.MTTS, screenReaderMTTS)
	}
	if !info.ScreenReader() {
		t.Fatal("MTTS screen-reader bit (64) not reported")
	}
}

// A client without MTTS repeats its terminal type; the repeat ends the
// cycle rather than asking forever.
func TestTTYPEWithoutMTTSStopsOnRepeat(t *testing.T) {
	c, f := newTestConn(t)
	feed(c, cmd(WILL, OptTTYPE)...)
	feed(c, ttypeIs("XTERM")...)
	f.takeSent()
	feed(c, ttypeIs("XTERM")...)
	wantSent(t, f, nil)
	if info := clientInfo(c); info.HasMTTS || info.Name != "XTERM" {
		t.Fatalf("got name %q HasMTTS %v, want XTERM false", info.Name, info.HasMTTS)
	}
}

// ---------------------------------------------------------------- MNES

func TestMNESRequestsVariables(t *testing.T) {
	c, f := newTestConn(t)
	feed(c, cmd(WILL, OptNewEnviron)...)
	sent := f.takeSent()
	for _, v := range []string{"CLIENT_NAME", "CLIENT_VERSION", "CHARSET", "MTTS", "TERMINAL_TYPE"} {
		if !bytes.Contains(sent, append([]byte{EnvVar}, v...)) {
			t.Errorf("MNES SEND lacks %s: %s", v, Describe(sent))
		}
	}
}

func TestMNESReportsIdentity(t *testing.T) {
	c, _ := newTestConn(t)
	feed(c, cmd(WILL, OptNewEnviron)...)
	info := lastUpdate(t, feed(c, mnes(EnvIs,
		def("CLIENT_NAME", "TinTin++"), def("CLIENT_VERSION", "2.02.20"), def("MTTS", "64"))...))
	if info.Name != "TinTin++" || info.Version != "2.02.20" || !info.ScreenReader() {
		t.Fatalf("got %q %q screen reader %v, want TinTin++ 2.02.20 true", info.Name, info.Version, info.ScreenReader())
	}
}

// IPADDRESS is client-supplied, so it is only trustworthy from a proxy an
// admin has listed. None are configured, so it is never stored.
func TestMNESIgnoresIPADDRESS(t *testing.T) {
	c, _ := newTestConn(t)
	feed(c, cmd(WILL, OptNewEnviron)...)
	info := lastUpdate(t, feed(c, mnes(EnvIs, def("CLIENT_NAME", "x"), def("IPADDRESS", "203.0.113.9"))...))
	if v, ok := info.Env["IPADDRESS"]; ok {
		t.Fatalf("IPADDRESS stored as %q", v)
	}
}

// MNES INFO is how a client changes a value mid-session, e.g. turning its
// screen reader off.
func TestMNESInfoUpdatesMTTS(t *testing.T) {
	c, _ := newTestConn(t)
	feed(c, cmd(WILL, OptNewEnviron)...)
	feed(c, mnes(EnvIs, def("MTTS", "64"))...)
	if info := lastUpdate(t, feed(c, mnes(EnvInfo, def("MTTS", "0"))...)); info.ScreenReader() {
		t.Fatal("screen reader still reported after MNES INFO set MTTS to 0")
	}
}

// RFC 1572: "VAR name" with no VAL means the client does not have the
// variable. Mudlet 5.1 lists every requested variable that way before
// sending the ones it supports.
func TestMNESUndefinedVariables(t *testing.T) {
	t.Run("not recorded", func(t *testing.T) {
		c, _ := newTestConn(t)
		feed(c, cmd(WILL, OptNewEnviron)...)
		info := lastUpdate(t, feed(c, mnes(EnvIs,
			undef("CLIENT_NAME"), undef("CLIENT_VERSION"), undef("CHARSET"), undef("MTTS"), undef("TERMINAL_TYPE"),
			def("CHARSET", "UTF-8"), def("MTTS", fmt.Sprint(mudletMTTS)))...))
		want := map[string]string{"CHARSET": "UTF-8", "MTTS": fmt.Sprint(mudletMTTS)}
		if fmt.Sprint(info.Env) != fmt.Sprint(want) {
			t.Fatalf("Env = %v, want %v", info.Env, want)
		}
	})
	t.Run("defined but empty is recorded", func(t *testing.T) {
		c, _ := newTestConn(t)
		feed(c, cmd(WILL, OptNewEnviron)...)
		info := lastUpdate(t, feed(c, mnes(EnvIs, def("CLIENT_VERSION", ""))...))
		if v, ok := info.Env["CLIENT_VERSION"]; !ok || v != "" {
			t.Fatalf("Env = %v, want CLIENT_VERSION recorded as empty", info.Env)
		}
	})
	t.Run("INFO undefining a variable removes it", func(t *testing.T) {
		c, _ := newTestConn(t)
		feed(c, cmd(WILL, OptNewEnviron)...)
		feed(c, mnes(EnvIs, def("CHARSET", "UTF-8"))...)
		info := lastUpdate(t, feed(c, mnes(EnvInfo, undef("CHARSET"))...))
		if _, ok := info.Env["CHARSET"]; ok {
			t.Fatalf("Env = %v, want CHARSET removed", info.Env)
		}
	})
}

// Identity can arrive by TTYPE and MNES in either order. MNES values are
// explicit and win; empty ones never erase what TTYPE reported.
func TestIdentityPrecedence(t *testing.T) {
	tests := []struct {
		name         string
		ttype        []string
		mnes         []envVar
		wantName     string
		wantTerminal string
		wantMTTS     int
		wantSource   string
	}{
		{
			name:     "empty MNES values do not erase TTYPE",
			ttype:    []string{"MUDLET", "ANSI-TRUECOLOR", fmt.Sprintf("MTTS %d", mudletMTTS)},
			mnes:     []envVar{def("CLIENT_NAME", ""), def("TERMINAL_TYPE", ""), def("MTTS", fmt.Sprint(mudletMTTS))},
			wantName: "MUDLET", wantTerminal: "ANSI-TRUECOLOR", wantMTTS: mudletMTTS, wantSource: session.SourceTTYPE,
		},
		{
			// TinTin++ 2.02 only sets the MNES bit in its MNES answer.
			name:     "MNES MTTS wins over TTYPE MTTS",
			ttype:    []string{"TINTIN++", "XTERM-256COLOR", fmt.Sprintf("MTTS %d", tintinTTYPEMTTS)},
			mnes:     []envVar{def("MTTS", fmt.Sprint(tintinMNESMTTS))},
			wantName: "TINTIN++", wantTerminal: "XTERM-256COLOR", wantMTTS: tintinMNESMTTS, wantSource: session.SourceTTYPE,
		},
		{
			name:     "MNES name and terminal win over TTYPE",
			ttype:    []string{"TINTIN++", "XTERM-256COLOR", fmt.Sprintf("MTTS %d", tintinTTYPEMTTS)},
			mnes:     []envVar{def("CLIENT_NAME", "TinTin++"), def("TERMINAL_TYPE", "xterm-256color")},
			wantName: "TinTin++", wantTerminal: "xterm-256color", wantMTTS: tintinTTYPEMTTS, wantSource: session.SourceMNES,
		},
	}
	for _, tt := range tests {
		for _, mnesFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/mnesFirst=%v", tt.name, mnesFirst), func(t *testing.T) {
				c, _ := newTestConn(t)
				feed(c, cmd(WILL, OptTTYPE)...)
				feed(c, cmd(WILL, OptNewEnviron)...)
				if mnesFirst {
					feed(c, mnes(EnvIs, tt.mnes...)...)
				}
				for _, v := range tt.ttype {
					feed(c, ttypeIs(v)...)
				}
				if !mnesFirst {
					feed(c, mnes(EnvIs, tt.mnes...)...)
				}
				got := clientInfo(c)
				if got.Name != tt.wantName || got.Terminal != tt.wantTerminal || got.MTTS != tt.wantMTTS || got.NameSource != tt.wantSource {
					t.Fatalf("got name %q terminal %q mtts %d source %q\nwant name %q terminal %q mtts %d source %q",
						got.Name, got.Terminal, got.MTTS, got.NameSource,
						tt.wantName, tt.wantTerminal, tt.wantMTTS, tt.wantSource)
				}
			})
		}
	}
}

// ---------------------------------------------------------------- NAWS, CHARSET, MSSP

func TestNAWS(t *testing.T) {
	c, _ := newTestConn(t)
	feed(c, cmd(WILL, OptNAWS)...)
	// Width 255 is the IAC byte, so it arrives doubled.
	info := lastUpdate(t, feed(c, sb(OptNAWS, 0, IAC, IAC, 0, 50)...))
	if info.Width != 255 || info.Height != 50 {
		t.Fatalf("window %dx%d, want 255x50", info.Width, info.Height)
	}
}

func TestNAWSIgnoredUnlessNegotiated(t *testing.T) {
	c, _ := newTestConn(t)
	if evs := feed(c, sb(OptNAWS, 0, 80, 0, 24)...); len(evs) != 0 {
		t.Fatalf("NAWS before WILL NAWS produced %#v", evs)
	}
}

func TestCharset(t *testing.T) {
	t.Run("server request accepted", func(t *testing.T) {
		c, f := newTestConn(t)
		feed(c, cmd(DO, OptCharset)...)
		wantSent(t, f, sb(OptCharset, append([]byte{CharsetRequest}, ";UTF-8"...)...))
		info := lastUpdate(t, feed(c, sb(OptCharset, append([]byte{CharsetAccepted}, "UTF-8"...)...)...))
		if info.Charset != "UTF-8" {
			t.Fatalf("charset %q, want UTF-8", info.Charset)
		}
	})
	t.Run("client request picks UTF-8 from its list", func(t *testing.T) {
		c, f := newTestConn(t)
		feed(c, cmd(DO, OptCharset)...)
		f.takeSent()
		feed(c, sb(OptCharset, append([]byte{CharsetRequest}, " ISO-8859-1 UTF-8"...)...)...)
		wantSent(t, f, sb(OptCharset, append([]byte{CharsetAccepted}, "UTF-8"...)...))
	})
	t.Run("client request without UTF-8 rejected", func(t *testing.T) {
		c, f := newTestConn(t)
		feed(c, cmd(DO, OptCharset)...)
		f.takeSent()
		feed(c, sb(OptCharset, append([]byte{CharsetRequest}, ";KOI8-R"...)...)...)
		wantSent(t, f, sb(OptCharset, CharsetRejected))
	})
}

func TestMSSP(t *testing.T) {
	c, f := newTestConn(t)
	feed(c, cmd(DO, OptMSSP)...)
	want := sb(OptMSSP, cat(
		[]byte{MSSPVarCode}, []byte("NAME"), []byte{MSSPValCode}, []byte("Test"),
		[]byte{MSSPVarCode}, []byte("PLAYERS"), []byte{MSSPValCode}, []byte("3"),
		// A variable may carry several values.
		[]byte{MSSPVarCode}, []byte("WEBSOCKET_SUBPROTOCOLS"), []byte{MSSPValCode}, []byte("a"), []byte{MSSPValCode}, []byte("b"),
	)...)
	wantSent(t, f, want)
}

// ---------------------------------------------------------------- GMCP

func TestGMCP(t *testing.T) {
	gmcpSB := func(s string) []byte { return sb(OptGMCP, []byte(s)...) }

	t.Run("ignored before negotiation", func(t *testing.T) {
		c, _ := newTestConn(t)
		if evs := feed(c, gmcpSB(`Core.Hello {}`)...); len(evs) != 0 {
			t.Fatalf("GMCP before DO GMCP produced %#v", evs)
		}
	})
	t.Run("valid message delivered", func(t *testing.T) {
		c, _ := newTestConn(t)
		feed(c, cmd(DO, OptGMCP)...)
		evs := feed(c, gmcpSB(`Core.Hello {"client":"Mudlet","version":"5.1.1"}`)...)
		if len(evs) != 1 {
			t.Fatalf("got %d events %#v, want 1", len(evs), evs)
		}
		g, ok := evs[0].(session.GMCP)
		if !ok || g.Package != "Core.Hello" || string(g.Data) != `{"client":"Mudlet","version":"5.1.1"}` {
			t.Fatalf("got %#v, want Core.Hello with its payload", evs[0])
		}
	})
	for _, bad := range []string{`Core.Hello {"client":`, `Core.Hello not-json`, `Bad Package!`} {
		t.Run("malformed rejected: "+bad, func(t *testing.T) {
			c, _ := newTestConn(t)
			feed(c, cmd(DO, OptGMCP)...)
			if evs := feed(c, gmcpSB(bad)...); len(evs) != 0 {
				t.Fatalf("malformed GMCP produced %#v", evs)
			}
		})
	}
	t.Run("outbound message compacted and framed", func(t *testing.T) {
		c, f := newTestConn(t)
		feed(c, cmd(DO, OptGMCP)...)
		write(t, c, session.GMCPOut{Package: "Char.Vitals", Data: json.RawMessage(`{"hp": 10}`)})
		wantSent(t, f, gmcpSB(`Char.Vitals {"hp":10}`))
	})
	t.Run("outbound dropped without negotiation", func(t *testing.T) {
		c, f := newTestConn(t)
		write(t, c, session.GMCPOut{Package: "Char.Vitals", Data: json.RawMessage(`{}`)})
		wantSent(t, f, nil)
	})
}

// ---------------------------------------------------------------- output encoding

// Prompts end with EOR when negotiated so clients and screen readers know
// where a prompt ends; otherwise GA, unless SGA suppressed it.
func TestPromptTerminators(t *testing.T) {
	tests := []struct {
		name  string
		setup [][]byte
		want  []byte
	}{
		{"EOR negotiated", [][]byte{cmd(DO, OptEOR)}, []byte{'>', ' ', IAC, EOR}},
		{"neither EOR nor SGA", nil, []byte{'>', ' ', IAC, GA}},
		{"SGA without EOR", [][]byte{cmd(DO, OptSGA)}, []byte{'>', ' '}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, f := newTestConn(t)
			for _, s := range tt.setup {
				feed(c, s...)
			}
			f.takeSent()
			write(t, c, session.Prompt{Text: "> "})
			wantSent(t, f, tt.want)
		})
	}
}

func TestTextEncoding(t *testing.T) {
	c, f := newTestConn(t)
	// LF becomes CRLF, a bare CR becomes CR NUL (RFC 854), and invalid
	// UTF-8 becomes U+FFFD so no raw IAC byte can reach the wire.
	write(t, c, session.Text{Text: "a\nb\r\nc\rd\xff"})
	wantSent(t, f, []byte("a\r\nb\r\nc\r\x00d\xef\xbf\xbd"))
}

// ---------------------------------------------------------------- input

func TestLineAssembly(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"CRLF", "look\r\n", []string{"look"}},
		{"CR NUL", "cr nul\r\x00", []string{"cr nul"}},
		{"bare LF", "lf only\n", []string{"lf only"}},
		{"empty line", "\r\n", []string{""}},
		// Clients in character mode send BS or DEL.
		{"backspace", "typo\x08\x08\x08\x08fixed\r\n", []string{"fixed"}},
		{"DEL erases a whole rune", "ünï\x7fi\r\n", []string{"üni"}},
		{"escape sequences stripped", "esc\x1b[31mape\r\n", []string{"escape"}},
		{"IAC IAC is data", "a\xff\xffb\r\n", []string{"a�b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestConn(t)
			if got := linesIn(feed(c, []byte(tt.in)...)); fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Fatalf("lines %q, want %q", got, tt.want)
			}
		})
	}

	// Reads can split anywhere, including between the CR and LF of one
	// line ending.
	t.Run("split across reads", func(t *testing.T) {
		c, _ := newTestConn(t)
		var got []string
		for _, chunk := range []string{"split ", "line\r", "\nnext\r\n"} {
			got = append(got, linesIn(feed(c, []byte(chunk)...))...)
		}
		if want := []string{"split line", "next"}; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
	})
}

func TestLineTruncatedAtMaxLine(t *testing.T) {
	c, _ := newTestConn(t)
	got := linesIn(feed(c, append(bytes.Repeat([]byte("x"), MaxLine+100), '\r', '\n')...))
	if len(got) != 1 || len(got[0]) != MaxLine {
		t.Fatalf("got %d lines, want 1 line of %d bytes", len(got), MaxLine)
	}
}

func TestOversizeSubnegotiationDiscarded(t *testing.T) {
	c, _ := newTestConn(t)
	feed(c, cmd(DO, OptGMCP)...)
	big := cat([]byte(`Core.Hello "`), bytes.Repeat([]byte("x"), MaxSubneg), []byte(`"`))
	if evs := feed(c, sb(OptGMCP, big...)...); len(evs) != 0 {
		t.Fatalf("oversize subnegotiation produced %d events", len(evs))
	}
	if got := linesIn(feed(c, []byte("ok\r\n")...)); fmt.Sprint(got) != "[ok]" {
		t.Fatalf("after oversize subnegotiation, lines %q, want [ok]", got)
	}
}

// IAC followed by a command inside a subnegotiation is a protocol error;
// the subnegotiation is abandoned and the command handled normally.
func TestCommandInsideSubnegotiationAbandonsIt(t *testing.T) {
	c, f := newTestConn(t)
	feed(c, cat([]byte{IAC, SB, OptGMCP}, []byte("Core.He"), cmd(WILL, OptSGA))...)
	wantSent(t, f, cmd(DO, OptSGA))
}

// ---------------------------------------------------------------- MCCP2

func TestMCCP2(t *testing.T) {
	c, f := newTestConn(t)
	start := sb(OptMCCP2)

	feed(c, cmd(DO, OptMCCP2)...)
	write(t, c, session.Text{Text: "compressed hello\n"})
	sent := f.takeSent()
	if !bytes.HasPrefix(sent, start) {
		t.Fatalf("step 1: no MCCP2 start sequence; sent %s", Describe(sent))
	}
	stream := sent[len(start):]
	zr, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("step 1: zlib header: %v", err)
	}
	want := "compressed hello\r\n"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(zr, got); err != nil || string(got) != want {
		t.Fatalf("step 1: decompressed %q (%v), want %q", got, err, want)
	}

	// DONT MCCP2 ends the zlib stream, then the WONT goes out uncompressed.
	feed(c, cmd(DONT, OptMCCP2)...)
	tail := f.takeSent()
	if !bytes.HasSuffix(tail, cmd(WONT, OptMCCP2)) {
		t.Fatalf("step 2: tail does not end with an uncompressed WONT MCCP2: %v", tail)
	}
	zr2, err := zlib.NewReader(bytes.NewReader(cat(stream, tail[:len(tail)-3])))
	if err != nil {
		t.Fatalf("step 2: %v", err)
	}
	if all, err := io.ReadAll(zr2); err != nil || string(all) != want {
		t.Fatalf("step 2: stream did not end cleanly: %q, %v", all, err)
	}

	write(t, c, session.Text{Text: "plain\n"})
	wantSent(t, f, []byte("plain\r\n"))
}

// ---------------------------------------------------------------- transport

func TestReadEventOverStream(t *testing.T) {
	c, f := newTestConn(t)
	f.in <- []byte("hello\r\n")
	ev, err := c.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if l, ok := ev.(session.Line); !ok || l.Text != "hello" {
		t.Fatalf("got %#v, want Line hello", ev)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.ReadEvent(); err != io.EOF {
		t.Fatalf("ReadEvent after Close: %v, want io.EOF", err)
	}
}

// ---------------------------------------------------------------- limits and hostile input (red-team round 1)

// RFC 1073: NAWS width and height are 16-bit big-endian; 300 needs the
// high byte (0x012C).
func TestNAWSUsesHighByte(t *testing.T) {
	c, _ := newTestConn(t)
	info := lastUpdate(t, feed(c, cat(cmd(WILL, OptNAWS), sb(OptNAWS, 0x01, 0x2C, 0x01, 0x2C))...))
	if info.Width != 300 || info.Height != 300 {
		t.Fatalf("window %dx%d, want 300x300", info.Width, info.Height)
	}
}

// An oversize subnegotiation is discarded whole, never truncated and then
// acted on. Cut at MaxSubneg, this TTYPE reply would be a valid name once
// its trailing spaces were trimmed. (A GMCP payload would not show the
// bug: GMCP's own size limit rejects it either way.)
func TestOversizeSubnegotiationNotTruncated(t *testing.T) {
	c, _ := newTestConn(t)
	feed(c, cmd(WILL, OptTTYPE)...)
	padded := "MUDLET" + strings.Repeat(" ", MaxSubneg)
	feed(c, ttypeIs(padded)...)
	if info := clientInfo(c); info.Name != "" {
		t.Fatalf("oversize TTYPE reply was truncated and used: name %q", info.Name)
	}
}

// Replies to requests we never made are ignored: identity is only taken
// from the exchange the server started.
func TestUnsolicitedRepliesIgnored(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"TTYPE IS without WILL TTYPE", ttypeIs("SPOOF")},
		{"NEW-ENVIRON IS without WILL NEW-ENVIRON", mnes(EnvIs, def("CLIENT_NAME", "SPOOF"))},
		{"CHARSET ACCEPTED without our REQUEST", sb(OptCharset, append([]byte{CharsetAccepted}, "KOI8-R"...)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestConn(t)
			feed(c, tt.in...)
			info := clientInfo(c)
			if info.Name != "" || info.Terminal != "" || info.HasMTTS || len(info.Env) != 0 || info.Charset != "UTF-8" {
				t.Fatalf("unsolicited reply changed identity: %+v", info)
			}
		})
	}
}

// A client that keeps inventing new terminal types is asked at most
// maxTTYPE times.
func TestTTYPERequestsAreBounded(t *testing.T) {
	c, f := newTestConn(t)
	feed(c, cmd(WILL, OptTTYPE)...)
	requests := bytes.Count(f.takeSent(), sb(OptTTYPE, TTypeSend))
	for i := 0; i < 10; i++ {
		feed(c, ttypeIs(fmt.Sprintf("TERM-%d", i))...)
		requests += bytes.Count(f.takeSent(), sb(OptTTYPE, TTypeSend))
	}
	if requests != maxTTYPE {
		t.Fatalf("sent %d TTYPE requests, want %d", requests, maxTTYPE)
	}
}

func TestClientIdentityIsSanitisedAndCapped(t *testing.T) {
	t.Run("escape sequences stripped from TTYPE", func(t *testing.T) {
		c, _ := newTestConn(t)
		feed(c, cmd(WILL, OptTTYPE)...)
		if info := lastUpdate(t, feed(c, ttypeIs("MUD\x1b[31mLET")...)); info.Name != "MUDLET" {
			t.Fatalf("name %q, want MUDLET", info.Name)
		}
	})
	t.Run("MNES value capped", func(t *testing.T) {
		c, _ := newTestConn(t)
		feed(c, cmd(WILL, OptNewEnviron)...)
		info := lastUpdate(t, feed(c, mnes(EnvIs, def("CLIENT_NAME", strings.Repeat("x", 1000)))...))
		if n := len(info.Name); n != maxEnvValue {
			t.Fatalf("name is %d bytes, want capped at %d", n, maxEnvValue)
		}
	})
	t.Run("non-MNES variables not kept", func(t *testing.T) {
		// BSD telnet sends USER, the local account name.
		c, _ := newTestConn(t)
		feed(c, cmd(WILL, OptNewEnviron)...)
		info := lastUpdate(t, feed(c, mnes(EnvIs, def("CLIENT_NAME", "x"), def("USER", "alice"))...))
		if _, ok := info.Env["USER"]; ok {
			t.Fatalf("Env = %v, want USER not kept", info.Env)
		}
	})
	t.Run("CHARSET answer sanitised", func(t *testing.T) {
		c, _ := newTestConn(t)
		feed(c, cmd(DO, OptCharset)...)
		info := lastUpdate(t, feed(c, sb(OptCharset, append([]byte{CharsetAccepted}, "UTF-8\x1b[2J"...)...)...))
		if info.Charset != "UTF-8" {
			t.Fatalf("charset %q, want UTF-8", info.Charset)
		}
	})
}

func TestCharsetRequestEdgeCases(t *testing.T) {
	t.Run("TTABLE prefix skipped (RFC 2066)", func(t *testing.T) {
		c, f := newTestConn(t)
		feed(c, cmd(DO, OptCharset)...)
		f.takeSent()
		feed(c, sb(OptCharset, append([]byte{CharsetRequest}, "[TTABLE]\x01;UTF-8"...)...)...)
		wantSent(t, f, sb(OptCharset, append([]byte{CharsetAccepted}, "UTF-8"...)...))
	})
	t.Run("ignored when CHARSET is not enabled", func(t *testing.T) {
		c, f := newTestConn(t)
		feed(c, sb(OptCharset, append([]byte{CharsetRequest}, ";UTF-8"...)...)...)
		wantSent(t, f, nil)
	})
}

// MSSP values come from the server, but the telnet layer still strips
// control bytes, which would corrupt the VAR/VAL framing.
func TestMSSPValuesCleaned(t *testing.T) {
	f := &fakeRW{in: make(chan []byte, 1)}
	c := NewConn(f, Config{Log: discardLog, MSSP: func() []MSSPVar {
		return []MSSPVar{{"NAME", []string{"a\x01b\x7fc"}}}
	}})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	f.takeSent()
	feed(c, cmd(DO, OptMSSP)...)
	wantSent(t, f, sb(OptMSSP, cat([]byte{MSSPVarCode}, []byte("NAME"), []byte{MSSPValCode}, []byte("abc"))...))
}

// The zlib header goes out with the start sequence, so a client can set up
// decompression immediately rather than on the next output.
func TestMCCP2HeaderSentImmediately(t *testing.T) {
	c, f := newTestConn(t)
	feed(c, cmd(DO, OptMCCP2)...)
	sent := f.takeSent()
	start := sb(OptMCCP2)
	if !bytes.HasPrefix(sent, start) || len(sent) <= len(start) || sent[len(start)] != 0x78 {
		t.Fatalf("sent %s, want the MCCP2 start followed by a zlib header (0x78 ...)", Describe(sent))
	}
}

// Close must not wait the full write timeout on a stalled client. Close
// shortens the write deadline before taking the lock, so a write already
// under way must not lengthen it again. This drives that write directly:
// with closing set, a flush keeps the short deadline.
func TestFlushDuringCloseKeepsShortDeadline(t *testing.T) {
	c, f := newTestConn(t)
	c.closing.Store(true) // as Close does before waiting for the lock
	before := time.Now()
	write(t, c, session.Text{Text: "last words\n"})
	if d := f.lastDeadline().Sub(before); d > closeGrace+100*time.Millisecond {
		t.Fatalf("flush set a deadline %v ahead while closing, want at most %v", d, closeGrace)
	}
}
