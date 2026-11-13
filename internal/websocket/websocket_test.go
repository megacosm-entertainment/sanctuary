package websocket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sentience/internal/session"
	"sentience/internal/websocket/wstest"
)

// ---------------------------------------------------------------- handshake

func upgradeRequest(protocols, origin string) *http.Request {
	r := httptest.NewRequest("GET", "https://mud.example:9020/", nil)
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if protocols != "" {
		r.Header.Set("Sec-WebSocket-Protocol", protocols)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestAcceptKey(t *testing.T) {
	// The worked example in RFC 6455 §1.3.
	const key, want = "dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := AcceptKey(key); got != want {
		t.Fatalf("AcceptKey(%q) = %q, want %q", key, got, want)
	}
}

func TestNegotiateSubprotocol(t *testing.T) {
	tests := []struct {
		name, offered   string
		wantProto       string
		wantEcho        string // the client's spelling, echoed back
		wantRefusedWith int    // HTTP status; 0 means accepted
	}{
		{"gmcp", "gmcp.mudstandards.org", ProtoGMCP, "gmcp.mudstandards.org", 0},
		{"telnet", "telnet.mudstandards.org", ProtoTelnet, "telnet.mudstandards.org", 0},
		{"telnet short alias", "telnet", ProtoTelnet, "telnet", 0},
		{"server preference wins", "telnet.mudstandards.org, gmcp.mudstandards.org", ProtoGMCP, "gmcp.mudstandards.org", 0},
		{"unknown ones skipped", "v1.someone-else.com, telnet", ProtoTelnet, "telnet", 0},
		{"case-insensitive, client spelling echoed", "GMCP.MudStandards.org", ProtoGMCP, "GMCP.MudStandards.org", 0},
		// Negotiation is explicit: telnet-over-WebSocket and the GMCP
		// subprotocol are not interchangeable, so there is no default.
		{"none offered", "", "", "", http.StatusBadRequest},
		{"only unsupported", "chat, superchat", "", "", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto, echo, err := Negotiate(upgradeRequest(tt.offered, ""), OriginPolicy{})
			if tt.wantRefusedWith != 0 {
				var he *HandshakeError
				if !errors.As(err, &he) || he.Status != tt.wantRefusedWith {
					t.Fatalf("Negotiate(%q) error = %v, want HTTP %d", tt.offered, err, tt.wantRefusedWith)
				}
				return
			}
			if err != nil || proto != tt.wantProto || echo != tt.wantEcho {
				t.Fatalf("Negotiate(%q) = %q, %q, %v; want %q, %q, nil", tt.offered, proto, echo, err, tt.wantProto, tt.wantEcho)
			}
		})
	}
}

func TestOriginPolicy(t *testing.T) {
	tests := []struct {
		name, origin string
		allowed      []string
		wantOK       bool
	}{
		// Non-browser clients send no Origin and cannot be used for
		// cross-site WebSocket hijacking.
		{"no origin", "", nil, true},
		{"same origin", "https://mud.example:9020", nil, true},
		{"cross origin", "https://evil.example", nil, false},
		{"opaque origin (file://, sandboxed iframe)", "null", nil, false},
		{"allowlisted", "https://play.mud.example", []string{"https://play.mud.example"}, true},
		{"allowlist replaces same-origin", "https://mud.example:9020", []string{"https://play.mud.example"}, false},
		{"allowlist entry with trailing slash", "https://play.mud.example", []string{"https://play.mud.example/"}, true},
		// Same origin includes the scheme (RFC 6454): the request is https.
		{"same host, other scheme", "http://mud.example:9020", nil, false},
		{"origin without a host", "https://", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Negotiate(upgradeRequest(ProtoGMCP, tt.origin), OriginPolicy{Allowed: tt.allowed})
			if gotOK := err == nil; gotOK != tt.wantOK {
				t.Fatalf("origin %q, allowed %v: accepted = %v (err %v), want %v", tt.origin, tt.allowed, gotOK, err, tt.wantOK)
			}
		})
	}
}

func TestNegotiateRejectsMalformedUpgrade(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"old protocol version", func(r *http.Request) { r.Header.Set("Sec-WebSocket-Version", "8") }},
		{"key not 16 bytes", func(r *http.Request) { r.Header.Set("Sec-WebSocket-Key", "c2hvcnQ=") }},
		{"not an upgrade", func(r *http.Request) { r.Header.Del("Upgrade") }},
		{"not GET", func(r *http.Request) { r.Method = http.MethodPost }},
		{"Connection header without upgrade", func(r *http.Request) { r.Header.Set("Connection", "keep-alive") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := upgradeRequest(ProtoGMCP, "")
			tt.mutate(r)
			if _, _, err := Negotiate(r, OriginPolicy{}); err == nil {
				t.Fatal("accepted, want refused")
			}
		})
	}
}

// ---------------------------------------------------------------- framing

// pipe returns a server Conn and a wstest client joined by net.Pipe. Writes
// on a pipe block until the other side reads, so each test runs the server
// side in a goroutine (see serve) and drives the client from the test
// goroutine.
func pipe(t *testing.T) (*Conn, *wstest.Client) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() }) // also ends any server goroutine still reading
	return NewServerConn(a), wstest.NewClient(b)
}

type message struct {
	op  byte
	msg []byte
	err error
}

// serveRead runs one ReadMessage in the background and delivers the result.
func serveRead(s *Conn) <-chan message {
	ch := make(chan message, 1)
	go func() {
		op, msg, err := s.ReadMessage()
		ch <- message{op, msg, err}
	}()
	return ch
}

func mustSend(t *testing.T, c *wstest.Client, fin bool, op byte, p []byte) {
	t.Helper()
	if err := c.WriteFrame(fin, op, p); err != nil {
		t.Fatalf("client write: %v", err)
	}
}

// expectClose reads the server's close frame and checks its status code.
func expectClose(t *testing.T, c *wstest.Client, wantCode int) {
	t.Helper()
	op, p, err := c.ReadFrame()
	if err != nil {
		t.Fatalf("reading close frame: %v", err)
	}
	if op != OpClose || wstest.CloseCode(p) != wantCode {
		t.Fatalf("got opcode %d code %d, want close %d", op, wstest.CloseCode(p), wantCode)
	}
}

// RFC 6455 §5.4: control frames may arrive between the fragments of a
// message and must be answered without disturbing it.
func TestFragmentedMessageWithInterleavedPing(t *testing.T) {
	s, c := pipe(t)
	got := serveRead(s)

	mustSend(t, c, false, OpBinary, []byte("hel"))
	mustSend(t, c, true, OpPing, []byte("p"))
	op, p, err := c.ReadFrame()
	if err != nil || op != OpPong || string(p) != "p" {
		t.Fatalf("got opcode %d %q (%v), want pong \"p\"", op, p, err)
	}
	mustSend(t, c, true, OpContinuation, []byte("lo"))

	m := <-got
	if m.err != nil || m.op != OpBinary || string(m.msg) != "hello" {
		t.Fatalf("ReadMessage = %d %q %v, want binary \"hello\"", m.op, m.msg, m.err)
	}
}

func TestProtocolViolationsClose(t *testing.T) {
	tests := []struct {
		name     string
		send     func(*wstest.Client) error
		wantCode int
	}{
		// RFC 6455 §5.1: a server must close on an unmasked client frame.
		{"unmasked frame", func(c *wstest.Client) error { return c.WriteUnmaskedFrame(OpBinary, []byte("x")) }, CloseProtocolError},
		{"text frame not UTF-8", func(c *wstest.Client) error { return c.Send(OpText, []byte{0xff, 0xfe}) }, CloseInvalidData},
		{"declared length over MaxMessage", func(c *wstest.Client) error {
			// Header only: the server must refuse before reading a payload.
			h := []byte{0x80 | OpBinary, 0x80 | 127}
			return c.WriteRaw(binary.BigEndian.AppendUint64(h, MaxMessage+1))
		}, CloseTooBig},
		{"continuation without a start", func(c *wstest.Client) error { return c.WriteFrame(true, OpContinuation, []byte("x")) }, CloseProtocolError},
		{"unknown opcode", func(c *wstest.Client) error { return c.Send(0x3, nil) }, CloseProtocolError},
		// §5.2: RSV1-3 must be 0 without a negotiated extension.
		{"reserved bit set", func(c *wstest.Client) error { return c.WriteRaw([]byte{0x80 | 0x40 | OpBinary, 0x80, 0, 0, 0, 0}) }, CloseProtocolError},
		// §5.5: control frames are at most 125 bytes and never fragmented.
		{"ping of 126 bytes", func(c *wstest.Client) error { return c.Send(OpPing, make([]byte, 126)) }, CloseProtocolError},
		{"fragmented ping", func(c *wstest.Client) error { return c.WriteFrame(false, OpPing, []byte("x")) }, CloseProtocolError},
		// MaxMessage applies to the assembled message, not only to one frame.
		{"fragments totalling over MaxMessage", func(c *wstest.Client) error {
			if err := c.WriteFrame(false, OpBinary, make([]byte, MaxMessage/2+1)); err != nil {
				return err
			}
			return c.WriteFrame(true, OpContinuation, make([]byte, MaxMessage/2+1))
		}, CloseTooBig},
		// §5.5.1, §7.4: a malformed close frame fails the connection
		// rather than being acknowledged.
		{"close payload of one byte", func(c *wstest.Client) error { return c.Send(OpClose, []byte{0x03}) }, CloseProtocolError},
		{"close code 0", func(c *wstest.Client) error { return c.Send(OpClose, []byte{0x00, 0x00}) }, CloseProtocolError},
		{"reserved close code 1005", func(c *wstest.Client) error { return c.Send(OpClose, []byte{0x03, 0xed}) }, CloseProtocolError},
		{"close reason not UTF-8", func(c *wstest.Client) error { return c.Send(OpClose, []byte{0x03, 0xe8, 0xff}) }, CloseInvalidData},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, c := pipe(t)
			got := serveRead(s)
			if err := tt.send(c); err != nil {
				t.Fatalf("client write: %v", err)
			}
			expectClose(t, c, tt.wantCode)
			var ce *CloseError
			if m := <-got; !errors.As(m.err, &ce) || ce.Code != tt.wantCode {
				t.Fatalf("ReadMessage error = %v, want CloseError %d", m.err, tt.wantCode)
			}
		})
	}
}

// ---------------------------------------------------------------- gmcp.mudstandards.org transport

func newGMCPTransport(t *testing.T) (*GMCPTransport, *wstest.Client) {
	t.Helper()
	s, c := pipe(t)
	return NewGMCPTransport(s, session.Meta{Kind: "ws/gmcp"}, slog.New(slog.NewTextHandler(io.Discard, nil))), c
}

// clientSends writes frames in order from a goroutine, since each write
// blocks until the transport reads it. The returned channel yields the
// first write error, or nil once every frame is written.
func clientSends(c *wstest.Client, frames ...[2]any) <-chan error {
	done := make(chan error, 1)
	go func() {
		for _, f := range frames {
			if err := c.Send(f[0].(byte), []byte(f[1].(string))); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	return done
}

func TestGMCPTransportInbound(t *testing.T) {
	tr, c := newGMCPTransport(t)
	sent := clientSends(c,
		[2]any{OpBinary, "look\r\nsay \x1b[31mhi\n"},  // two lines in one frame; ANSI stripped
		[2]any{OpText, `Core.Hello {"client":`},       // malformed: must be dropped
		[2]any{OpText, `Core.Hello {"client":"web"}`}, // valid
		[2]any{OpBinary, "after"},                     // trailing newline optional
	)
	want := []session.Inbound{
		session.Line{Text: "look"},
		session.Line{Text: "say hi"},
		session.GMCP{Package: "Core.Hello", Data: []byte(`{"client":"web"}`)},
		session.Line{Text: "after"},
	}
	for i, w := range want {
		ev, err := tr.ReadEvent()
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if g, ok := w.(session.GMCP); ok {
			got, ok := ev.(session.GMCP)
			if !ok || got.Package != g.Package || string(got.Data) != string(g.Data) {
				t.Fatalf("event %d = %#v, want %s %s", i, ev, g.Package, g.Data)
			}
			continue
		}
		if ev != w {
			t.Fatalf("event %d = %#v, want %#v", i, ev, w)
		}
	}
	if err := <-sent; err != nil {
		t.Fatalf("client write: %v", err)
	}
}

func TestGMCPTransportOutbound(t *testing.T) {
	tests := []struct {
		name    string
		out     session.Outbound
		wantOp  byte
		wantMsg string
	}{
		{"text in a binary frame with CRLF", session.Text{Text: "hi\n"}, OpBinary, "hi\r\n"},
		{"GMCP in a text frame, compacted", session.GMCPOut{Package: "Char.Vitals", Data: []byte(`{"hp": 1}`)}, OpText, `Char.Vitals {"hp":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, c := newGMCPTransport(t)
			werr := make(chan error, 1)
			go func() { werr <- tr.WriteEvent(tt.out) }()
			op, p, err := c.ReadFrame()
			if err != nil || op != tt.wantOp || string(p) != tt.wantMsg {
				t.Fatalf("got opcode %d %q (%v), want %d %q", op, p, err, tt.wantOp, tt.wantMsg)
			}
			if err := <-werr; err != nil {
				t.Fatalf("WriteEvent: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------- telnet.mudstandards.org stream

func TestStreamPassesBinaryFramesThrough(t *testing.T) {
	s, c := pipe(t)
	st := NewStream(s)
	iacWillNAWS := []byte{255, 251, 31} // IAC WILL NAWS: raw telnet bytes travel unchanged
	sent := clientSends(c, [2]any{OpBinary, string(iacWillNAWS)})
	buf := make([]byte, 16)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != string(iacWillNAWS) {
		t.Fatalf("Read = %q (%v), want %q", buf[:n], err, iacWillNAWS)
	}
	if err := <-sent; err != nil {
		t.Fatalf("client write: %v", err)
	}
}

func TestStreamRejectsTextFrames(t *testing.T) {
	s, c := pipe(t)
	st := NewStream(s)
	readErr := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 16))
		readErr <- err
	}()
	if err := c.Send(OpText, []byte("nope")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectClose(t, c, CloseUnsupported)
	if err := <-readErr; err != io.EOF {
		t.Fatalf("Read error = %v, want io.EOF", err)
	}
}

// ---------------------------------------------------------------- red-team round 1

// A client's close code and reason reach the caller unchanged, and the
// server acknowledges with 1000.
func TestPeerCloseReported(t *testing.T) {
	s, c := pipe(t)
	got := serveRead(s)
	if err := c.Send(OpClose, append([]byte{0x03, 0xe9}, "bye"...)); err != nil { // 1001 going away
		t.Fatalf("client write: %v", err)
	}
	expectClose(t, c, CloseNormal)
	var ce *CloseError
	if m := <-got; !errors.As(m.err, &ce) || ce.Code != CloseGoingAway || ce.Reason != "bye" {
		t.Fatalf("ReadMessage error = %v, want CloseError 1001 \"bye\"", m.err)
	}
}

// RFC 6455 §5.2: payload length is 7 bits up to 125, then 16 bits up to
// 65535, then 64 bits. Check each side of both boundaries.
func TestWriteMessageLengthEncodings(t *testing.T) {
	for _, n := range []int{0, 125, 126, 65535, 65536} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s, c := pipe(t)
			werr := make(chan error, 1)
			go func() { werr <- s.WriteMessage(OpBinary, make([]byte, n)) }()
			op, p, err := c.ReadFrame()
			if err != nil || op != OpBinary || len(p) != n {
				t.Fatalf("read opcode %d, %d bytes (%v), want binary %d bytes", op, len(p), err, n)
			}
			if err := <-werr; err != nil {
				t.Fatalf("WriteMessage: %v", err)
			}
		})
	}
}

// A close reason is truncated so the close frame stays a valid control
// frame (at most 125 bytes: 2 for the code, 123 for the reason).
func TestCloseReasonTruncated(t *testing.T) {
	s, c := pipe(t)
	go s.Close(ClosePolicy, strings.Repeat("r", 300))
	op, p, err := c.ReadFrame()
	if err != nil || op != OpClose || len(p) != 125 || wstest.CloseCode(p) != ClosePolicy {
		t.Fatalf("got opcode %d, %d-byte payload, code %d (%v); want close %d with a 125-byte payload",
			op, len(p), wstest.CloseCode(p), err, ClosePolicy)
	}
}

// A refused upgrade with the wrong version tells the client which version
// to use (RFC 6455 §4.4).
func TestUpgradeAdvertisesSupportedVersion(t *testing.T) {
	r := upgradeRequest(ProtoGMCP, "")
	r.Header.Set("Sec-WebSocket-Version", "8")
	w := httptest.NewRecorder()
	if _, _, err := Upgrade(w, r, OriginPolicy{}); err == nil {
		t.Fatal("Upgrade accepted version 8")
	}
	if w.Code != http.StatusUpgradeRequired || w.Header().Get("Sec-WebSocket-Version") != "13" {
		t.Fatalf("status %d, Sec-WebSocket-Version %q; want 426 and 13", w.Code, w.Header().Get("Sec-WebSocket-Version"))
	}
}

func TestGMCPTransportLimitsAndEncoding(t *testing.T) {
	t.Run("input line capped at 4096 bytes", func(t *testing.T) {
		tr, c := newGMCPTransport(t)
		sent := clientSends(c, [2]any{OpBinary, strings.Repeat("x", 5000)})
		ev, err := tr.ReadEvent()
		if l, ok := ev.(session.Line); err != nil || !ok || len(l.Text) != 4096 {
			t.Fatalf("got %T (%v), want a 4096-byte Line", ev, err)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("invalid UTF-8 output replaced", func(t *testing.T) {
		tr, c := newGMCPTransport(t)
		go tr.WriteEvent(session.Text{Text: "a\xffb"})
		if _, p, err := c.ReadFrame(); err != nil || string(p) != "a\ufffdb" {
			t.Fatalf("frame %q (%v), want %q", p, err, "a\ufffdb")
		}
	})
}
