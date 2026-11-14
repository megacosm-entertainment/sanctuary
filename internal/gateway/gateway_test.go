package gateway_test

// End-to-end tests over real loopback sockets, driven by the shared test
// clients (telnettest, wstest). Handler behaviour is covered without
// sockets by sessiontest; these prove the listeners, TLS and the WebSocket
// upgrade are wired to it.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"sanctuary/internal/echo"
	"sanctuary/internal/gateway"
	tn "sanctuary/internal/telnet"
	"sanctuary/internal/telnet/telnettest"
	"sanctuary/internal/websocket"
	"sanctuary/internal/websocket/wstest"
)

// ---------------------------------------------------------------- fixture

// fixture is a running gateway on loopback ports.
type fixture struct {
	G               *gateway.Gateway
	Telnet, TLS, WS string // listener addresses; empty when disabled
	Logs            *syncBuffer
	cancel          context.CancelFunc
	done            chan struct{}
}

// startGateway runs a gateway with all three listeners on free loopback
// ports. mods adjust the config before it starts. The gateway is stopped
// when the test ends.
func startGateway(t *testing.T, mods ...func(*gateway.Config)) *fixture {
	t.Helper()
	cert, err := gateway.SelfSigned([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	logs := &syncBuffer{}
	cfg := gateway.Config{
		Name:        "Test",
		TelnetAddr:  "127.0.0.1:0",
		TelnetsAddr: "127.0.0.1:0",
		WSAddr:      "127.0.0.1:0",
		TLS:         gateway.TLSConfig(cert),
		Handler:     echo.Handler{},
		Log:         slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, m := range mods {
		m(&cfg)
	}
	g := gateway.New(cfg)
	if err := g.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	f := &fixture{G: g, Logs: logs, done: make(chan struct{})}
	addrs := g.Addrs()
	next := func() string { a := addrs[0].String(); addrs = addrs[1:]; return a }
	if cfg.TelnetAddr != "" {
		f.Telnet = next()
	}
	if cfg.TelnetsAddr != "" {
		f.TLS = next()
	}
	if cfg.WSAddr != "" {
		f.WS = next()
	}
	var ctx context.Context
	ctx, f.cancel = context.WithCancel(context.Background())
	go func() { g.Run(ctx); close(f.done) }()
	t.Cleanup(f.Stop)
	return f
}

// Stop shuts the gateway down and waits for Run to return. Idempotent.
func (f *fixture) Stop() {
	f.cancel()
	<-f.done
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// dialTelnet connects a scripted client and waits until it has seen the
// first prompt and finished identifying itself.
func dialTelnet(t *testing.T, addr string, useTLS bool) *telnettest.Client {
	t.Helper()
	c, err := telnettest.Dial(addr, useTLS, telnettest.ScreenReaderProfile())
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.WaitPrompt(); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitIdentified(); err != nil {
		t.Fatal(err)
	}
	return c
}

// round sends a line and fails unless the reply contains every want.
func round(t *testing.T, c *telnettest.Client, line string, wants ...string) string {
	t.Helper()
	out, err := c.Round(line)
	if err != nil {
		t.Fatalf("after %q: %v", line, err)
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Fatalf("after %q: reply lacks %q; got %q", line, w, out)
		}
	}
	return out
}

func dialWS(t *testing.T, addr string, opts wstest.DialOptions) (*wstest.Client, *http.Response) {
	t.Helper()
	c, resp, err := wstest.Dial(addr, opts)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	return c, resp
}

// ---------------------------------------------------------------- telnet

func TestTelnetEndToEnd(t *testing.T) {
	f := startGateway(t)
	c := dialTelnet(t, f.Telnet, false)

	round(t, c, "hello there", "You said: hello there")
	if got := c.LastPrompt(); got != tn.EOR {
		t.Fatalf("prompt ended with %s, want EOR", tn.Describe([]byte{tn.IAC, got}))
	}
	// info reflects what the client negotiated: NAWS and MTTS from the
	// screen-reader profile.
	round(t, c, "info", "120 x 40", "screen reader: true", "encrypted: false")
}

func TestTelnetTLSEndToEnd(t *testing.T) {
	f := startGateway(t)
	c := dialTelnet(t, f.TLS, true)
	round(t, c, "over tls", "You said: over tls")
	round(t, c, "info", "telnet+tls (encrypted: true)")
}

func TestConnectionLimitPerHost(t *testing.T) {
	f := startGateway(t, func(c *gateway.Config) { c.MaxPerHost = 1 })
	dialTelnet(t, f.Telnet, false) // holds the only slot for 127.0.0.1

	second, err := net.DialTimeout("tcp", f.Telnet, telnettest.DefaultTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(telnettest.DefaultTimeout))
	got, err := io.ReadAll(second) // the gateway writes a refusal and closes
	if err != nil {
		t.Fatalf("reading refusal: %v (got %q)", err, got)
	}
	if !strings.Contains(string(got), "Too many connections") {
		t.Fatalf("second connection got %q, want a refusal", got)
	}
}

// ---------------------------------------------------------------- WebSocket

func TestWebSocketGMCPEndToEnd(t *testing.T) {
	f := startGateway(t)
	c, resp := dialWS(t, f.WS, wstest.DialOptions{
		TLS:       true,
		Protocols: []string{websocket.ProtoGMCP},
		Origin:    "https://" + f.WS, // a browser on the gateway's own page
	})
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Protocol") != websocket.ProtoGMCP {
		t.Fatalf("handshake: status %d protocol %q, want 101 %s", resp.StatusCode, resp.Header.Get("Sec-WebSocket-Protocol"), websocket.ProtoGMCP)
	}
	if _, err := c.ReadUntil(websocket.OpBinary, "> "); err != nil {
		t.Fatalf("banner: %v", err)
	}
	// Core.Hello is the only identity a browser can send; info must
	// show it.
	for _, m := range []struct {
		op byte
		s  string
	}{
		{websocket.OpText, `Core.Hello {"client":"e2e","version":"7"}`},
		{websocket.OpBinary, "info\n"},
	} {
		if err := c.Send(m.op, []byte(m.s)); err != nil {
			t.Fatalf("send %q: %v", m.s, err)
		}
	}
	if _, err := c.ReadUntil(websocket.OpBinary, "e2e 7"); err != nil {
		t.Fatalf("info after Core.Hello: %v", err)
	}
}

func TestWebSocketTelnetEndToEnd(t *testing.T) {
	f := startGateway(t)
	c, resp := dialWS(t, f.WS, wstest.DialOptions{TLS: true, Protocols: []string{"telnet"}})
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Protocol") != "telnet" {
		t.Fatalf("handshake: status %d protocol %q, want 101 telnet", resp.StatusCode, resp.Header.Get("Sec-WebSocket-Protocol"))
	}
	stream, err := c.ReadUntil(websocket.OpBinary, "> ")
	if err != nil {
		t.Fatalf("banner: %v", err)
	}
	if offer := string([]byte{tn.IAC, tn.WILL, tn.OptGMCP}); !strings.Contains(stream, offer) {
		t.Fatalf("telnet negotiation not carried over WebSocket: %s", tn.Describe([]byte(stream)))
	}
	if err := c.Send(websocket.OpBinary, []byte("over ws\r\n")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := c.ReadUntil(websocket.OpBinary, "You said: over ws"); err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketRefusals(t *testing.T) {
	f := startGateway(t)
	tests := []struct {
		name       string
		opts       wstest.DialOptions
		wantStatus int
	}{
		{"cross-origin browser", wstest.DialOptions{TLS: true, Protocols: []string{websocket.ProtoGMCP}, Origin: "https://evil.example"}, http.StatusForbidden},
		{"no subprotocol", wstest.DialOptions{TLS: true}, http.StatusBadRequest},
		{"unsupported subprotocol", wstest.DialOptions{TLS: true, Protocols: []string{"chat"}}, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, resp := dialWS(t, f.WS, tt.opts)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

// ---------------------------------------------------------------- lifecycle and logging

func TestShutdownSaysGoodbyeAndDrains(t *testing.T) {
	f := startGateway(t)
	c := dialTelnet(t, f.Telnet, false)

	stopped := make(chan struct{})
	go func() { f.Stop(); close(stopped) }()
	if err := c.WaitText("shutting down"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not stop within 10s")
	}
	if n := f.G.Registry().Count(); n != 0 {
		t.Fatalf("%d sessions left after shutdown, want 0", n)
	}
	// A clean shutdown is not an error: operators alert on ERROR lines.
	for _, line := range strings.Split(f.Logs.String(), "\n") {
		if strings.Contains(line, `"level":"ERROR"`) {
			t.Errorf("clean shutdown logged an error: %s", line)
		}
	}
}

// Every log line about a connection carries its session ID, so overlapping
// sessions can be told apart.
func TestConnectionLogsCarrySessionID(t *testing.T) {
	f := startGateway(t)
	c := dialTelnet(t, f.Telnet, false)
	// quit closes the connection, so there is no prompt to wait for.
	if err := c.SendLine("quit"); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitText("Goodbye"); err != nil {
		t.Fatal(err)
	}
	c.Close()

	deadline := time.Now().Add(telnettest.DefaultTimeout)
	for !strings.Contains(f.Logs.String(), `"msg":"session closed"`) {
		if time.Now().After(deadline) {
			t.Fatalf("no \"session closed\" log line within %v; logs:\n%s", telnettest.DefaultTimeout, f.Logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(f.Logs.String()), "\n") {
		if !strings.Contains(line, `"remote":`) {
			continue // listener-level lines are not about a connection
		}
		checked++
		if !strings.Contains(line, `"session":`) {
			t.Errorf("log line without session ID: %s", line)
		}
	}
	// Opened, several negotiation lines, closed: far more than three.
	if checked < 3 {
		t.Fatalf("only %d connection log lines; logs:\n%s", checked, f.Logs.String())
	}
}

// ---------------------------------------------------------------- red-team round 1

// Design doc §02: player text, GMCP payloads and non-MNES environment
// variables never reach the logs, even at debug level. Each canary is
// unique, so a hit names the leak.
func TestLogsNeverContainPlayerText(t *testing.T) {
	f := startGateway(t)
	p := telnettest.ScreenReaderProfile()
	p.MNES = append(p.MNES, [2]string{"USER", "CANARY-MNES-USER"})
	c, err := telnettest.Dial(f.Telnet, false, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.WaitPrompt(); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitIdentified(); err != nil {
		t.Fatal(err)
	}
	round(t, c, "CANARY-TELNET-LINE", "You said: CANARY-TELNET-LINE")
	if err := c.SendSB(tn.OptGMCP, []byte(`Char.Login {"password":"CANARY-TELNET-GMCP"}`)...); err != nil {
		t.Fatal(err)
	}
	round(t, c, "sync", "You said: sync") // the GMCP before it has been processed
	round(t, c, "secret")
	round(t, c, "CANARY-SECRET")

	w, _ := dialWS(t, f.WS, wstest.DialOptions{TLS: true, Protocols: []string{websocket.ProtoGMCP}})
	for _, m := range []struct {
		op byte
		s  string
	}{
		{websocket.OpText, `Char.Login {"password":"CANARY-WS-GMCP"}`},
		{websocket.OpBinary, "CANARY-WS-LINE\n"},
	} {
		if err := w.Send(m.op, []byte(m.s)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.ReadUntil(websocket.OpBinary, "You said: CANARY-WS-LINE"); err != nil {
		t.Fatal(err)
	}
	logs := f.Logs.String()
	for _, canary := range []string{"CANARY-TELNET-LINE", "CANARY-TELNET-GMCP", "CANARY-SECRET", "CANARY-MNES-USER", "CANARY-WS-GMCP", "CANARY-WS-LINE"} {
		if strings.Contains(logs, canary) {
			t.Errorf("logs contain %s", canary)
		}
	}
}

func TestWSOriginsConfigReplacesSameOrigin(t *testing.T) {
	f := startGateway(t, func(c *gateway.Config) { c.WSOrigins = []string{"https://play.example"} })
	tests := []struct {
		origin     string
		wantStatus int
	}{
		{"https://play.example", http.StatusSwitchingProtocols},
		{"https://" + f.WS, http.StatusForbidden},
	}
	for _, tt := range tests {
		_, resp := dialWS(t, f.WS, wstest.DialOptions{TLS: true, Protocols: []string{websocket.ProtoGMCP}, Origin: tt.origin})
		if resp.StatusCode != tt.wantStatus {
			t.Errorf("origin %s: status %d, want %d", tt.origin, resp.StatusCode, tt.wantStatus)
		}
	}
}

// -ws-plain serves ws://; sessions must not claim to be encrypted.
func TestPlainWebSocketReportsUnencrypted(t *testing.T) {
	f := startGateway(t, func(c *gateway.Config) { c.WSPlain = true })
	c, resp := dialWS(t, f.WS, wstest.DialOptions{Protocols: []string{websocket.ProtoGMCP}})
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	if err := c.Send(websocket.OpBinary, []byte("info\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadUntil(websocket.OpBinary, "ws/gmcp (encrypted: false)"); err != nil {
		t.Fatal(err)
	}
}

func TestMSSPReportsPlayerCount(t *testing.T) {
	f := startGateway(t)
	c := dialTelnet(t, f.Telnet, false)
	want := append(append([]byte{tn.MSSPVarCode}, "PLAYERS"...), tn.MSSPValCode, '1')
	if len(c.SBs[tn.OptMSSP]) == 0 || !bytes.Contains(c.SBs[tn.OptMSSP][0], want) {
		t.Fatalf("MSSP %q lacks PLAYERS 1", c.SBs[tn.OptMSSP])
	}
}

func TestTestPageSendsSecurityHeaders(t *testing.T) {
	f := startGateway(t)
	cl := &http.Client{Timeout: wstest.DefaultTimeout, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // dev certificate is self-signed
	resp, err := cl.Get("https://" + f.WS + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("Content-Security-Policy %q, want default-src 'self'", csp)
	}
	if v := resp.Header.Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("X-Content-Type-Options %q, want nosniff", v)
	}
}

// A client that opens a TLS connection and never handshakes is dropped
// after HandshakeTimeout, freeing its per-host slot.
func TestStalledTLSHandshakeTimesOut(t *testing.T) {
	f := startGateway(t, func(c *gateway.Config) {
		c.HandshakeTimeout = 200 * time.Millisecond
		c.MaxPerHost = 1
	})
	stalled, err := net.DialTimeout("tcp", f.TLS, telnettest.DefaultTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	stalled.SetReadDeadline(time.Now().Add(telnettest.DefaultTimeout))
	if _, err := io.ReadAll(stalled); err != nil { // nil error means the server closed it
		t.Fatalf("stalled handshake not closed by the server: %v", err)
	}
	dialTelnet(t, f.Telnet, false) // the slot is free again
}
