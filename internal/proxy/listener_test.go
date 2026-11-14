package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"sanctuary/internal/echo"
	"sanctuary/internal/proxy"
	"sanctuary/internal/realm"
	"sanctuary/internal/realmproto"
	rpt "sanctuary/internal/realmproto/realmprototest"
	"sanctuary/internal/session/sessiontest"
)

func linkIdentity(t *testing.T, name string) (tls.Certificate, string) {
	t.Helper()
	certPEM, keyPEM, err := realmproto.GenerateIdentity(name)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	return c, realmproto.Pin(leaf)
}

// listening is a hub serving a real loopback realm port.
type listening struct {
	*hub
	addr  string
	gwPin string
	done  chan error
}

func listen(t *testing.T, realmPins []string, lc proxy.ListenerConfig) *listening {
	t.Helper()
	h := newHub(t, proxy.HubConfig{})
	gwID, gwPin := linkIdentity(t, "gateway")
	conf, err := realmproto.ServerTLS(gwID, realmproto.Trust{Pins: realmPins})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	lc.TLS = conf
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ls := &listening{hub: h, addr: l.Addr().String(), gwPin: gwPin, done: make(chan error, 1)}
	go func() { ls.done <- h.ServeListener(h.ctx, l, lc) }()
	t.Cleanup(func() {
		h.cancel()
		select {
		case <-ls.done:
		case <-time.After(rpt.Timeout):
			t.Error("ServeListener did not return after cancel")
		}
	})
	return ls
}

// runRealm dials ls as a real realm would and serves it until the test ends.
func runRealm(t *testing.T, ls *listening, id tls.Certificate, realmID string) {
	t.Helper()
	conf, err := realmproto.ClientTLS(id, realmproto.Trust{Pins: []string{ls.gwPin}}, "gateway")
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		realm.Run(ctx, realm.TLSDialer(ls.addr, conf, time.Second),
			realm.Config{ID: realmID, Handler: echo.Handler{Banner: "Separate realm.\n"}, Log: quiet},
			realm.Backoff{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond})
	}()
	t.Cleanup(func() { cancel(); <-done })
}

func waitRegistered(t *testing.T, h *hub, id string) {
	t.Helper()
	deadline := time.Now().Add(rpt.Timeout)
	for time.Now().Before(deadline) {
		for _, r := range h.Realms() {
			if r.ID == id {
				return
			}
		}
		time.Sleep(5 * time.Millisecond) // polling with a deadline (testing.md §7)
	}
	t.Fatalf("realm %q never registered; registered: %+v", id, h.Realms())
}

// The production path: a realm process dials the realm port over mTLS,
// registers, and serves a player.
func TestRealmOverMTLSServesPlayers(t *testing.T) {
	realmID, realmPin := linkIdentity(t, "realm")
	ls := listen(t, []string{realmPin}, proxy.ListenerConfig{})
	runRealm(t, ls, realmID, "live")
	waitRegistered(t, ls.hub, "live")

	p := sessiontest.New(t, proxy.Handler{Hub: ls.Hub})
	if banner, _ := p.UntilPrompt(); banner != "Separate realm.\n" {
		t.Fatalf("banner = %q, want the realm's", banner)
	}
	p.Type("over the wire")
	if out, _ := p.UntilPrompt(); out != "You said: over the wire\n" {
		t.Fatalf("echo = %q", out)
	}
}

// A connection that opens TCP and never completes TLS holds its pending
// slot only until the handshake timeout.
func TestHandshakeTimeoutFreesSlot(t *testing.T) {
	_, pin := linkIdentity(t, "realm")
	ls := listen(t, []string{pin}, proxy.ListenerConfig{HandshakeTimeout: 100 * time.Millisecond})
	c, err := net.Dial("tcp", ls.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(rpt.Timeout))
	start := time.Now()
	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, net.ErrClosed) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("silent connection still open after the handshake timeout")
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("silent connection closed after %v, want about the 100ms handshake timeout", d)
	}
}

// closedQuickly reports whether the server closes c without waiting for
// the handshake timeout: a refused connection.
func closedQuickly(t *testing.T, c net.Conn) bool {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func TestPendingHandshakesCapped(t *testing.T) {
	_, pin := linkIdentity(t, "realm")
	ls := listen(t, []string{pin}, proxy.ListenerConfig{MaxPending: 2, HandshakeTimeout: 10 * time.Second})
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ls.addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, c)
	}
	// The two held connections fill the pending slots; give the accept
	// loop a moment to take them, polling until the third is refused.
	deadline := time.Now().Add(rpt.Timeout)
	for {
		c, err := net.Dial("tcp", ls.addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		refused := closedQuickly(t, c)
		c.Close()
		if refused {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a third pending handshake was accepted with MaxPending 2")
		}
	}
	for i, c := range held {
		if closedQuickly(t, c) {
			t.Fatalf("held connection %d was closed; the cap should refuse only new ones", i)
		}
	}
}

func TestPerSourceRateLimit(t *testing.T) {
	_, pin := linkIdentity(t, "realm")
	ls := listen(t, []string{pin}, proxy.ListenerConfig{PerSourcePerMinute: 2, HandshakeTimeout: 10 * time.Second})
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			c.Close()
		}
	})
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ls.addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
		if closedQuickly(t, c) {
			t.Fatalf("attempt %d of 2 refused", i+1)
		}
	}
	c, err := net.Dial("tcp", ls.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conns = append(conns, c)
	if !closedQuickly(t, c) {
		t.Fatal("third attempt in a minute from one source was not refused")
	}
}

func TestListenerRefusesNonMTLSConfig(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	id, _ := linkIdentity(t, "gateway")
	for name, conf := range map[string]*tls.Config{
		"no TLS":             nil,
		"no client certs":    {Certificates: []tls.Certificate{id}, MinVersion: tls.VersionTLS13},
		"certs, no verifier": {Certificates: []tls.Certificate{id}, ClientAuth: tls.RequireAnyClientCert},
	} {
		if err := h.ServeListener(h.ctx, l, proxy.ListenerConfig{TLS: conf}); err == nil {
			t.Errorf("ServeListener(%s) = nil, want a refusal", name)
		}
	}
}

// A realm whose certificate is not pinned never registers, even if it
// presents a well-formed hello for a real realm id.
func TestUntrustedRealmNeverRegisters(t *testing.T) {
	_, pinnedPin := linkIdentity(t, "the realm we expect")
	stranger, _ := linkIdentity(t, "stranger")
	ls := listen(t, []string{pinnedPin}, proxy.ListenerConfig{})
	conf, _ := realmproto.ClientTLS(stranger, realmproto.Trust{Pins: []string{ls.gwPin}}, "gateway")
	attempt := make(chan error, 1)
	go func() {
		c, err := realm.TLSDialer(ls.addr, conf, time.Second)(context.Background())
		if err != nil {
			attempt <- err
			return
		}
		// TLS 1.3 lets the client finish first; the refusal then arrives
		// when Serve reads the reply to its hello.
		attempt <- realm.Serve(context.Background(), c, realm.Config{ID: "live", Handler: echo.Handler{}, Log: quiet})
	}()
	select {
	case err := <-attempt:
		if err == nil {
			t.Fatal("an unpinned realm's link ended cleanly; want it refused")
		}
	case <-time.After(rpt.Timeout):
		t.Fatal("an unpinned realm's attempt was neither refused nor ended")
	}
	// The attempt has failed on the realm's side, which happens only after
	// the gateway refused it: now the absence is meaningful.
	if got := ls.Realms(); len(got) != 0 {
		t.Fatalf("realms after an untrusted connection = %+v, want none", got)
	}
}
