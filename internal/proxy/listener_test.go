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
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return c, realmproto.Pin(leaf)
}

// listening is a hub serving a real loopback realm port.
type listening struct {
	*hub
	addr  string
	gwPin string
	done  chan error
}

// listen serves a realm port trusting the given id=pin bindings (and
// lc.CAs, if set).
func listen(t *testing.T, bindings []string, lc proxy.ListenerConfig) *listening {
	t.Helper()
	h := newHub(t, proxy.HubConfig{})
	gwID, gwPin := linkIdentity(t, "gateway")
	bound, err := realmproto.ParseRealmPins(bindings)
	if err != nil {
		t.Fatalf("ParseRealmPins: %v", err)
	}
	conf, err := realmproto.ServerTLS(gwID, realmproto.Trust{Pins: bound.Pins(), CAs: lc.CAs})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	lc.TLS, lc.Realms = conf, bound
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
	ls := listen(t, []string{"live=" + realmPin}, proxy.ListenerConfig{})
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
	ls := listen(t, []string{"live=" + pin}, proxy.ListenerConfig{HandshakeTimeout: 100 * time.Millisecond})
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
	ls := listen(t, []string{"live=" + pin}, proxy.ListenerConfig{MaxPending: 2, HandshakeTimeout: 10 * time.Second})
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
	ls := listen(t, []string{"live=" + pin}, proxy.ListenerConfig{PerSourcePerMinute: 2, HandshakeTimeout: 10 * time.Second})
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
	ls := listen(t, []string{"live=" + pinnedPin}, proxy.ListenerConfig{})
	conf, err := realmproto.ClientTLS(stranger, realmproto.Trust{Pins: []string{ls.gwPin}}, "gateway")
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
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

// ── Realm ids are bound to keys (RT-3-1) ─────────────────────

// dialAs dials the realm port with identity id, sends a hello for realmID,
// and returns the link and the gateway's answer (welcome or reject).
func dialAs(t *testing.T, ls *listening, id tls.Certificate, realmID string) (*realmproto.Conn, realmproto.Message) {
	t.Helper()
	conf, err := realmproto.ClientTLS(id, realmproto.Trust{Pins: []string{ls.gwPin}}, "gateway")
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
	c, err := realm.TLSDialer(ls.addr, conf, rpt.Timeout)(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Send(&realmproto.Hello{Versions: []int{realmproto.Version}, Realm: realmID}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(rpt.Timeout))
	m, err := c.Recv()
	if err != nil {
		t.Fatalf("waiting for the gateway's answer: %v", err)
	}
	return c, m
}

// Two trusted keys, live's and staging's. While live is down with players
// held for it, staging's key claims to be live: it must be refused, or it
// would be handed live's players and what they type next.
func TestRealmCannotRegisterAsAnotherRealm(t *testing.T) {
	liveID, livePin := linkIdentity(t, "live realm")
	stagingID, stagingPin := linkIdentity(t, "staging realm")
	ls := listen(t, []string{"live=" + livePin, "staging=" + stagingPin}, proxy.ListenerConfig{})

	live, ans := dialAs(t, ls, liveID, "live")
	if _, ok := ans.(*realmproto.Welcome); !ok {
		t.Fatalf("live's own key registering as live got %+v, want welcome", ans)
	}
	p := sessiontest.New(t, proxy.Handler{Hub: ls.Hub, Realm: "live", Hold: rpt.Timeout})
	gw := rpt.Start(t, live)
	rpt.Expect[*realmproto.SessionOpen](gw)
	live.Close() // live goes down; its player is held
	p.ExpectText("unavailable for the moment")

	_, ans = dialAs(t, ls, stagingID, "live")
	rej, ok := ans.(*realmproto.Reject)
	if !ok || rej.Reason != realmproto.RejectNotAllowed {
		t.Fatalf("staging's key registering as live got %+v, want reject %q", ans, realmproto.RejectNotAllowed)
	}
	if got := ls.Realms(); len(got) != 0 {
		t.Fatalf("realms after the refused claim = %+v, want none", got)
	}
	// Staging's key can still be staging.
	if _, ans := dialAs(t, ls, stagingID, "staging"); !isWelcome(ans) {
		t.Fatalf("staging's key registering as staging got %+v, want welcome", ans)
	}
}

func isWelcome(m realmproto.Message) bool { _, ok := m.(*realmproto.Welcome); return ok }

// A bare pin, with no realm named, is refused when the gateway starts.
func TestUnboundPinRefused(t *testing.T) {
	_, pin := linkIdentity(t, "realm")
	if _, err := realmproto.ParseRealmPins([]string{pin}); err == nil {
		t.Fatal("ParseRealmPins accepted a pin with no realm id")
	}
	for _, bad := range []string{"Live=" + pin, "a b=" + pin, "=" + pin, "live=sha256/short"} {
		if _, err := realmproto.ParseRealmPins([]string{bad}); err == nil {
			t.Errorf("ParseRealmPins(%q) accepted", bad)
		}
	}
}

func TestListenerRefusesNoBindings(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	gwID, _ := linkIdentity(t, "gateway")
	_, pin := linkIdentity(t, "realm")
	conf, err := realmproto.ServerTLS(gwID, realmproto.Trust{Pins: []string{pin}})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := h.ServeListener(h.ctx, l, proxy.ListenerConfig{TLS: conf}); err == nil {
		t.Fatal("ServeListener with trust but no realm bindings = nil, want a refusal")
	}
}
