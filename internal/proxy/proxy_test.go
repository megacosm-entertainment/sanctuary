package proxy_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/proxy"
	"sanctuary/internal/realmproto"
	rpt "sanctuary/internal/realmproto/realmprototest"
	"sanctuary/internal/session"
	"sanctuary/internal/session/sessiontest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// hub is a Hub with links served in the background.
type hub struct {
	*proxy.Hub
	ctx    context.Context
	cancel context.CancelFunc
}

func newHub(t *testing.T, cfg proxy.HubConfig) *hub {
	t.Helper()
	cfg.Log = quiet
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &hub{Hub: proxy.NewHub(cfg), ctx: ctx, cancel: cancel}
}

// connect starts serving a new link and returns the fake realm's end, plus
// a channel with Serve's result.
func (h *hub) connect(t *testing.T) (*rpt.Peer, <-chan error) {
	t.Helper()
	realm, gwEnd := rpt.NewRealm(t)
	done := make(chan error, 1)
	go func() { done <- h.Serve(h.ctx, gwEnd) }()
	return realm, done
}

// register connects a fake realm and completes its handshake.
func (h *hub) register(t *testing.T, id string) *rpt.Peer {
	t.Helper()
	realm, _ := h.connect(t)
	realm.Send(&realmproto.Hello{Versions: []int{realmproto.Version}, Realm: id, Name: "Realm " + id, Build: "test"})
	if w := rpt.Expect[*realmproto.Welcome](realm); w.Version != realmproto.Version {
		t.Fatalf("welcome = %+v, want version %d", w, realmproto.Version)
	}
	return realm
}

func waitErr(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(rpt.Timeout):
		t.Fatal("Serve still running")
	}
	return nil
}

// player connects an in-memory player through the proxy handler and
// returns it with the session.open the realm received for it.
func player(t *testing.T, h *hub, realm *rpt.Peer, handler proxy.Handler) (*sessiontest.Harness, *realmproto.SessionOpen) {
	t.Helper()
	if handler.Hub == nil {
		handler.Hub = h.Hub
	}
	p := sessiontest.New(t, handler)
	open := rpt.Expect[*realmproto.SessionOpen](realm)
	if open.Session != p.Session.ID {
		t.Fatalf("session.open for %d, want the player's session %d", open.Session, p.Session.ID)
	}
	return p, open
}

// ── Handshake (protocol.md §4) ───────────────────────────────

func TestRealmRegisters(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	h.register(t, "live")
	got := h.Realms()
	if len(got) != 1 || got[0].ID != "live" || got[0].Name != "Realm live" {
		t.Fatalf("Realms() = %+v, want the one registered realm", got)
	}
}

func TestHandshakeRejects(t *testing.T) {
	cases := []struct {
		name   string
		hello  string // raw first frame
		reason string
	}{
		{"unsupported version", `{"type":"hello","versions":[99],"realm":"live"}`, realmproto.RejectUnsupportedVersion},
		{"invalid realm id", `{"type":"hello","versions":[1],"realm":"Live Realm"}`, realmproto.RejectBadHello},
		{"not a hello", `{"type":"pong","n":1}`, realmproto.RejectBadHello},
		// A realm may not send gateway-only messages, even first.
		{"gateway-only message", `{"type":"welcome","version":1}`, realmproto.RejectBadHello},
		{"not JSON", `hello`, realmproto.RejectBadHello},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHub(t, proxy.HubConfig{})
			realm, done := h.connect(t)
			if err := realm.Conn.SendRaw([]byte(c.hello)); err != nil {
				t.Fatalf("SendRaw: %v", err)
			}
			if rej := rpt.Expect[*realmproto.Reject](realm); rej.Reason != c.reason {
				t.Fatalf("reject reason = %q, want %q", rej.Reason, c.reason)
			}
			if err := waitErr(t, done); err == nil {
				t.Fatal("Serve after a reject = nil, want an error")
			}
			if n := len(h.Realms()); n != 0 {
				t.Fatalf("%d realms registered after a reject", n)
			}
		})
	}
}

func TestUnsupportedVersionRejectListsOurs(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm, _ := h.connect(t)
	realm.Send(&realmproto.Hello{Versions: []int{2, 3}, Realm: "live"})
	rej := rpt.Expect[*realmproto.Reject](realm)
	if len(rej.Versions) != 1 || rej.Versions[0] != realmproto.Version {
		t.Fatalf("reject versions = %v, want [%d] so the realm can tell why", rej.Versions, realmproto.Version)
	}
}

func TestDuplicateRealmRejected(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	h.register(t, "live")
	second, _ := h.connect(t)
	second.Send(&realmproto.Hello{Versions: []int{realmproto.Version}, Realm: "live"})
	if rej := rpt.Expect[*realmproto.Reject](second); rej.Reason != realmproto.RejectDuplicateRealm {
		t.Fatalf("second live realm: reject %q, want %q", rej.Reason, realmproto.RejectDuplicateRealm)
	}
}

func TestRealmCap(t *testing.T) {
	h := newHub(t, proxy.HubConfig{MaxRealms: 1})
	h.register(t, "a")
	second, _ := h.connect(t)
	second.Send(&realmproto.Hello{Versions: []int{realmproto.Version}, Realm: "b"})
	if rej := rpt.Expect[*realmproto.Reject](second); rej.Reason != realmproto.RejectTooManyRealms {
		t.Fatalf("realm over the cap: reject %q, want %q", rej.Reason, realmproto.RejectTooManyRealms)
	}
}

// A connection that never says hello must not hold a slot forever.
func TestHelloTimeout(t *testing.T) {
	h := newHub(t, proxy.HubConfig{HandshakeTimeout: 50 * time.Millisecond})
	_, done := h.connect(t)
	if err := waitErr(t, done); err == nil || !strings.Contains(err.Error(), "waiting for hello") {
		t.Fatalf("Serve = %v, want a hello timeout", err)
	}
}

// ── Relaying (protocol.md §5) ────────────────────────────────

func TestPlayerRoutedToRealm(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, open := player(t, h, realm, proxy.Handler{})
	if open.Transport != "mem" || !open.Secure {
		t.Fatalf("session.open = %+v, want transport mem, secure", open)
	}

	realm.Send(&realmproto.Text{Session: open.Session, Text: "Welcome.\n"})
	realm.Send(&realmproto.Prompt{Session: open.Session, Text: "> "})
	if out, pr := p.UntilPrompt(); out != "Welcome.\n" || pr.Text != "> " {
		t.Fatalf("player saw %q, prompt %q", out, pr.Text)
	}

	p.Type("look")
	if in := rpt.Expect[*realmproto.Input](realm); in.Session != open.Session || in.Text != "look" {
		t.Fatalf("realm got %+v, want input \"look\" for session %d", in, open.Session)
	}
}

func TestInputModeAndGMCPRelayed(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, open := player(t, h, realm, proxy.Handler{})

	realm.Send(&realmproto.InputMode{Session: open.Session, Hidden: true})
	if m := sessiontest.ExpectNext[session.InputMode](p); !m.Hidden {
		t.Fatalf("player got %+v, want hidden input", m)
	}
	realm.Send(&realmproto.GMCP{Session: open.Session, Package: "Char.Vitals", Data: []byte(`{"hp":3}`)})
	if g := sessiontest.ExpectNext[session.GMCPOut](p); g.Package != "Char.Vitals" || string(g.Data) != `{"hp":3}` {
		t.Fatalf("player got %+v, want Char.Vitals {\"hp\":3}", g)
	}
	p.Send(session.GMCP{Package: "Core.Hello", Data: []byte(`{"client":"x"}`)})
	if g := rpt.Expect[*realmproto.GMCP](realm); g.Package != "Core.Hello" || string(g.Data) != `{"client":"x"}` {
		t.Fatalf("realm got %+v, want the player's Core.Hello", g)
	}
	p.Send(session.ClientUpdate{Info: session.ClientInfo{Name: "mudlet", Width: 90, Height: 30}})
	if c := rpt.Expect[*realmproto.Client](realm); c.Client.Name != "mudlet" || c.Client.Width != 90 {
		t.Fatalf("realm got %+v, want the client update", c)
	}
}

// The gateway cleans realm output again (protocol.md §5): colour survives,
// anything that could take over the terminal does not.
func TestRealmOutputSanitised(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, open := player(t, h, realm, proxy.Handler{})
	realm.Send(&realmproto.Text{Session: open.Session, Text: "\x1b]0;pwned\x07\x1b[31mred\x1b[0m \x1b[2Jdone\n"})
	if txt := sessiontest.ExpectNext[session.Text](p); txt.Text != "\x1b[31mred\x1b[0m done\n" {
		t.Fatalf("player got %q, want colour kept and title/clear removed", txt.Text)
	}
}

func TestRealmClosesPlayerAfterOutput(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, open := player(t, h, realm, proxy.Handler{})
	realm.Send(&realmproto.Text{Session: open.Session, Text: "Goodbye.\n"})
	realm.Send(&realmproto.SessionClose{Session: open.Session})
	if txt := sessiontest.ExpectNext[session.Text](p); txt.Text != "Goodbye.\n" {
		t.Fatalf("player got %q before close, want the goodbye", txt.Text)
	}
	p.ExpectClosed()
}

func TestPlayerDisconnectTellsRealm(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, open := player(t, h, realm, proxy.Handler{})
	p.Client.Hangup()
	c := rpt.Expect[*realmproto.SessionClosed](realm)
	if c.Session != open.Session || c.Reason != realmproto.ClosedDisconnected {
		t.Fatalf("realm got %+v, want session.closed disconnected for %d", c, open.Session)
	}
}

func TestOutputForUnknownSessionDropped(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	realm.Send(&realmproto.Text{Session: 424242, Text: "nobody\n"})
	realm.Send(&realmproto.Ping{N: 1})
	if p := rpt.Expect[*realmproto.Pong](realm); p.N != 1 {
		t.Fatalf("pong = %+v, want N 1: the link must survive output for a gone session", p)
	}
}

// ── Choosing a realm ─────────────────────────────────────────

func TestPlayerWaitsForRealm(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	p := sessiontest.New(t, proxy.Handler{Hub: h.Hub, Wait: rpt.Timeout})
	p.ExpectText("Connecting you to a realm")
	realm := h.register(t, "live")
	if open := rpt.Expect[*realmproto.SessionOpen](realm); open.Session != p.Session.ID {
		t.Fatalf("session.open for %d, want the waiting player %d", open.Session, p.Session.ID)
	}
}

func TestNoRealmAvailable(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	p := sessiontest.New(t, proxy.Handler{Hub: h.Hub, Wait: 50 * time.Millisecond})
	p.ExpectText("No realm is available")
	p.ExpectClosed()
}

func TestNamedRealmChosen(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	a := h.register(t, "a")
	b := h.register(t, "b")
	sessiontest.New(t, proxy.Handler{Hub: h.Hub, Realm: "b"})
	rpt.Expect[*realmproto.SessionOpen](b)
	a.Send(&realmproto.Ping{N: 1})
	if p := rpt.Expect[*realmproto.Pong](a); p.N != 1 {
		t.Fatal("realm a received something other than its pong")
	}
}

func TestDrainingRealmGetsNoNewPlayers(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	realm.Send(&realmproto.Drain{DeadlineMS: 1000})
	realm.Send(&realmproto.Ping{N: 1})
	rpt.Expect[*realmproto.Pong](realm) // the drain has been processed
	p := sessiontest.New(t, proxy.Handler{Hub: h.Hub, Wait: 50 * time.Millisecond})
	p.ExpectText("No realm is available")
}

// ── Failure and shutdown ─────────────────────────────────────

func TestRealmLossTellsPlayers(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, _ := player(t, h, realm, proxy.Handler{})
	realm.Conn.Close()
	p.ExpectText("realm has gone away")
	p.ExpectClosed()
	if n := len(h.Realms()); n != 0 {
		t.Fatalf("%d realms still registered after the link was lost", n)
	}
}

func TestGatewayShutdownTellsRealmAndPlayers(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, _ := player(t, h, realm, proxy.Handler{})
	h.cancel()
	p.Shutdown() // the gateway cancels every handler's context too
	p.ExpectText("gateway is shutting down")
	rpt.Until[*realmproto.Shutdown](realm, nil)
}

// ── Isolation: the bottlenecks that must not exist ───────────

// stalledRealm registers a realm whose end of the link is never read after
// the handshake.
func stalledRealm(t *testing.T, h *hub, id string) {
	t.Helper()
	gw, realm := realmproto.Pipe()
	t.Cleanup(func() { gw.Close(); realm.Close() })
	go h.Serve(h.ctx, gw)
	if err := realm.Send(&realmproto.Hello{Versions: []int{realmproto.Version}, Realm: id}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	if _, err := realm.Recv(); err != nil {
		t.Fatalf("welcome: %v", err)
	}
	// From here, nothing on realm is read.
}

// A realm that stops reading must not delay another realm's players: their
// output and input keep flowing at once.
func TestStalledRealmDoesNotAffectOtherRealms(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	stalledRealm(t, h, "a")
	stuck := sessiontest.New(t, proxy.Handler{Hub: h.Hub, Realm: "a"})
	for i := 0; i < 50; i++ {
		stuck.Type("into the void")
	}

	b := h.register(t, "b")
	p, open := player(t, h, b, proxy.Handler{Realm: "b"})
	start := time.Now()
	b.Send(&realmproto.Text{Session: open.Session, Text: "still here\n"})
	if txt := sessiontest.ExpectNext[session.Text](p); txt.Text != "still here\n" {
		t.Fatalf("player on b got %q", txt.Text)
	}
	p.Type("ping")
	rpt.Expect[*realmproto.Input](b)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("round trip on realm b took %v while realm a was stalled", d)
	}
}

// One player flooding input at a realm that is slow to read is
// disconnected alone; the realm and its other players are unaffected.
func TestInputFloodDisconnectsOnlyThatPlayer(t *testing.T) {
	h := newHub(t, proxy.HubConfig{Writer: realmproto.WriterLimits{SessionBytes: 2048, LinkBytes: 1 << 20}})
	stalledRealm(t, h, "slow")
	flooder := sessiontest.New(t, proxy.Handler{Hub: h.Hub, Realm: "slow"})
	other := sessiontest.New(t, proxy.Handler{Hub: h.Hub, Realm: "slow"})
	line := strings.Repeat("x", 500)
	for i := 0; i < 20; i++ {
		if err := flooder.Client.Send(session.Line{Text: line}); err != nil {
			break // the session has been closed for overflow
		}
	}
	flooder.ExpectClosed()
	select {
	case <-other.Session.Done():
		t.Fatalf("the other player was disconnected too (%v)", other.Session.Err())
	default:
	}
	if got := h.Realms(); len(got) != 1 {
		t.Fatalf("realms after one player's flood = %+v, want the realm still registered", got)
	}
}

// A realm that stops reading entirely is dropped once its queue fills, so
// its players are told rather than left hanging.
func TestStuckRealmIsDropped(t *testing.T) {
	h := newHub(t, proxy.HubConfig{Writer: realmproto.WriterLimits{SessionBytes: 1 << 20, LinkBytes: 8192}})
	stalledRealm(t, h, "stuck")
	p := sessiontest.New(t, proxy.Handler{Hub: h.Hub, Realm: "stuck"})
	line := strings.Repeat("x", 500)
	for i := 0; i < 40; i++ {
		if errors.Is(p.Client.Send(session.Line{Text: line}), session.ErrClosed) {
			break
		}
	}
	p.ExpectText("realm has gone away")
	p.ExpectClosed()
}

// The gateway's link reader must keep reading from a realm that has
// stopped reading its own end: pongs are queued, never written inline, and
// once the queue fills the gateway drops the link instead of hanging.
func TestStalledRealmDoesNotBlockGatewayReader(t *testing.T) {
	h := newHub(t, proxy.HubConfig{Writer: realmproto.WriterLimits{LinkBytes: 4096, WriteTimeout: time.Minute}})
	gw, realm := realmproto.Pipe()
	t.Cleanup(func() { gw.Close(); realm.Close() })
	done := make(chan error, 1)
	go func() { done <- h.Serve(h.ctx, gw) }()
	if err := realm.Send(&realmproto.Hello{Versions: []int{realmproto.Version}, Realm: "deaf"}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	if _, err := realm.Recv(); err != nil {
		t.Fatalf("welcome: %v", err)
	}
	// The realm now only writes. Each Send blocks until the gateway's
	// reader takes the frame, so a blocked reader shows up as a stuck Send.
	go func() {
		for i := uint64(1); ; i++ {
			if realm.Send(&realmproto.Ping{N: i}) != nil {
				return
			}
		}
	}()
	select {
	case err := <-done:
		if !errors.Is(err, realmproto.ErrStalled) {
			t.Fatalf("Serve = %v, want ErrStalled once the queue to the realm filled", err)
		}
	case <-time.After(rpt.Timeout):
		t.Fatal("gateway neither kept reading nor dropped a realm that stopped reading")
	}
}
