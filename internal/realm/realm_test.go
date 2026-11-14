package realm_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/echo"
	"sanctuary/internal/realm"
	"sanctuary/internal/realmproto"
	rpt "sanctuary/internal/realmproto/realmprototest"
	"sanctuary/internal/session"
)

const banner = "Stub realm.\n"

func intp(n int) *int { return &n }

// served is a realm running against a fake gateway.
type served struct {
	gw     *rpt.Peer
	cancel context.CancelFunc
	done   chan error
}

func serve(t *testing.T, mod ...func(*realm.Config)) *served {
	t.Helper()
	gw, conn := rpt.NewGateway(t)
	cfg := realm.Config{
		ID: "live", Name: "Test Realm", Build: "test",
		Handler: echo.Handler{Banner: banner},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, m := range mod {
		m(&cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &served{gw: gw, cancel: cancel, done: make(chan error, 1)}
	go func() { s.done <- realm.Serve(ctx, conn, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(rpt.Timeout):
			t.Error("Serve did not return after cancel")
		}
	})
	return s
}

// registered is serve plus a completed handshake.
func registered(t *testing.T, mod ...func(*realm.Config)) *served {
	t.Helper()
	s := serve(t, mod...)
	s.gw.Handshake()
	return s
}

func (s *served) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-s.done:
		s.done <- err // keep it for Cleanup
		return err
	case <-time.After(rpt.Timeout):
		t.Fatal("Serve still running")
	}
	return nil
}

// open routes a player to the realm and reads past the banner.
func (s *served) open(t *testing.T, id uint64, client realmproto.ClientInfo) {
	t.Helper()
	s.gw.Send(&realmproto.SessionOpen{Session: id, Transport: "telnet", Client: client})
	out, p := s.gw.TextFor(id)
	if out != banner || p.Text != "> " {
		t.Fatalf("session %d opened with %q, prompt %q; want banner %q and \"> \"", id, out, p.Text, banner)
	}
}

func (s *served) say(id uint64, text string) {
	s.gw.Send(&realmproto.Input{Session: id, Text: text})
}

// sync proves the realm has processed everything sent before it: the
// realm answers pings from its link reader, in order.
func (s *served) sync(t *testing.T) {
	t.Helper()
	s.gw.Send(&realmproto.Ping{N: 99})
	if p := rpt.Expect[*realmproto.Pong](s.gw); p.N != 99 {
		t.Fatalf("pong N = %d, want 99", p.N)
	}
}

// ── Handshake (protocol.md §4) ───────────────────────────────

func TestHelloDescribesRealm(t *testing.T) {
	s := serve(t, func(c *realm.Config) { c.Fingerprint = "sha256:abc" })
	h := rpt.Expect[*realmproto.Hello](s.gw)
	if h.Realm != "live" || h.Name != "Test Realm" || h.Build != "test" || h.Fingerprint != "sha256:abc" {
		t.Fatalf("hello = %+v, want the configured realm identity", h)
	}
	if len(h.Versions) != 1 || h.Versions[0] != realmproto.Version {
		t.Fatalf("hello versions = %v, want [%d]", h.Versions, realmproto.Version)
	}
}

func TestRejectEndsServe(t *testing.T) {
	s := serve(t)
	rpt.Expect[*realmproto.Hello](s.gw)
	s.gw.Send(&realmproto.Reject{Reason: realmproto.RejectDuplicateRealm})
	var rej *realm.RejectedError
	if err := s.wait(t); !errors.As(err, &rej) || rej.Reason != realmproto.RejectDuplicateRealm {
		t.Fatalf("Serve = %v, want RejectedError{%s}", err, realmproto.RejectDuplicateRealm)
	}
}

func TestNoWelcomeTimesOut(t *testing.T) {
	s := serve(t, func(c *realm.Config) { c.HandshakeTimeout = 50 * time.Millisecond })
	rpt.Expect[*realmproto.Hello](s.gw)
	if err := s.wait(t); err == nil || !strings.Contains(err.Error(), "waiting for welcome") {
		t.Fatalf("Serve = %v, want a welcome timeout", err)
	}
}

func TestWelcomeForOtherVersionIsProtocolError(t *testing.T) {
	s := serve(t)
	rpt.Expect[*realmproto.Hello](s.gw)
	s.gw.Send(&realmproto.Welcome{Version: realmproto.Version + 1})
	if err := s.wait(t); !errors.Is(err, realm.ErrProtocol) {
		t.Fatalf("Serve = %v, want ErrProtocol", err)
	}
}

func TestMessageBeforeWelcomeIsProtocolError(t *testing.T) {
	s := serve(t)
	rpt.Expect[*realmproto.Hello](s.gw)
	s.gw.Send(&realmproto.Ping{N: 1})
	if err := s.wait(t); !errors.Is(err, realm.ErrProtocol) {
		t.Fatalf("Serve = %v, want ErrProtocol", err)
	}
}

// ── Sessions (protocol.md §5) ────────────────────────────────

func TestInputReachesHandlerAndOutputComesBack(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{})
	s.say(1, "hello")
	if out, _ := s.gw.TextFor(1); out != "You said: hello\n" {
		t.Fatalf("output = %q, want %q", out, "You said: hello\n")
	}
}

// The handler sees the client as the gateway described it at open time and
// as later Client messages update it.
func TestClientInfoReachesHandler(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{Name: "mushclient", Terminal: "ANSI", MTTS: intp(13), Charset: "UTF-8", Width: 80, Height: 26})
	s.say(1, "/info")
	out, _ := s.gw.TextFor(1)
	for _, want := range []string{"mushclient", "MTTS:          13", "80 x 26", "Transport:     telnet"} {
		if !strings.Contains(out, want) {
			t.Errorf("/info missing %q:\n%s", want, out)
		}
	}
	s.gw.Send(&realmproto.Client{Session: 1, Client: realmproto.ClientInfo{Name: "mushclient", Width: 120, Height: 40}})
	s.say(1, "/info")
	if out, _ := s.gw.TextFor(1); !strings.Contains(out, "120 x 40") {
		t.Errorf("/info after a Client update:\n%s\nwant the new window size 120 x 40", out)
	}
}

func TestHiddenInputUsesInputMode(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{})
	s.say(1, "/secret")
	if m := rpt.Expect[*realmproto.InputMode](s.gw); !m.Hidden || m.Session != 1 {
		t.Fatalf("input.mode = %+v, want hidden for session 1", m)
	}
	s.gw.TextFor(1) // "Secret: " prompt
	s.say(1, "hunter2")
	if m := rpt.Expect[*realmproto.InputMode](s.gw); m.Hidden {
		t.Fatalf("input.mode after the secret = %+v, want echo restored", m)
	}
	if out, _ := s.gw.TextFor(1); strings.Contains(out, "hunter2") {
		t.Fatalf("hidden input echoed: %q", out)
	}
}

// When the realm ends a player, its last output is sent before it asks the
// gateway to disconnect them.
func TestQuitSendsOutputThenSessionClose(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{})
	s.say(1, "/quit")
	if m := rpt.Expect[*realmproto.Text](s.gw); m.Text != "Goodbye.\n" {
		t.Fatalf("first message after /quit = %+v, want Goodbye", m)
	}
	if c := rpt.Expect[*realmproto.SessionClose](s.gw); c.Session != 1 {
		t.Fatalf("session.close = %+v, want session 1", c)
	}
}

// After the gateway says a player is gone, the realm sends nothing more for
// them and ignores late input: a normal race, not an error.
func TestGatewayCloseEndsPlayerQuietly(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{})
	s.gw.Send(&realmproto.SessionClosed{Session: 1, Reason: realmproto.ClosedQuit})
	s.say(1, "too late")
	s.sync(t) // the pong must come before any output or session.close
}

func TestSessionsAreIndependent(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{})
	s.open(t, 2, realmproto.ClientInfo{})
	s.say(2, "two")
	if out, _ := s.gw.TextFor(2); out != "You said: two\n" {
		t.Fatalf("session 2 output = %q", out)
	}
	s.say(1, "one")
	if out, _ := s.gw.TextFor(1); out != "You said: one\n" {
		t.Fatalf("session 1 output = %q", out)
	}
}

func TestDuplicateOpenIsProtocolError(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{})
	s.gw.Send(&realmproto.SessionOpen{Session: 1, Transport: "telnet"})
	if err := s.wait(t); !errors.Is(err, realm.ErrProtocol) {
		t.Fatalf("Serve = %v, want ErrProtocol for a reused session id", err)
	}
}

// stall is a handler that never reads input, so a player's backlog fills.
type stall struct{}

func (stall) ServeSession(ctx context.Context, s *session.Session) {
	select {
	case <-ctx.Done():
	case <-s.Done():
	}
}

// One player flooding input must not stall the link for everyone else: past
// InputBuffer they are disconnected with reason overflow.
func TestInputBacklogDisconnectsOnlyThatPlayer(t *testing.T) {
	const buffer = 4
	s := registered(t, func(c *realm.Config) {
		c.Handler = stall{}
		c.InputBuffer = buffer
	})
	s.gw.Send(&realmproto.SessionOpen{Session: 1, Transport: "telnet"})
	// The open-time client update takes one slot, so buffer more lines
	// than fit.
	for i := 0; i <= buffer; i++ {
		s.say(1, "spam")
	}
	c := rpt.Expect[*realmproto.SessionClose](s.gw)
	if c.Session != 1 || c.Reason != realmproto.ClosedOverflow {
		t.Fatalf("session.close = %+v, want session 1 with reason %q", c, realmproto.ClosedOverflow)
	}
	s.sync(t) // the link itself is still serving
}

// ── Link lifecycle (protocol.md §8) ──────────────────────────

func TestPingAnswered(t *testing.T) {
	s := registered(t)
	s.gw.Send(&realmproto.Ping{N: 7})
	if p := rpt.Expect[*realmproto.Pong](s.gw); p.N != 7 {
		t.Fatalf("pong = %+v, want N 7", p)
	}
}

func TestUnknownTypeIgnored(t *testing.T) {
	s := registered(t)
	if err := s.gw.Conn.SendRaw([]byte(`{"type":"future.thing","x":1}`)); err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	s.sync(t)
}

func TestMalformedMessageEndsLink(t *testing.T) {
	s := registered(t)
	if err := s.gw.Conn.SendRaw([]byte(`{"type":"input","session":0}`)); err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	if err := s.wait(t); !errors.Is(err, realmproto.ErrInvalidField) {
		t.Fatalf("Serve = %v, want ErrInvalidField", err)
	}
}

func TestShutdownEndsServeCleanly(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{})
	s.gw.Send(&realmproto.Shutdown{})
	if err := s.wait(t); err != nil {
		t.Fatalf("Serve after shutdown = %v, want nil", err)
	}
}

// Serve returns only after every player handler has ended, so a realm
// process can exit without abandoning a goroutine mid-write.
func TestLinkLossEndsEveryPlayer(t *testing.T) {
	ended := make(chan struct{})
	s := registered(t, func(c *realm.Config) {
		c.Handler = session.HandlerFunc(func(ctx context.Context, sess *session.Session) {
			defer close(ended)
			stall{}.ServeSession(ctx, sess)
		})
	})
	s.gw.Send(&realmproto.SessionOpen{Session: 1, Transport: "telnet"})
	s.sync(t) // the player's handler is running
	s.gw.Conn.Close()
	if err := s.wait(t); err == nil {
		t.Fatal("Serve after link loss = nil, want the link error")
	}
	select {
	case <-ended:
	default:
		t.Fatal("Serve returned while a player handler was still running")
	}
}

func TestCancelEndsServe(t *testing.T) {
	s := registered(t)
	s.cancel()
	if err := s.wait(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve after cancel = %v, want context.Canceled", err)
	}
}

func TestCancelDuringHandshake(t *testing.T) {
	s := serve(t) // default 5s handshake timeout: cancel must not wait for it
	rpt.Expect[*realmproto.Hello](s.gw)
	s.cancel()
	if err := s.wait(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve after cancel during handshake = %v, want context.Canceled", err)
	}
}

// A gateway that stops reading must not freeze the realm's link reader:
// pings keep being accepted (and their pongs queued) until the link-wide
// queue fills, and then the realm gives up on the link instead of hanging.
func TestStalledGatewayDoesNotBlockReader(t *testing.T) {
	gw, conn := realmproto.Pipe() // raw: this gateway stops reading after the handshake
	t.Cleanup(func() { gw.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- realm.Serve(ctx, conn, realm.Config{
			ID: "live", Handler: echo.Handler{Banner: banner},
			Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			Writer: realmproto.WriterLimits{LinkBytes: 4096, WriteTimeout: time.Minute},
		})
	}()
	if _, err := gw.RecvLimit(realmproto.MaxHello); err != nil {
		t.Fatalf("reading hello: %v", err)
	}
	if err := gw.Send(&realmproto.Welcome{Version: realmproto.Version}); err != nil {
		t.Fatalf("sending welcome: %v", err)
	}
	// From here the gateway only writes. Each Send blocks until the realm's
	// reader takes the frame, so a blocked reader shows up as a stuck Send.
	sent := make(chan error, 1)
	go func() {
		for i := uint64(1); ; i++ {
			if err := gw.Send(&realmproto.Ping{N: i}); err != nil {
				sent <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		if !errors.Is(err, realmproto.ErrStalled) {
			t.Fatalf("Serve = %v, want ErrStalled once the queue to the gateway filled", err)
		}
	case <-time.After(rpt.Timeout):
		t.Fatal("realm neither kept reading nor gave up on a stalled gateway")
	}
	select {
	case <-sent: // the realm closed the link, so the writes stopped
	case <-time.After(rpt.Timeout):
		t.Fatal("gateway writes still blocked after the realm closed the link")
	}
}

// One player whose output is not getting out is disconnected alone; the
// realm stays registered.
func TestPlayerOutputBacklogDisconnectsOnlyThatPlayer(t *testing.T) {
	flood := session.HandlerFunc(func(ctx context.Context, s *session.Session) {
		for i := 0; i < 100; i++ {
			s.Send(session.Text{Text: strings.Repeat("x", 1000) + "\n"})
		}
		<-s.Done()
	})
	gw, conn := realmproto.Pipe()
	t.Cleanup(func() { gw.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go realm.Serve(ctx, conn, realm.Config{
		ID: "live", Handler: flood,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Writer: realmproto.WriterLimits{SessionBytes: 8192, LinkBytes: 1 << 20, WriteTimeout: time.Minute},
	})
	if _, err := gw.RecvLimit(realmproto.MaxHello); err != nil {
		t.Fatalf("reading hello: %v", err)
	}
	if err := gw.Send(&realmproto.Welcome{Version: realmproto.Version}); err != nil {
		t.Fatalf("sending welcome: %v", err)
	}
	if err := gw.Send(&realmproto.SessionOpen{Session: 1, Transport: "telnet"}); err != nil {
		t.Fatalf("session.open: %v", err)
	}
	// Now read: some of the flood, then session.close for overflow.
	for {
		m, err := gw.Recv()
		if err != nil {
			t.Fatalf("link ended (%v) before the flooded player was closed", err)
		}
		if c, ok := m.(*realmproto.SessionClose); ok {
			if c.Session != 1 || c.Reason != realmproto.ClosedOverflow {
				t.Fatalf("session.close = %+v, want session 1 with reason overflow", c)
			}
			break
		}
	}
	if err := gw.Send(&realmproto.Ping{N: 5}); err != nil {
		t.Fatalf("ping after overflow: %v", err)
	}
	for {
		m, err := gw.Recv()
		if err != nil {
			t.Fatalf("link ended (%v) after one player overflowed", err)
		}
		if p, ok := m.(*realmproto.Pong); ok && p.N == 5 {
			return
		}
	}
}

// A gateway that goes silent (no pong, nothing) ends the link, so the realm
// can reconnect instead of serving a connection nobody is on.
func TestSilentGatewayEndsLink(t *testing.T) {
	s := registered(t, func(c *realm.Config) {
		c.Keepalive = realmproto.Keepalive{Idle: 30 * time.Millisecond, Grace: 30 * time.Millisecond}
	})
	rpt.Expect[*realmproto.Ping](s.gw) // received, deliberately not answered
	if err := s.wait(t); !errors.Is(err, realmproto.ErrPeerSilent) {
		t.Fatalf("Serve with a silent gateway = %v, want ErrPeerSilent", err)
	}
}

// Run reconnects after the link drops and registers again, so a gateway
// restart (or a network blip) needs no operator action.
func TestRunReconnects(t *testing.T) {
	links := make(chan *rpt.Peer, 4)
	dial := func(ctx context.Context) (*realmproto.Conn, error) {
		gw, conn := rpt.NewGateway(t)
		links <- gw
		return conn, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- realm.Run(ctx, dial, realm.Config{ID: "live", Handler: echo.Handler{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
			realm.Backoff{Min: time.Millisecond, Max: 5 * time.Millisecond})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(rpt.Timeout):
			t.Error("Run did not return after cancel")
		}
	})
	first := <-links
	first.Handshake()
	first.Conn.Close() // the gateway goes away
	select {
	case second := <-links:
		if h := second.Handshake(); h.Realm != "live" {
			t.Fatalf("second hello = %+v, want realm live", h)
		}
	case <-time.After(rpt.Timeout):
		t.Fatal("realm did not reconnect after the link dropped")
	}
}

// A rejection is retried, not fatal: a duplicate-realm rejection is
// usually this realm's own previous link, not yet noticed as dead.
func TestRunRetriesAfterReject(t *testing.T) {
	links := make(chan *rpt.Peer, 4)
	dial := func(ctx context.Context) (*realmproto.Conn, error) {
		gw, conn := rpt.NewGateway(t)
		links <- gw
		return conn, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- realm.Run(ctx, dial, realm.Config{ID: "live", Handler: echo.Handler{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
			realm.Backoff{Min: time.Millisecond, Max: 5 * time.Millisecond})
	}()
	first := <-links
	rpt.Expect[*realmproto.Hello](first)
	first.Send(&realmproto.Reject{Reason: realmproto.RejectDuplicateRealm})
	select {
	case second := <-links:
		second.Handshake()
	case <-time.After(rpt.Timeout):
		t.Fatal("realm gave up after one rejection")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run after cancel = %v, want context.Canceled", err)
		}
	case <-time.After(rpt.Timeout):
		t.Fatal("Run did not return after cancel")
	}
}

// ── Drain (protocol.md §8) ───────────────────────────────────

// SIGTERM in a realm is a drain, not a dropped link: announce it, let each
// player's handler say goodbye, hand each player back for the gateway to
// hold, then send drained and close.
func TestShutdownDrainsInOrder(t *testing.T) {
	s := registered(t)
	s.open(t, 1, realmproto.ClientInfo{})
	s.cancel()
	if d := rpt.Expect[*realmproto.Drain](s.gw); d.DeadlineMS <= 0 {
		t.Fatalf("drain = %+v, want a positive deadline", d)
	}
	if txt := rpt.Expect[*realmproto.Text](s.gw); !strings.Contains(txt.Text, "shutting down") {
		t.Fatalf("after drain the player got %+v, want the realm's goodbye", txt)
	}
	if c := rpt.Expect[*realmproto.SessionClose](s.gw); c.Session != 1 || c.Reason != realmproto.ClosedDrain {
		t.Fatalf("session.close = %+v, want session 1 handed back with reason %q", c, realmproto.ClosedDrain)
	}
	rpt.Expect[*realmproto.Drained](s.gw)
	s.gw.ExpectClosed()
	if err := s.wait(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve after a drain = %v, want context.Canceled", err)
	}
}

// A player arriving while the realm drains is handed straight back.
func TestOpenDuringDrainHandedBack(t *testing.T) {
	hold := make(chan struct{})
	s := registered(t, func(c *realm.Config) {
		c.Handler = session.HandlerFunc(func(ctx context.Context, sess *session.Session) {
			<-hold // keep the drain waiting on this player
		})
	})
	t.Cleanup(func() { close(hold) })
	s.gw.Send(&realmproto.SessionOpen{Session: 1, Transport: "telnet"})
	s.sync(t)
	s.cancel()
	rpt.Expect[*realmproto.Drain](s.gw)
	s.gw.Send(&realmproto.SessionOpen{Session: 2, Transport: "telnet"})
	c := rpt.Until[*realmproto.SessionClose](s.gw, func(c *realmproto.SessionClose) bool { return c.Session == 2 })
	if c.Reason != realmproto.ClosedDrain {
		t.Fatalf("session.close for a player opened mid-drain = %+v, want reason %q", c, realmproto.ClosedDrain)
	}
}

// A handler that ignores shutdown cannot hold the realm past its deadline:
// remaining players are handed back and the link closes anyway.
func TestDrainDeadline(t *testing.T) {
	const deadline = 100 * time.Millisecond
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	s := registered(t, func(c *realm.Config) {
		c.DrainTimeout = deadline
		c.Handler = session.HandlerFunc(func(ctx context.Context, sess *session.Session) {
			select { // ignores ctx: only the transport closing ends it
			case <-sess.Done():
			case <-block:
			}
		})
	})
	s.gw.Send(&realmproto.SessionOpen{Session: 1, Transport: "telnet"})
	s.sync(t)
	start := time.Now()
	s.cancel()
	rpt.Expect[*realmproto.Drain](s.gw)
	if c := rpt.Expect[*realmproto.SessionClose](s.gw); c.Session != 1 || c.Reason != realmproto.ClosedDrain {
		t.Fatalf("session.close = %+v, want session 1 handed back at the deadline", c)
	}
	rpt.Expect[*realmproto.Drained](s.gw)
	if d := time.Since(start); d < deadline || d > deadline+time.Second {
		t.Fatalf("drained after %v, want about the %v deadline", d, deadline)
	}
}

// One oversize message from a handler is dropped; the link and the player
// stay up (RT-3-7: without Encode's limit the writer would fail and close
// the link for every player).
func TestOversizeOutputDroppedNotFatal(t *testing.T) {
	s := registered(t, func(c *realm.Config) {
		c.Policy = session.QueuePolicy{MaxBytes: 1 << 20, MaxMessages: 64, GMCPSoftBytes: 1 << 10, DrainTimeout: time.Second}
		c.Handler = session.HandlerFunc(func(ctx context.Context, sess *session.Session) {
			sess.Send(session.Text{Text: strings.Repeat("x", realmproto.MaxFrame) + "\n"})
			sess.Send(session.Text{Text: "after\n"})
			select {
			case <-ctx.Done():
			case <-sess.Done():
			}
		})
	})
	s.gw.Send(&realmproto.SessionOpen{Session: 1, Transport: "telnet"})
	if txt := rpt.Expect[*realmproto.Text](s.gw); txt.Text != "after\n" {
		t.Fatalf("first output = %d bytes, want the oversize message dropped and \"after\" delivered", len(txt.Text))
	}
	s.sync(t) // the link is still up
}
