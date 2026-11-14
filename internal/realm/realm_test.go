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
