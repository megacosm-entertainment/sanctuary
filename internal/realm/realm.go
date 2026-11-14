// Package realm is the realm's side of a realm link (docs/protocol.md): it
// performs the handshake, then presents each player the gateway routes here
// as a session.Transport, so ordinary session.Handlers run behind the
// protocol with the same queues and overflow policy as in the gateway.
//
// The stage-02 stub realm uses this with the echo handler. A full world
// server will drive players from its tick loop instead of a goroutine per
// player, but it keeps this package's link handling.
package realm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"sanctuary/internal/realmproto"
	"sanctuary/internal/session"
)

// Config describes the realm and how it serves players.
type Config struct {
	ID          string // realm id: 1-32 of [a-z0-9-]
	Name        string // shown in the gateway's realm list
	Build       string
	Fingerprint string // ruleset fingerprint (design §06); may be empty in stage 02

	Handler session.Handler
	Policy  session.QueuePolicy // zero means session.DefaultPolicy
	Log     *slog.Logger

	// Timeouts; zero means the default. Tests set them in milliseconds.
	HandshakeTimeout time.Duration // waiting for welcome; default 5s (protocol.md §4)
	WriteTimeout     time.Duration // one frame to the gateway; default 10s

	// InputBuffer is how many inbound events a player may have waiting for
	// its handler. A player past it is disconnected (reason "overflow")
	// rather than stalling the link for everyone else. Default 256.
	InputBuffer int
}

// RejectedError is returned by Serve when the gateway refuses the realm.
type RejectedError struct {
	Reason   string
	Versions []int // what the gateway supports, for unsupported-version
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("realm: gateway rejected the realm: %s", e.Reason)
}

// ErrProtocol wraps a gateway message that breaks the protocol.
var ErrProtocol = errors.New("realm: protocol violation by gateway")

// Serve runs one link until it ends: the gateway sends shutdown (nil), the
// link fails (that error), or ctx is cancelled (ctx.Err()). Every player
// session has ended by the time Serve returns.
func Serve(ctx context.Context, c *realmproto.Conn, cfg Config) error {
	cfg = withDefaults(cfg)
	l := &link{
		conn:    c,
		cfg:     cfg,
		log:     cfg.Log.With("realm", cfg.ID),
		players: map[uint64]*player{},
		reg:     session.NewRegistry(),
	}
	// Cancelling ctx closes the link, which unblocks Recv, including while
	// the handshake waits for welcome.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if err := l.handshake(); err != nil {
		c.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	l.log.Info("registered with gateway")

	hctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := l.run(hctx)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	c.Close()
	l.closeAll()
	cancel()
	l.reg.Wait()
	return err
}

func withDefaults(cfg Config) Config {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Policy == (session.QueuePolicy{}) {
		cfg.Policy = session.DefaultPolicy
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 5 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	if cfg.InputBuffer == 0 {
		cfg.InputBuffer = 256
	}
	return cfg
}

type link struct {
	conn *realmproto.Conn
	cfg  Config
	log  *slog.Logger
	reg  *session.Registry

	mu      sync.Mutex
	players map[uint64]*player
	unknown int // messages of types this version does not know
}

func (l *link) handshake() error {
	if err := l.send(&realmproto.Hello{
		Versions:    []int{realmproto.Version},
		Realm:       l.cfg.ID,
		Name:        l.cfg.Name,
		Build:       l.cfg.Build,
		Fingerprint: l.cfg.Fingerprint,
	}); err != nil {
		return err
	}
	l.conn.SetReadDeadline(time.Now().Add(l.cfg.HandshakeTimeout))
	m, err := l.conn.Recv()
	l.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("realm: waiting for welcome: %w", err)
	}
	switch v := m.(type) {
	case *realmproto.Welcome:
		if v.Version != realmproto.Version {
			return fmt.Errorf("%w: welcome for version %d, we offered %d", ErrProtocol, v.Version, realmproto.Version)
		}
		return nil
	case *realmproto.Reject:
		return &RejectedError{Reason: v.Reason, Versions: v.Versions}
	default:
		return fmt.Errorf("%w: %s before welcome", ErrProtocol, m.Type())
	}
}

// send writes one message with a deadline. A gateway that cannot take a
// frame within WriteTimeout is broken; the link is closed so Serve ends.
func (l *link) send(m realmproto.Message) error {
	l.conn.SetWriteDeadline(time.Now().Add(l.cfg.WriteTimeout))
	err := l.conn.Send(m)
	if err != nil {
		l.conn.Close()
	}
	return err
}

func (l *link) run(ctx context.Context) error {
	for {
		m, err := l.conn.Recv()
		if err != nil {
			return err
		}
		switch v := m.(type) {
		case *realmproto.SessionOpen:
			if err := l.open(ctx, v); err != nil {
				return err
			}
		case *realmproto.Input:
			l.deliver(v.Session, session.Line{Text: v.Text})
		case *realmproto.GMCP:
			l.deliver(v.Session, session.GMCP{Package: v.Package, Data: v.Data})
		case *realmproto.Client:
			l.deliver(v.Session, session.ClientUpdate{Info: v.Client.ToSession()})
		case *realmproto.SessionClosed:
			if p := l.player(v.Session); p != nil {
				p.gatewayClosed(v.Reason)
			}
		case *realmproto.Ping:
			if err := l.send(&realmproto.Pong{N: v.N}); err != nil {
				return err
			}
		case *realmproto.Pong:
		case *realmproto.Shutdown:
			l.log.Info("gateway is shutting down")
			return nil
		case *realmproto.Unknown:
			l.mu.Lock()
			l.unknown++
			n := l.unknown
			l.mu.Unlock()
			l.log.Debug("ignoring unknown message type", "type", v.Name, "count", n)
		default:
			return fmt.Errorf("%w: unexpected %s", ErrProtocol, m.Type())
		}
	}
}

func (l *link) open(ctx context.Context, o *realmproto.SessionOpen) error {
	l.mu.Lock()
	if _, dup := l.players[o.Session]; dup {
		l.mu.Unlock()
		// The gateway never reuses an id while a link is up (protocol.md §5).
		return fmt.Errorf("%w: session %d opened twice", ErrProtocol, o.Session)
	}
	p := &player{
		id:     o.Session,
		link:   l,
		meta:   session.Meta{Kind: o.Transport, Remote: "gateway", Secure: o.Secure},
		in:     make(chan session.Inbound, l.cfg.InputBuffer),
		closed: make(chan struct{}),
	}
	l.players[o.Session] = p
	l.mu.Unlock()

	// The client as the gateway saw it at open time; later changes arrive
	// as Client messages.
	p.in <- session.ClientUpdate{Info: o.Client.ToSession()}

	// Session ids come from the gateway, so log lines on both sides match.
	s := session.NewWithID(o.Session, p, l.cfg.Policy, l.log)
	l.reg.Reserve("gateway", 0, 0) // 0, 0: no limits; the gateway enforces them
	go l.reg.Serve(ctx, "gateway", s, l.cfg.Handler)
	return nil
}

func (l *link) player(id uint64) *player {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.players[id]
}

// deliver hands an inbound event to a player without blocking the link.
// Input for a session that has already gone is a normal race and dropped.
func (l *link) deliver(id uint64, ev session.Inbound) {
	p := l.player(id)
	if p == nil {
		return
	}
	select {
	case p.in <- ev:
	case <-p.closed:
	default:
		l.log.Warn("player input backlog full; disconnecting", "session", id)
		p.closeWith(realmproto.ClosedOverflow)
	}
}

func (l *link) forget(id uint64) {
	l.mu.Lock()
	delete(l.players, id)
	l.mu.Unlock()
}

// closeAll ends every player when the link is gone; nothing can be sent.
func (l *link) closeAll() {
	l.mu.Lock()
	ps := make([]*player, 0, len(l.players))
	for _, p := range l.players {
		ps = append(ps, p)
	}
	l.mu.Unlock()
	for _, p := range ps {
		p.gatewayClosed(realmproto.ClosedDisconnected)
	}
}

// player is one routed session, as a session.Transport.
type player struct {
	id   uint64
	link *link
	meta session.Meta
	in   chan session.Inbound

	closeOnce sync.Once
	closed    chan struct{}
}

func (p *player) Meta() session.Meta { return p.meta }

func (p *player) ReadEvent() (session.Inbound, error) {
	// Events already queued are delivered before the close is seen, so a
	// player's last line before quitting is not lost.
	select {
	case ev := <-p.in:
		return ev, nil
	default:
	}
	select {
	case ev := <-p.in:
		return ev, nil
	case <-p.closed:
		return nil, session.ErrClosed
	}
}

func (p *player) WriteEvent(o session.Outbound) error {
	select {
	case <-p.closed:
		return session.ErrClosed
	default:
	}
	var m realmproto.Message
	switch v := o.(type) {
	case session.Text:
		m = &realmproto.Text{Session: p.id, Text: v.Text}
	case session.Prompt:
		m = &realmproto.Prompt{Session: p.id, Text: v.Text}
	case session.GMCPOut:
		m = &realmproto.GMCP{Session: p.id, Package: v.Package, Data: v.Data}
	case session.InputMode:
		m = &realmproto.InputMode{Session: p.id, Hidden: v.Hidden}
	default:
		return nil
	}
	if err := p.link.send(m); err != nil {
		if errors.Is(err, realmproto.ErrFrameTooLarge) || errors.Is(err, realmproto.ErrInvalidField) {
			// A handler bug, not a link failure: drop the one message.
			p.link.log.Warn("dropped invalid output", "session", p.id, "type", m.Type(), "err", err)
			return nil
		}
		return err
	}
	return nil
}

// Close is called by the session when its handler is done: the realm ends
// the player, so the gateway is asked to disconnect them.
func (p *player) Close() error {
	p.closeWith("")
	return nil
}

func (p *player) closeWith(reason string) {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.link.forget(p.id)
		// Best effort: if the link is down there is nobody to tell.
		p.link.send(&realmproto.SessionClose{Session: p.id, Reason: reason})
	})
}

// gatewayClosed ends the player because the gateway says they are gone, or
// the link is; nothing is sent back.
func (p *player) gatewayClosed(reason string) {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.link.forget(p.id)
		p.link.log.Debug("player gone", "session", p.id, "reason", reason)
	})
}
