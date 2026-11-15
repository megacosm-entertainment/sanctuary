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

	// HandshakeTimeout bounds waiting for welcome; default 5s (protocol.md
	// §4). Tests set it in milliseconds.
	HandshakeTimeout time.Duration

	// Writer bounds the queue to the gateway: per player, so one flooded
	// player is disconnected alone, and per link, so a gateway that stops
	// reading is detected. Zero fields take realmproto's defaults.
	Writer realmproto.WriterLimits

	// InputBuffer is how many inbound events a player may have waiting for
	// its handler. A player past it is disconnected (reason "overflow")
	// rather than stalling the link for everyone else. Default 256.
	InputBuffer int

	// Keepalive pings the gateway on a quiet link and ends a link that has
	// gone silent (protocol.md §8). Zero fields take the defaults.
	Keepalive realmproto.Keepalive

	// DrainTimeout bounds the shutdown drain: players are told and handed
	// back, then the link closes, within this. Default 20s, inside the 30s
	// grace an orchestrator usually allows between SIGTERM and SIGKILL.
	DrainTimeout time.Duration

	// OnRegistered, if set, is called once the gateway has welcomed the
	// realm. Run uses it to tell a working link from failed attempts.
	OnRegistered func()
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
// link fails (that error), or ctx is cancelled (ctx.Err()), which drains
// the link first. Every player session has ended by the time Serve returns,
// except, after a drain, a handler that ignored its context for longer than
// DrainTimeout: the realm is exiting, and is not held up by it.
func Serve(ctx context.Context, c *realmproto.Conn, cfg Config) error {
	cfg = withDefaults(cfg)
	l := &link{
		conn:    c,
		cfg:     cfg,
		log:     cfg.Log.With("realm", cfg.ID),
		players: map[uint64]*player{},
		reg:     session.NewRegistry(),
		w:       realmproto.NewWriter(c, cfg.Writer),
		ka:      cfg.Keepalive,
	}
	defer l.w.Close()
	// During the handshake, cancelling ctx just closes the link, which
	// unblocks Recv.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	err := l.handshake()
	stop()
	if err != nil || ctx.Err() != nil {
		c.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	l.log.Info("registered with gateway", "command_prefix", l.prefix)
	if cfg.OnRegistered != nil {
		cfg.OnRegistered()
	}

	// Handlers get their own context: on shutdown the realm announces the
	// drain first, then tells handlers to finish (protocol.md §8).
	hctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	stopDrain := context.AfterFunc(ctx, func() {
		defer close(drained)
		l.drain(cancel)
	})
	defer func() {
		if !stopDrain() {
			<-drained // a drain started; let it finish before returning
		}
	}()

	err = l.run(hctx)
	switch {
	case ctx.Err() != nil:
		err = ctx.Err()
	case l.w.Err() != nil:
		// The writer closed the link (gateway stalled, or a write failed);
		// that, not the reader's resulting EOF, is why the link ended.
		err = l.w.Err()
	}
	c.Close()
	l.closeAll()
	cancel()
	if ctx.Err() == nil {
		l.reg.Wait()
		return err
	}
	// Shutting down: the drain has handed every player back, but a handler
	// that ignores its context could still be running. Give it the drain
	// deadline, then let the process exit rather than hang on it.
	waited := make(chan struct{})
	go func() { l.reg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(l.cfg.DrainTimeout):
		l.log.Warn("session handlers still running after the drain; not waiting for them")
	}
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
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = 20 * time.Second
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
	w    *realmproto.Writer // the only writer to conn
	ka   realmproto.Keepalive

	mu       sync.Mutex
	players  map[uint64]*player
	unknown  int           // messages of types this version does not know
	draining bool          // shutting down: no new players; players are handed back
	allGone  chan struct{} // closed when the last player leaves during a drain
	prefix   string        // the gateway's command prefix, from welcome
}

func (l *link) handshake() error {
	if err := l.w.Send(&realmproto.Hello{
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
		l.prefix = v.CommandPrefix
		if l.prefix == "" {
			l.prefix = ">"
		}
		return nil
	case *realmproto.Reject:
		return &RejectedError{Reason: v.Reason, Versions: v.Versions}
	default:
		return fmt.Errorf("%w: %s before welcome", ErrProtocol, m.Type())
	}
}

func (l *link) run(ctx context.Context) error {
	for {
		m, err := l.ka.Recv(l.conn, l.w)
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
			// Queued, never written here: the reader keeps reading even
			// when the gateway is slow to take our output.
			if err := l.w.Send(&realmproto.Pong{N: v.N}); err != nil {
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
	if l.draining {
		// Sent before the gateway saw our drain: hand the player straight
		// back, to be held for this realm's return.
		l.mu.Unlock()
		l.w.Send(&realmproto.SessionClose{Session: o.Session, Reason: realmproto.ClosedDrain})
		return nil
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
	if o.Account != nil {
		s.SetAccount(session.Account{ID: o.Account.ID, Name: o.Account.Name})
	}
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
	if l.draining && len(l.players) == 0 && l.allGone != nil {
		close(l.allGone)
		l.allGone = nil
	}
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
	err := p.link.w.Send(m)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, realmproto.ErrSessionBacklog):
		// This player's output is not reaching the gateway fast enough;
		// end them alone, as the gateway would a slow client.
		p.link.log.Warn("player output backlog full; disconnecting", "session", p.id)
		p.closeWith(realmproto.ClosedOverflow)
		return session.ErrOverflow
	case errors.Is(err, realmproto.ErrFrameTooLarge) || errors.Is(err, realmproto.ErrInvalidField):
		// A handler bug, not a link failure: drop the one message.
		p.link.log.Warn("dropped invalid output", "session", p.id, "type", m.Type(), "err", err)
		return nil
	default:
		return err
	}
}

// Close is called by the session when its handler is done: the realm ends
// the player, so the gateway is asked to disconnect them.
func (p *player) Close() error {
	reason := ""
	p.link.mu.Lock()
	if p.link.draining {
		reason = realmproto.ClosedDrain // handed back, not quitting
	}
	p.link.mu.Unlock()
	p.closeWith(reason)
	return nil
}

// drain is the shutdown sequence (protocol.md §8, design §04 "Graceful
// shutdown"): announce it, stop taking players, let each handler say
// goodbye and end (each player is handed back with reason "drain"), then
// send drained and close the link, all within DrainTimeout.
func (l *link) drain(stopHandlers context.CancelFunc) {
	deadline := l.cfg.DrainTimeout
	started := time.Now()
	// Wait on the player table, not the handler WaitGroup: the table is
	// updated under l.mu, so a player opened just before the drain is
	// counted, and nothing calls Add while this waits.
	done := make(chan struct{})
	l.mu.Lock()
	l.draining = true
	n := len(l.players)
	if n == 0 {
		close(done)
	} else {
		l.allGone = done
	}
	l.mu.Unlock()
	l.log.Info("draining", "players", n, "deadline", deadline)
	l.w.Send(&realmproto.Drain{DeadlineMS: deadline.Milliseconds()})
	stopHandlers()

	select {
	case <-done:
	case <-time.After(deadline):
		l.mu.Lock()
		left := make([]*player, 0, len(l.players))
		for _, p := range l.players {
			left = append(left, p)
		}
		l.mu.Unlock()
		l.log.Warn("drain deadline passed; handing back remaining players", "players", len(left))
		for _, p := range left {
			p.closeWith(realmproto.ClosedDrain)
		}
	}
	l.w.Send(&realmproto.Drained{})
	// Flush every goodbye and session.close, within what is left of the
	// deadline (at least a second), so the whole drain stays inside the
	// grace an orchestrator allows; then the link goes.
	left := deadline - time.Since(started)
	if left < time.Second {
		left = time.Second
	}
	l.w.CloseWithin(left)
	l.conn.Close()
	l.log.Info("drained")
}

func (p *player) closeWith(reason string) {
	p.closeOnce.Do(func() {
		close(p.closed)
		// Queue session.close before forgetting the player: forgetting the
		// last player wakes a drain, which then sends drained, and that must
		// follow every session.close on the wire. Best effort: if the link
		// is down there is nobody to tell.
		p.link.w.Send(&realmproto.SessionClose{Session: p.id, Reason: reason})
		p.link.forget(p.id)
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
