// Package proxy is the gateway's side of realm links (docs/protocol.md). A
// Hub accepts realm links and keeps the list of registered realms; Handler
// is the session.Handler that routes a player to a realm and relays events
// both ways.
//
// Each realm link has its own reader goroutine, its own writer and its own
// session table, so a slow or stuck realm affects only its own players:
// realm output reaches players through their non-blocking session queues,
// and player input reaches a realm through that realm's bounded writer.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"sanctuary/internal/realmproto"
	"sanctuary/internal/sanitize"
	"sanctuary/internal/session"
)

// HubConfig configures a Hub. Zero fields take the defaults.
type HubConfig struct {
	Gateway          string        // build id sent in welcome
	CommandPrefix    string        // sent in welcome; empty means the protocol default ">"
	MaxRealms        int           // registered realms at once; default 32
	HandshakeTimeout time.Duration // hello must arrive within this; default 5s (protocol.md §4)
	Writer           realmproto.WriterLimits
	Keepalive        realmproto.Keepalive // per link; zero fields take the defaults
	// ShutdownFlush bounds the final flush to each realm on gateway
	// shutdown; default 5s. A realm that reads slowly cannot hold the
	// gateway open past it.
	ShutdownFlush time.Duration
	Log           *slog.Logger
}

// Hub holds the registered realms.
type Hub struct {
	cfg HubConfig
	log *slog.Logger

	mu      sync.Mutex
	realms  map[string]*Realm
	changed chan struct{} // closed and replaced whenever realms changes
}

// NewHub returns an empty hub.
func NewHub(cfg HubConfig) *Hub {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.MaxRealms == 0 {
		cfg.MaxRealms = 32
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 5 * time.Second
	}
	if cfg.ShutdownFlush == 0 {
		cfg.ShutdownFlush = 5 * time.Second
	}
	return &Hub{cfg: cfg, log: cfg.Log, realms: map[string]*Realm{}, changed: make(chan struct{})}
}

// RealmInfo describes a registered realm.
type RealmInfo struct {
	ID, Name, Build string
}

// Realms lists registered realms, sorted by id.
func (h *Hub) Realms() []RealmInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]RealmInfo, 0, len(h.realms))
	for _, r := range h.realms {
		out = append(out, RealmInfo{r.ID, r.Name, r.Build})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// pick returns realm id, or the first realm by id when id is empty, waiting
// until ctx ends for one to register.
func (h *Hub) pick(ctx context.Context, id string) (*Realm, error) {
	for {
		h.mu.Lock()
		var r *Realm
		if id != "" {
			r = h.realms[id]
		} else if len(h.realms) > 0 {
			ids := make([]string, 0, len(h.realms))
			for k := range h.realms {
				ids = append(ids, k)
			}
			r = h.realms[slices.Min(ids)]
		}
		changed := h.changed
		h.mu.Unlock()
		if r != nil && !r.draining() && !r.failing() {
			return r, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *Hub) notify() {
	close(h.changed)
	h.changed = make(chan struct{})
}

// ErrRealmProtocol wraps a realm message that breaks the protocol.
var ErrRealmProtocol = errors.New("proxy: protocol violation by realm")

// Serve runs one realm link that may register as any realm id: only for
// links that nothing outside this process can open (the in-process stub
// realm over realmproto.Pipe). Network links use ServeAs, via ServeListener.
func (h *Hub) Serve(ctx context.Context, c *realmproto.Conn) error {
	return h.ServeAs(ctx, c, nil)
}

// ServeAs runs one realm link: the handshake, then relaying until the link
// ends or ctx is cancelled (gateway shutdown). allowed says which realm ids
// the connected key may register as (realmproto.RealmIDs); a hello for any
// other id is rejected (RT-3-1). nil allows any id. It closes c before
// returning.
func (h *Hub) ServeAs(ctx context.Context, c *realmproto.Conn, allowed func(id string) bool) error {
	w := realmproto.NewWriter(c, h.cfg.Writer)
	defer func() {
		c.Close()
		w.Close()
	}()
	// During the handshake, cancelling just closes the link.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	r, err := h.handshake(c, w, allowed)
	stop()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	log := h.log.With("realm", r.ID)
	log.Info("realm registered", "build", r.Build)
	defer func() {
		h.mu.Lock()
		delete(h.realms, r.ID)
		h.notify()
		h.mu.Unlock()
		r.lost()
		log.Info("realm link ended")
	}()

	// Once registered, gateway shutdown tells the realm first: queue
	// shutdown, flush, then close the link (protocol.md §8).
	stopShutdown := context.AfterFunc(ctx, func() {
		w.Send(&realmproto.Shutdown{})
		w.CloseWithin(h.cfg.ShutdownFlush)
		c.Close()
	})
	defer stopShutdown()
	if ctx.Err() != nil { // cancelled between the handshake and here
		stopShutdown()
		w.Send(&realmproto.Shutdown{})
		w.CloseWithin(h.cfg.ShutdownFlush)
		c.Close()
	}

	err = r.run()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case w.Err() != nil:
		return w.Err() // the realm stopped reading; the writer closed the link
	}
	return err
}

func (h *Hub) handshake(c *realmproto.Conn, w *realmproto.Writer, allowed func(string) bool) (*Realm, error) {
	c.SetReadDeadline(time.Now().Add(h.cfg.HandshakeTimeout))
	m, err := c.RecvLimit(realmproto.MaxHello)
	c.SetReadDeadline(time.Time{})
	reject := func(reason string, cause error) (*Realm, error) {
		rej := &realmproto.Reject{Reason: reason}
		if reason == realmproto.RejectUnsupportedVersion {
			rej.Versions = []int{realmproto.Version}
		}
		w.Send(rej)
		w.Close() // flush the reject before the caller closes the link
		h.log.Warn("realm rejected", "reason", reason, "err", cause)
		return nil, fmt.Errorf("proxy: realm rejected (%s): %w", reason, cause)
	}
	if err != nil {
		if errors.Is(err, realmproto.ErrInvalidField) || errors.Is(err, realmproto.ErrWrongSender) ||
			errors.Is(err, realmproto.ErrNotObject) || errors.Is(err, realmproto.ErrFrameTooLarge) {
			return reject(realmproto.RejectBadHello, err)
		}
		return nil, fmt.Errorf("proxy: waiting for hello: %w", err)
	}
	hello, ok := m.(*realmproto.Hello)
	if !ok {
		return reject(realmproto.RejectBadHello, fmt.Errorf("%w: %s before hello", ErrRealmProtocol, m.Type()))
	}
	if !slices.Contains(hello.Versions, realmproto.Version) {
		return reject(realmproto.RejectUnsupportedVersion, fmt.Errorf("realm offers %v", hello.Versions))
	}
	if allowed != nil && !allowed(hello.Realm) {
		// A trusted key is not enough: it must be the key for this realm,
		// or one realm could take over another's players (RT-3-1).
		return reject(realmproto.RejectNotAllowed, fmt.Errorf("this key may not register as realm %q", hello.Realm))
	}

	r := &Realm{
		ID:       hello.Realm,
		Name:     sanitize.Untrusted(hello.Name),
		Build:    sanitize.Untrusted(hello.Build),
		conn:     c,
		w:        w,
		log:      h.log.With("realm", hello.Realm),
		sessions: map[uint64]*attached{},
		ka:       h.cfg.Keepalive,
		gone:     make(chan struct{}),
	}
	h.mu.Lock()
	if _, dup := h.realms[r.ID]; dup {
		h.mu.Unlock()
		return reject(realmproto.RejectDuplicateRealm, fmt.Errorf("realm %q already registered", r.ID))
	}
	if len(h.realms) >= h.cfg.MaxRealms {
		h.mu.Unlock()
		return reject(realmproto.RejectTooManyRealms, fmt.Errorf("%d realms registered", len(h.realms)))
	}
	h.realms[r.ID] = r
	h.notify()
	h.mu.Unlock()
	if err := w.Send(&realmproto.Welcome{Version: realmproto.Version, Gateway: h.cfg.Gateway, CommandPrefix: h.cfg.CommandPrefix}); err != nil {
		h.mu.Lock()
		delete(h.realms, r.ID)
		h.notify()
		h.mu.Unlock()
		return nil, err
	}
	return r, nil
}

// Realm is the gateway's view of one registered realm.
type Realm struct {
	ID, Name, Build string

	conn *realmproto.Conn
	w    *realmproto.Writer
	ka   realmproto.Keepalive
	log  *slog.Logger

	mu        sync.Mutex
	sessions  map[uint64]*attached
	isDrain   bool
	unknown   int
	gone      chan struct{} // closed when the link has ended
	closeOnce sync.Once
}

// attached is a player routed to this realm.
type attached struct {
	s           *session.Session
	realmClosed chan struct{} // the realm sent session.close
	closeReason string        // its reason; set before realmClosed is closed
	hidden      atomic.Bool   // the realm last asked for hidden input
	prompt      atomic.Value  // string: the realm's last prompt, repeated after a gateway command
	once        sync.Once
}

// failing reports whether the realm's link has stopped (its writer failed,
// or the link ended) while the hub has not removed it yet. Handing such a
// realm to a player would fail at once, and a held player would go round
// attach, fail, hold as fast as the CPU allows (red team round 3).
func (r *Realm) failing() bool {
	select {
	case <-r.w.Done():
		return true
	case <-r.gone:
		return true
	default:
		return false
	}
}

func (r *Realm) draining() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.isDrain
}

// Gone is closed when the realm's link has ended.
func (r *Realm) Gone() <-chan struct{} { return r.gone }

func (r *Realm) lost() { r.closeOnce.Do(func() { close(r.gone) }) }

func (r *Realm) session(id uint64) *attached {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

// run relays realm messages until the link ends. Nothing here blocks on a
// player: session.Send only queues, and a player whose queue overflows is
// disconnected by the session itself.
func (r *Realm) run() error {
	for {
		m, err := r.ka.Recv(r.conn, r.w)
		if err != nil {
			return err
		}
		switch v := m.(type) {
		case *realmproto.Text:
			if a := r.session(v.Session); a != nil {
				a.s.Send(session.Text{Text: sanitize.Server(v.Text)})
			}
		case *realmproto.Prompt:
			if a := r.session(v.Session); a != nil {
				p := sanitize.Server(v.Text)
				a.prompt.Store(p)
				a.s.Send(session.Prompt{Text: p})
			}
		case *realmproto.GMCP:
			if a := r.session(v.Session); a != nil {
				a.s.Send(session.GMCPOut{Package: v.Package, Data: v.Data})
			}
		case *realmproto.InputMode:
			if a := r.session(v.Session); a != nil {
				a.hidden.Store(v.Hidden)
				a.s.Send(session.InputMode{Hidden: v.Hidden})
			}
		case *realmproto.SessionClose:
			if a := r.session(v.Session); a != nil {
				a.once.Do(func() {
					a.closeReason = v.Reason
					close(a.realmClosed)
				})
			}
		case *realmproto.Ping:
			if err := r.w.Send(&realmproto.Pong{N: v.N}); err != nil {
				return err
			}
		case *realmproto.Pong:
		case *realmproto.Drain:
			r.mu.Lock()
			r.isDrain = true
			r.mu.Unlock()
			r.log.Info("realm draining", "deadline_ms", v.DeadlineMS)
		case *realmproto.Drained:
			r.log.Info("realm drained")
			return nil
		case *realmproto.Unknown:
			r.mu.Lock()
			r.unknown++
			n := r.unknown
			r.mu.Unlock()
			r.log.Debug("ignoring unknown message type", "type", v.Name, "count", n)
		default:
			// Decode already refuses gateway-only types from a realm.
			return fmt.Errorf("%w: unexpected %s", ErrRealmProtocol, m.Type())
		}
	}
}

// attach routes s to the realm. The returned attachment is the handler's
// view: realmClosed fires if the realm ends the player.
func (r *Realm) attach(s *session.Session) (*attached, error) {
	a := &attached{s: s, realmClosed: make(chan struct{})}
	r.mu.Lock()
	r.sessions[s.ID] = a
	r.mu.Unlock()
	m := s.Meta()
	open := &realmproto.SessionOpen{
		Session:   s.ID,
		Transport: m.Kind,
		Secure:    m.Secure,
		Client:    realmproto.ClientFrom(s.Client()),
	}
	if acct := s.Account(); acct.LoggedIn() {
		open.Account = &realmproto.AccountInfo{ID: acct.ID, Name: acct.Name}
	}
	err := r.w.Send(open)
	if err != nil {
		r.detach(s.ID, "")
		return nil, err
	}
	return a, nil
}

// detach removes a player and, unless reason is empty, tells the realm.
func (r *Realm) detach(id uint64, reason string) {
	r.mu.Lock()
	delete(r.sessions, id)
	r.mu.Unlock()
	if reason != "" {
		r.w.Send(&realmproto.SessionClosed{Session: id, Reason: reason})
	}
}
