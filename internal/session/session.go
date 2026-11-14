package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sanctuary/internal/sanitize"
)

// Meta describes where a session came from.
type Meta struct {
	Kind   string // "telnet", "telnet+tls", "ws/gmcp", "ws/telnet", "mem"
	Remote string // remote address as seen by the gateway
	Secure bool   // transport is encrypted end to end to the client
}

// Transport is one client connection, normalised. Socket transports (telnet,
// WebSocket) and the in-memory transport all implement it.
//
// ReadEvent is called from one goroutine only (the Handler's). WriteEvent is
// called from one goroutine only (the Session's writer). Close may be called
// from anywhere and must unblock both.
type Transport interface {
	ReadEvent() (Inbound, error)
	WriteEvent(Outbound) error
	Close() error
	Meta() Meta
}

// Handler drives a session until it returns. When ServeSession returns the
// session is closed. ctx is cancelled at gateway shutdown.
type Handler interface {
	ServeSession(ctx context.Context, s *Session)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, s *Session)

func (f HandlerFunc) ServeSession(ctx context.Context, s *Session) { f(ctx, s) }

// Errors reported by Send and Err.
var (
	ErrClosed   = errors.New("session closed")
	ErrOverflow = errors.New("outbound queue overflow: client is not reading")
)

// Outbound queue policy.
//
// Every session has a bounded outbound queue so a slow client can never stall
// the code producing output (in stage 02, a realm's tick). Send never blocks.
// When the queue is over budget:
//
//   - Text, Prompt and InputMode are never dropped. Losing a line of game
//     text silently is worse than disconnecting, especially for screen-reader
//     users who cannot glance back at what scrolled past. The session is
//     disconnected with ErrOverflow.
//   - GMCP is state, not narrative, and is superseded by the next update. It
//     is dropped (and counted) once the queue passes the soft limit, which
//     leaves headroom for text before the hard limit disconnects.
type QueuePolicy struct {
	MaxBytes      int           // hard limit on queued output bytes
	MaxMessages   int           // hard limit on queued messages
	GMCPSoftBytes int           // GMCP is dropped above this many queued bytes
	DrainTimeout  time.Duration // how long Close waits for queued output to flush
}

// DefaultPolicy is the gateway's stage-01 policy.
var DefaultPolicy = QueuePolicy{
	MaxBytes:      256 << 10,
	MaxMessages:   4096,
	GMCPSoftBytes: 64 << 10,
	DrainTimeout:  3 * time.Second,
}

var nextID atomic.Uint64

// Session wraps a Transport with an outbound queue and client-info tracking.
type Session struct {
	ID     uint64
	t      Transport
	meta   Meta
	policy QueuePolicy
	log    *slog.Logger

	mu          sync.Mutex
	queue       []Outbound
	queuedBytes int
	closing     bool // no new output accepted; writer drains then closes
	err         error
	client      ClientInfo // as last reported by the transport
	hello       coreHello  // from GMCP Core.Hello
	dropped     int

	wake      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// AllocID reserves a session ID. Callers that build a Transport before the
// Session use it so the transport's log lines carry the same ID.
func AllocID() uint64 { return nextID.Add(1) }

// New starts a session over t with a fresh ID. The writer goroutine runs
// until the session closes.
func New(t Transport, policy QueuePolicy, log *slog.Logger) *Session {
	return NewWithID(AllocID(), t, policy, log)
}

// NewWithID is New with an ID from AllocID.
func NewWithID(id uint64, t Transport, policy QueuePolicy, log *slog.Logger) *Session {
	if log == nil {
		log = slog.Default()
	}
	s := &Session{
		ID:     id,
		t:      t,
		meta:   t.Meta(),
		policy: policy,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
		client: ClientInfo{Charset: "UTF-8"},
	}
	s.log = log.With("session", s.ID, "transport", s.meta.Kind, "remote", s.meta.Remote)
	go s.writer()
	return s
}

// Meta reports where the session came from.
func (s *Session) Meta() Meta { return s.meta }

// Log returns the session's logger.
func (s *Session) Log() *slog.Logger { return s.log }

// Client returns the latest snapshot of client-reported information.
//
// Name and version are taken as a pair from one source, in this order:
// MNES CLIENT_NAME (explicit), GMCP Core.Hello (the client's own spelling
// with a version, and the only identity a WebSocket client can send), then
// the TTYPE name (upper case by MTTS convention, no version). A version from
// a lower-ranked source is used only when it names the same client.
func (s *Session) Client() ClientInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.client.Clone()
	h := s.hello
	switch {
	case c.NameSource == SourceMNES && c.Name != "":
		if c.Version == "" && strings.EqualFold(c.Name, h.client) {
			c.Version = h.version
		}
	case h.client != "":
		version := h.version
		if version == "" && strings.EqualFold(c.Name, h.client) {
			version = c.Version // same client, version reported elsewhere
		}
		c.Name, c.Version, c.NameSource = h.client, version, SourceCoreHello
	case c.Version == "" && c.Name == "" && h.version != "":
		c.Version = h.version
	}
	return c
}

// Done is closed once the session has fully closed.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err reports why the session closed, or nil while it is open or after a
// normal close.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Dropped reports how many GMCP messages were dropped under the queue policy.
func (s *Session) Dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Recv returns the next inbound event. ClientUpdate events also update the
// snapshot returned by Client. Call from one goroutine only.
func (s *Session) Recv() (Inbound, error) {
	ev, err := s.t.ReadEvent()
	if err != nil {
		return nil, err
	}
	switch v := ev.(type) {
	case ClientUpdate:
		s.mu.Lock()
		s.client = v.Info.Clone()
		s.mu.Unlock()
	case GMCP:
		if strings.EqualFold(v.Package, "Core.Hello") {
			if h, ok := parseHello(v.Data); ok {
				s.mu.Lock()
				s.hello = h
				s.mu.Unlock()
				s.log.Info("client identified via Core.Hello", "client", h.client, "version", h.version)
			}
		}
	case Line:
		// Size only: player text never goes to the logs (design doc §02).
		s.log.Debug("input", "bytes", len(v.Text))
	}
	return ev, nil
}

type coreHello struct{ client, version string }

// parseHello reads {"client": "...", "version": "..."}. Values are
// untrusted presentation hints: sanitised and capped.
func parseHello(data json.RawMessage) (coreHello, bool) {
	var raw struct {
		Client  any `json:"client"`
		Version any `json:"version"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return coreHello{}, false
	}
	str := func(v any) string {
		s, _ := v.(string)
		s = strings.TrimSpace(sanitize.Untrusted(s))
		if len(s) > 64 {
			s = strings.ToValidUTF8(s[:64], "")
		}
		return s
	}
	h := coreHello{client: str(raw.Client), version: str(raw.Version)}
	return h, h.client != "" || h.version != ""
}

// Send queues output without blocking. It applies the queue policy described
// on QueuePolicy.
func (s *Session) Send(o Outbound) error {
	size := sizeOf(o)
	s.mu.Lock()
	if s.closing {
		err := s.err
		s.mu.Unlock()
		if err == nil {
			err = ErrClosed
		}
		return err
	}
	if _, isGMCP := o.(GMCPOut); isGMCP && s.queuedBytes+size > s.policy.GMCPSoftBytes {
		s.dropped++
		n := s.dropped
		s.mu.Unlock()
		if n == 1 || n%100 == 0 {
			s.log.Warn("dropping GMCP: outbound queue over soft limit", "dropped", n)
		}
		return nil
	}
	if s.queuedBytes+size > s.policy.MaxBytes || len(s.queue)+1 > s.policy.MaxMessages {
		s.mu.Unlock()
		s.abort(ErrOverflow)
		return ErrOverflow
	}
	s.queue = append(s.queue, o)
	s.queuedBytes += size
	s.mu.Unlock()
	s.signal()
	return nil
}

// Close flushes queued output (up to the policy's DrainTimeout) and then
// closes the transport. It returns without waiting; use Done to wait.
func (s *Session) Close() {
	s.mu.Lock()
	already := s.closing
	s.closing = true
	s.mu.Unlock()
	if already {
		return
	}
	s.signal()
	go func() {
		select {
		case <-s.done:
		case <-time.After(s.policy.DrainTimeout):
			s.log.Debug("drain timeout; closing with output still queued")
			s.shutdown()
		}
	}()
}

// abort closes immediately, discarding queued output.
func (s *Session) abort(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.closing = true
	s.queue = nil
	s.queuedBytes = 0
	s.mu.Unlock()
	s.log.Info("session aborted", "reason", err)
	s.shutdown()
}

func (s *Session) shutdown() {
	s.closeOnce.Do(func() {
		s.t.Close()
		close(s.done)
	})
}

func (s *Session) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Session) writer() {
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closing {
			s.mu.Unlock()
			select {
			case <-s.wake:
			case <-s.done:
				return
			}
			s.mu.Lock()
		}
		if len(s.queue) == 0 { // closing and drained
			s.mu.Unlock()
			s.shutdown()
			return
		}
		o := s.queue[0]
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.queuedBytes -= sizeOf(o)
		s.mu.Unlock()

		if err := s.t.WriteEvent(o); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, ErrClosed) {
				s.log.Debug("write failed", "err", err)
			}
			s.mu.Lock()
			if s.err == nil && !s.closing {
				s.err = err
			}
			s.closing = true
			s.queue = nil
			s.queuedBytes = 0
			s.mu.Unlock()
			s.shutdown()
			return
		}
	}
}

func sizeOf(o Outbound) int {
	const overhead = 16
	switch v := o.(type) {
	case Text:
		return len(v.Text) + overhead
	case Prompt:
		return len(v.Text) + overhead
	case GMCPOut:
		return len(v.Package) + len(v.Data) + overhead
	default:
		return overhead
	}
}
