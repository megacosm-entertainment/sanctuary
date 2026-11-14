package realmproto

import (
	"errors"
	"sync"
	"time"
)

// Errors from Writer.Send.
var (
	// ErrSessionBacklog: one session has too much output queued. Only that
	// session is affected; the caller ends it (reason "overflow").
	ErrSessionBacklog = errors.New("realmproto: session backlog over its limit")
	// ErrStalled: the whole link's queue is full, so the peer has stopped
	// reading. The writer closes the link.
	ErrStalled = errors.New("realmproto: peer stalled; link closed")
	// ErrWriterClosed: the writer has stopped (closed, or a write failed).
	ErrWriterClosed = errors.New("realmproto: writer closed")
)

// WriterLimits bound a Writer's queue. Zero fields take the defaults.
type WriterLimits struct {
	// LinkBytes caps everything queued on the link. Past it the peer is
	// treated as stuck. Default 16 MiB: 64 sessions' full outbound budget.
	LinkBytes int
	// SessionBytes caps what one session may have queued, so one player
	// (spamming input at the gateway, or flooded with output in a realm)
	// cannot fill the link for everyone else. Default 1 MiB.
	SessionBytes int
	// WriteTimeout bounds writing one frame. Default 10s.
	WriteTimeout time.Duration
}

func (l WriterLimits) withDefaults() WriterLimits {
	if l.LinkBytes == 0 {
		l.LinkBytes = 16 << 20
	}
	if l.SessionBytes == 0 {
		l.SessionBytes = 1 << 20
	}
	if l.WriteTimeout == 0 {
		l.WriteTimeout = 10 * time.Second
	}
	return l
}

type queued struct {
	payload []byte
	session uint64
}

// Writer is the only thing that writes to a link. Send encodes in the
// caller's goroutine (so encoding runs in parallel across callers) and
// queues without blocking; one goroutine writes frames in order. Nothing
// that calls Send, a link reader answering a ping included, ever waits on
// the peer.
type Writer struct {
	c      *Conn
	limits WriterLimits

	mu        sync.Mutex
	queue     []queued
	bytes     int
	perSess   map[uint64]int
	closing   bool  // Close called: drain, then stop
	err       error // set when the writer stops
	wake      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewWriter starts a writer for c.
func NewWriter(c *Conn, limits WriterLimits) *Writer {
	w := &Writer{
		c:       c,
		limits:  limits.withDefaults(),
		perSess: map[uint64]int{},
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go w.run()
	return w
}

// Send validates, encodes and queues m. It never blocks. An encoding or
// validation error is returned as is and nothing is queued: that is a bug in
// the caller, not a link problem.
func (w *Writer) Send(m Message) error {
	payload, err := Encode(m)
	if err != nil {
		return err
	}
	id := SessionOf(m)
	n := len(payload) + headerLen

	w.mu.Lock()
	if w.err != nil || w.closing {
		w.mu.Unlock()
		return ErrWriterClosed
	}
	if id != 0 && !closes(m) && w.perSess[id]+n > w.limits.SessionBytes {
		w.mu.Unlock()
		return ErrSessionBacklog
	}
	if w.bytes+n > w.limits.LinkBytes {
		w.mu.Unlock()
		w.fail(ErrStalled)
		return ErrStalled
	}
	w.queue = append(w.queue, queued{payload, id})
	w.bytes += n
	if id != 0 {
		w.perSess[id] += n
	}
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return nil
}

// closes reports whether m ends a session. Those are exempt from the
// per-session limit: ending a session that overflowed must always be
// possible. They still count against the link limit.
func closes(m Message) bool {
	switch m.(type) {
	case *SessionClose, *SessionClosed:
		return true
	}
	return false
}

// Close stops accepting messages, writes what is queued (each frame still
// bounded by WriteTimeout), and returns when the writer has stopped. It does
// not close the link.
func (w *Writer) Close() {
	w.mu.Lock()
	w.closing = true
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
	<-w.done
}

// ErrFlushTimeout: CloseWithin gave up on writing what was queued.
var ErrFlushTimeout = errors.New("realmproto: flush did not finish in time; link closed")

// CloseWithin is Close with a bound on the whole flush, not just on each
// frame: whatever is not written within d is abandoned and the link is
// closed. Shutdown uses it, so a peer that reads slowly but steadily
// cannot hold a process open (red team round 3). It reports whether
// everything was written.
func (w *Writer) CloseWithin(d time.Duration) bool {
	w.mu.Lock()
	w.closing = true
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-w.done:
		return w.Err() == nil
	case <-t.C:
		w.fail(ErrFlushTimeout)
		<-w.done
		return false
	}
}

// Done is closed when the writer stops.
func (w *Writer) Done() <-chan struct{} { return w.done }

// Err is why the writer stopped: nil after a clean Close, otherwise the
// write error or ErrStalled.
func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if errors.Is(w.err, ErrWriterClosed) {
		return nil
	}
	return w.err
}

// Queued reports the bytes queued on the link and for one session (0 for
// the link only). For tests and diagnostics.
func (w *Writer) Queued(session uint64) (link, sess int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bytes, w.perSess[session]
}

// fail stops the writer with err and closes the link, so the link's reader
// sees the failure too.
func (w *Writer) fail(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.queue, w.bytes, w.perSess = nil, 0, map[uint64]int{}
	w.mu.Unlock()
	w.c.Close()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *Writer) run() {
	defer w.closeOnce.Do(func() { close(w.done) })
	for {
		w.mu.Lock()
		for len(w.queue) == 0 && w.err == nil && !w.closing {
			w.mu.Unlock()
			<-w.wake
			w.mu.Lock()
		}
		if w.err != nil || (w.closing && len(w.queue) == 0) {
			if w.err == nil {
				w.err = ErrWriterClosed
			}
			w.mu.Unlock()
			return
		}
		q := w.queue[0]
		w.queue[0] = queued{}
		w.queue = w.queue[1:]
		w.mu.Unlock()

		w.c.SetWriteDeadline(time.Now().Add(w.limits.WriteTimeout))
		err := w.c.writeFrame(q.payload)

		w.mu.Lock()
		n := len(q.payload) + headerLen
		if w.err == nil { // fail resets the counters
			w.bytes -= n
			if q.session != 0 {
				if w.perSess[q.session] -= n; w.perSess[q.session] <= 0 {
					delete(w.perSess, q.session)
				}
			}
		}
		w.mu.Unlock()
		if err != nil {
			w.fail(err)
			return
		}
	}
}
