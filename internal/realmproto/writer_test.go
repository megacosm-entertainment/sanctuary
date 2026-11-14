package realmproto_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/realmproto"
)

// A peer that never reads: net.Pipe writes block until read, so the
// writer's goroutine sticks on its first frame and everything after it
// queues.
func stalled(t *testing.T, limits realmproto.WriterLimits) (*realmproto.Writer, *realmproto.Conn) {
	t.Helper()
	gw, realm := realmproto.Pipe()
	w := realmproto.NewWriter(realm, limits)
	t.Cleanup(func() { gw.Close(); realm.Close(); w.Close() })
	return w, gw
}

func text(session uint64, n int) *realmproto.Text {
	return &realmproto.Text{Session: session, Text: strings.Repeat("x", n)}
}

// sendQuickly fails if Send blocks: the guarantee every caller relies on.
func sendQuickly(t *testing.T, w *realmproto.Writer, m realmproto.Message) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- w.Send(m) }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		t.Fatal("Writer.Send blocked on a peer that is not reading")
	}
	return nil
}

func TestWriterDeliversInOrder(t *testing.T) {
	gw, realm := realmproto.Pipe()
	w := realmproto.NewWriter(realm, realmproto.WriterLimits{})
	t.Cleanup(func() { gw.Close(); realm.Close(); w.Close() })
	for i := uint64(1); i <= 20; i++ {
		if err := w.Send(&realmproto.Pong{N: i}); err != nil {
			t.Fatalf("Send(pong %d): %v", i, err)
		}
	}
	for i := uint64(1); i <= 20; i++ {
		m, err := gw.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if p, ok := m.(*realmproto.Pong); !ok || p.N != i {
			t.Fatalf("message %d = %+v, want pong %d", i, m, i)
		}
	}
	// The peer has every frame, but the writer updates its counters just
	// after each write returns: poll briefly (testing.md §7).
	deadline := time.Now().Add(timeout)
	for {
		link, _ := w.Queued(0)
		if link == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Queued after delivery = %d bytes, want 0", link)
		}
		time.Sleep(time.Millisecond)
	}
}

// One session filling its share gets ErrSessionBacklog; the link stays up
// and other sessions can still send. This is what stops one player's input
// flood from cutting a realm off for everyone.
func TestSessionBacklogDoesNotAffectOthers(t *testing.T) {
	const share = 4096
	w, _ := stalled(t, realmproto.WriterLimits{SessionBytes: share, LinkBytes: 1 << 20})
	var err error
	for i := 0; i < 10 && err == nil; i++ {
		err = sendQuickly(t, w, text(1, 1000))
	}
	if !errors.Is(err, realmproto.ErrSessionBacklog) {
		t.Fatalf("Send past session 1's share = %v, want ErrSessionBacklog", err)
	}
	if err := sendQuickly(t, w, text(2, 1000)); err != nil {
		t.Fatalf("Send for session 2 after session 1 overflowed = %v, want nil", err)
	}
	if err := sendQuickly(t, w, &realmproto.Ping{N: 1}); err != nil {
		t.Fatalf("link-level Send after session overflow = %v, want nil", err)
	}
	select {
	case <-w.Done():
		t.Fatalf("writer stopped (%v) because of one session's backlog", w.Err())
	default:
	}
}

// When the whole link is full the peer is stuck: the writer stops and
// closes the link so the reader side notices too.
func TestLinkFullClosesLink(t *testing.T) {
	w, gw := stalled(t, realmproto.WriterLimits{SessionBytes: 1 << 20, LinkBytes: 8192})
	var err error
	for i := uint64(1); i <= 20 && err == nil; i++ {
		err = sendQuickly(t, w, text(i, 1000)) // spread over sessions: only the link limit applies
	}
	if !errors.Is(err, realmproto.ErrStalled) {
		t.Fatalf("Send past the link limit = %v, want ErrStalled", err)
	}
	select {
	case <-w.Done():
	case <-time.After(timeout):
		t.Fatal("writer still running after the link filled")
	}
	if !errors.Is(w.Err(), realmproto.ErrStalled) {
		t.Fatalf("Err = %v, want ErrStalled", w.Err())
	}
	if err := w.Send(&realmproto.Ping{}); !errors.Is(err, realmproto.ErrWriterClosed) {
		t.Fatalf("Send after stall = %v, want ErrWriterClosed", err)
	}
	// The link itself is closed, so the gateway end sees it.
	if _, err := gw.Recv(); err == nil {
		t.Fatal("peer can still read from a link the writer gave up on")
	}
}

// A peer that stops reading with little traffic is caught by the write
// deadline rather than by the queue limit.
func TestWriteTimeoutStopsWriter(t *testing.T) {
	w, _ := stalled(t, realmproto.WriterLimits{WriteTimeout: 50 * time.Millisecond})
	if err := w.Send(&realmproto.Ping{N: 1}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case <-w.Done():
	case <-time.After(timeout):
		t.Fatal("writer did not give up on a peer that stopped reading")
	}
	if !errors.Is(w.Err(), os.ErrDeadlineExceeded) {
		t.Fatalf("Err = %v, want a deadline error", w.Err())
	}
}

func TestInvalidMessageIsCallerError(t *testing.T) {
	w, _ := stalled(t, realmproto.WriterLimits{})
	if err := w.Send(&realmproto.Text{Session: 0}); !errors.Is(err, realmproto.ErrInvalidField) {
		t.Fatalf("Send(invalid) = %v, want ErrInvalidField", err)
	}
	if link, _ := w.Queued(0); link != 0 {
		t.Fatalf("an invalid message was queued (%d bytes)", link)
	}
	select {
	case <-w.Done():
		t.Fatal("an invalid message stopped the writer")
	default:
	}
}

// Close writes what is queued before returning, so a goodbye or a final
// session.close is not lost.
func TestCloseFlushes(t *testing.T) {
	gw, realm := realmproto.Pipe()
	t.Cleanup(func() { gw.Close(); realm.Close() })
	w := realmproto.NewWriter(realm, realmproto.WriterLimits{})
	for i := uint64(1); i <= 3; i++ {
		if err := w.Send(&realmproto.Pong{N: i}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	got := make(chan uint64, 3)
	go func() {
		for i := 0; i < 3; i++ {
			m, err := gw.Recv()
			if err != nil {
				return
			}
			if p, ok := m.(*realmproto.Pong); ok {
				got <- p.N
			}
		}
	}()
	w.Close()
	if err := w.Err(); err != nil {
		t.Fatalf("Err after clean Close = %v, want nil", err)
	}
	for i := uint64(1); i <= 3; i++ {
		select {
		case n := <-got:
			if n != i {
				t.Fatalf("flushed pong %d, want %d", n, i)
			}
		case <-time.After(timeout):
			t.Fatalf("pong %d not flushed by Close", i)
		}
	}
	if err := w.Send(&realmproto.Pong{}); !errors.Is(err, realmproto.ErrWriterClosed) {
		t.Fatalf("Send after Close = %v, want ErrWriterClosed", err)
	}
}

// A session that overflowed must still be closable.
func TestSessionCloseExemptFromSessionLimit(t *testing.T) {
	const share = 2048
	w, _ := stalled(t, realmproto.WriterLimits{SessionBytes: share, LinkBytes: 1 << 20})
	// Fill the share to within a few bytes, so that even a small
	// session.close would not fit without the exemption.
	closeMsg := &realmproto.SessionClose{Session: 1, Reason: realmproto.ClosedOverflow}
	closeSize := frameSize(t, closeMsg)
	fill := text(1, 0)
	fill.Text = strings.Repeat("x", share-frameSize(t, fill)-closeSize/2)
	if err := sendQuickly(t, w, fill); err != nil {
		t.Fatalf("setup: filling session 1's share: %v", err)
	}
	if _, used := w.Queued(1); share-used >= closeSize {
		t.Fatalf("setup: %d bytes left in the share, want fewer than a session.close (%d)", share-used, closeSize)
	}
	if err := sendQuickly(t, w, closeMsg); err != nil {
		t.Fatalf("Send(session.close) for an overflowed session = %v, want nil", err)
	}
}

// frameSize is what m costs in a Writer's accounting: header plus payload.
func frameSize(t *testing.T, m realmproto.Message) int {
	t.Helper()
	p, err := realmproto.Encode(m)
	if err != nil {
		t.Fatalf("Encode(%T): %v", m, err)
	}
	return len(p) + 4 // the uint32 length header
}
