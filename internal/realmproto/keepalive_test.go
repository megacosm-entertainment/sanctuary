package realmproto_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"sanctuary/internal/realmproto"
)

// Test timings: short, but far enough apart that scheduling noise under
// -race cannot turn one into the other.
const (
	// Grace differs from Idle, so a test can tell which one was waited
	// after the ping (protocol.md §8: 30 s idle, then 10 s for an answer).
	kaIdle  = 30 * time.Millisecond
	kaGrace = 120 * time.Millisecond
)

// keepaliveLink returns the realm end with a keepalive reader, and the raw
// gateway end for the test to play.
func keepaliveLink(t *testing.T) (*realmproto.Keepalive, *realmproto.Conn, *realmproto.Writer, *realmproto.Conn) {
	t.Helper()
	gw, realm := realmproto.Pipe()
	w := realmproto.NewWriter(realm, realmproto.WriterLimits{})
	t.Cleanup(func() { gw.Close(); realm.Close(); w.Close() })
	return &realmproto.Keepalive{Idle: kaIdle, Grace: kaGrace}, realm, w, gw
}

type recvResult struct {
	m   realmproto.Message
	err error
}

func recvAsync(k *realmproto.Keepalive, c *realmproto.Conn, w *realmproto.Writer) <-chan recvResult {
	ch := make(chan recvResult, 1)
	go func() {
		m, err := k.Recv(c, w)
		ch <- recvResult{m, err}
	}()
	return ch
}

// A quiet link whose peer answers pings stays up.
func TestKeepalivePingsQuietLink(t *testing.T) {
	k, realm, w, gw := keepaliveLink(t)
	got := recvAsync(k, realm, w)
	// The gateway end sees a ping after the idle time and answers it.
	m, err := gw.Recv()
	if err != nil {
		t.Fatalf("gateway Recv: %v", err)
	}
	ping, ok := m.(*realmproto.Ping)
	if !ok {
		t.Fatalf("first message on a quiet link = %+v, want a ping", m)
	}
	if err := gw.Send(&realmproto.Pong{N: ping.N}); err != nil {
		t.Fatalf("pong: %v", err)
	}
	select {
	case r := <-got:
		if p, ok := r.m.(*realmproto.Pong); r.err != nil || !ok || p.N != ping.N {
			t.Fatalf("Recv = %+v, %v; want the pong for ping %d", r.m, r.err, ping.N)
		}
	case <-time.After(timeout):
		t.Fatal("Recv did not return the pong")
	}
}

// A peer that answers nothing is declared dead after Idle + Grace, even
// though the connection itself is still open.
func TestKeepaliveDetectsSilentPeer(t *testing.T) {
	k, realm, w, gw := keepaliveLink(t)
	start := time.Now()
	got := recvAsync(k, realm, w)
	if m, err := gw.Recv(); err != nil {
		t.Fatalf("gateway Recv: %v", err)
	} else if _, ok := m.(*realmproto.Ping); !ok {
		t.Fatalf("got %+v, want a ping", m)
	}
	// ...and never answer.
	select {
	case r := <-got:
		if !errors.Is(r.err, realmproto.ErrPeerSilent) {
			t.Fatalf("Recv from a silent peer = %v, want ErrPeerSilent", r.err)
		}
		if d := time.Since(start); d < kaIdle+kaGrace {
			t.Fatalf("declared dead after %v, before idle+grace (%v)", d, kaIdle+kaGrace)
		}
	case <-time.After(timeout):
		t.Fatal("silent peer never detected")
	}
}

// Any message counts as life, not only a pong.
func TestKeepaliveAnyMessageCounts(t *testing.T) {
	k, realm, w, gw := keepaliveLink(t)
	got := recvAsync(k, realm, w)
	if _, err := gw.Recv(); err != nil { // the ping
		t.Fatalf("gateway Recv: %v", err)
	}
	if err := gw.Send(&realmproto.Input{Session: 1, Text: "hi"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case r := <-got:
		if in, ok := r.m.(*realmproto.Input); r.err != nil || !ok || in.Text != "hi" {
			t.Fatalf("Recv = %+v, %v; want the input", r.m, r.err)
		}
	case <-time.After(timeout):
		t.Fatal("Recv did not return the input")
	}
}

// A frame that starts and then stalls is not "idle": the stream is broken
// mid-frame and the link must end.
func TestStalledFrameIsNotIdle(t *testing.T) {
	raw, other := net.Pipe()
	t.Cleanup(func() { raw.Close(); other.Close() })
	realm := realmproto.NewConn(other, realmproto.FromGateway)
	got := make(chan error, 1)
	go func() {
		_, err := realm.RecvIdle(time.Second, kaGrace)
		got <- err
	}()
	// Half a frame header, then nothing.
	go raw.Write([]byte{0, 0})
	select {
	case err := <-got:
		if err == nil || errors.Is(err, realmproto.ErrIdle) {
			t.Fatalf("RecvIdle after half a header = %v, want a stalled-frame error", err)
		}
	case <-time.After(timeout):
		t.Fatal("RecvIdle never gave up on a stalled frame")
	}
}

func TestRecvIdleLeavesStreamIntact(t *testing.T) {
	gw, realm := realmproto.Pipe()
	t.Cleanup(func() { gw.Close(); realm.Close() })
	if _, err := realm.RecvIdle(kaIdle, kaGrace); !errors.Is(err, realmproto.ErrIdle) {
		t.Fatalf("RecvIdle on a quiet link = %v, want ErrIdle", err)
	}
	go gw.Send(&realmproto.Pong{N: 9})
	m, err := realm.RecvIdle(time.Second, time.Second)
	if p, ok := m.(*realmproto.Pong); err != nil || !ok || p.N != 9 {
		t.Fatalf("RecvIdle after an idle timeout = %+v, %v; want the pong intact", m, err)
	}
}
