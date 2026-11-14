// Package realmprototest plays one side of a realm link in tests: a fake
// gateway for testing a realm, or a fake realm for testing the gateway. It
// speaks real frames over realmproto.Pipe, so the code under test runs
// exactly as in production.
package realmprototest

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/realmproto"
)

// Timeout bounds every wait.
const Timeout = 2 * time.Second

type result struct {
	m   realmproto.Message
	err error
}

// Peer is the test's end of a link. A background goroutine reads every
// message into a channel; the test goroutine asserts (testing.md §7).
type Peer struct {
	T    testing.TB
	Conn *realmproto.Conn
	msgs chan result
}

// NewGateway returns a fake gateway and the realm's end of the link. Pass
// the second value to the realm under test.
func NewGateway(t testing.TB) (*Peer, *realmproto.Conn) {
	t.Helper()
	gw, realm := realmproto.Pipe()
	t.Cleanup(func() { realm.Close() })
	return start(t, gw), realm
}

// NewRealm returns a fake realm and the gateway's end of the link.
func NewRealm(t testing.TB) (*Peer, *realmproto.Conn) {
	t.Helper()
	gw, realm := realmproto.Pipe()
	t.Cleanup(func() { gw.Close() })
	return start(t, realm), gw
}

// Start makes a Peer of any link end, a real mTLS connection included, for
// tests that dial the realm port.
func Start(t testing.TB, c *realmproto.Conn) *Peer { return start(t, c) }

func start(t testing.TB, c *realmproto.Conn) *Peer {
	p := &Peer{T: t, Conn: c, msgs: make(chan result, 256)}
	go func() {
		for {
			m, err := c.Recv()
			p.msgs <- result{m, err}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { c.Close() })
	return p
}

// Send sends m, failing the test if it cannot.
func (p *Peer) Send(m realmproto.Message) {
	p.T.Helper()
	if err := p.Conn.Send(m); err != nil {
		p.T.Fatalf("send %s: %v", m.Type(), err)
	}
}

// Next returns the next message, failing the test on timeout or a read
// error.
func (p *Peer) Next() realmproto.Message {
	p.T.Helper()
	select {
	case r := <-p.msgs:
		if r.err != nil {
			p.T.Fatalf("link read failed: %v", r.err)
		}
		return r.m
	case <-time.After(Timeout):
		p.T.Fatalf("no message within %v", Timeout)
	}
	return nil
}

// Expect returns the next message as a T, failing the test if it is
// anything else.
func Expect[T realmproto.Message](p *Peer) T {
	p.T.Helper()
	m := p.Next()
	v, ok := m.(T)
	if !ok {
		var want T
		p.T.Fatalf("got %s %s, want %T", m.Type(), describe(m), want)
	}
	return v
}

// Until skips messages until one is a T and satisfies match (nil matches
// any), and returns it. For setup, such as reading past a banner; use
// Expect when the order is the behaviour under test.
func Until[T realmproto.Message](p *Peer, match func(T) bool) T {
	p.T.Helper()
	deadline := time.After(Timeout)
	var seen []string
	for {
		select {
		case r := <-p.msgs:
			if r.err != nil {
				p.T.Fatalf("link read failed while waiting (saw %s): %v", strings.Join(seen, ", "), r.err)
			}
			if v, ok := r.m.(T); ok && (match == nil || match(v)) {
				return v
			}
			seen = append(seen, r.m.Type())
		case <-deadline:
			var want T
			p.T.Fatalf("no matching %T within %v (saw %s)", want, Timeout, strings.Join(seen, ", "))
		}
	}
}

// ExpectClosed waits for the link to close (EOF or a closed-pipe error),
// failing if a message arrives first.
func (p *Peer) ExpectClosed() {
	p.T.Helper()
	select {
	case r := <-p.msgs:
		if r.err == nil {
			p.T.Fatalf("got %s %s, want the link closed", r.m.Type(), describe(r.m))
		}
		if !errors.Is(r.err, io.EOF) && !errors.Is(r.err, io.ErrClosedPipe) {
			p.T.Fatalf("link ended with %v, want a clean close", r.err)
		}
	case <-time.After(Timeout):
		p.T.Fatalf("link still open after %v", Timeout)
	}
}

// Handshake plays the gateway's side of the handshake: it expects a hello,
// answers welcome, and returns the hello.
func (p *Peer) Handshake() *realmproto.Hello {
	p.T.Helper()
	h := Expect[*realmproto.Hello](p)
	p.Send(&realmproto.Welcome{Version: realmproto.Version, Gateway: "test"})
	return h
}

// TextFor collects text messages for session id until a prompt for it
// arrives, and returns the text joined plus the prompt. Messages for other
// sessions are failures: tests drive one conversation at a time.
func (p *Peer) TextFor(id uint64) (string, *realmproto.Prompt) {
	p.T.Helper()
	var b strings.Builder
	for {
		switch m := p.Next().(type) {
		case *realmproto.Text:
			if m.Session != id {
				p.T.Fatalf("text for session %d while waiting for %d", m.Session, id)
			}
			b.WriteString(m.Text)
		case *realmproto.Prompt:
			if m.Session != id {
				p.T.Fatalf("prompt for session %d while waiting for %d", m.Session, id)
			}
			return b.String(), m
		default:
			p.T.Fatalf("got %s %s while collecting text for session %d", m.Type(), describe(m), id)
		}
	}
}

func describe(m realmproto.Message) string {
	if m == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%+v", m)
}
