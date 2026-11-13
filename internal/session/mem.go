package session

import (
	"errors"
	"io"
	"sync"
	"time"
)

// MemTransport is the in-memory Transport: events pass as values over
// channels, with no bytes, sockets or ports. The test harness drives sessions
// through it, and stage 02 can use the same shape for an in-process link.
type MemTransport struct {
	meta Meta
	in   chan Inbound
	out  chan Outbound

	closeOnce sync.Once
	closed    chan struct{}
}

// MemClient is the client end of a MemTransport.
type MemClient struct {
	t *MemTransport
}

// NewMemPipe returns a connected transport and client. outBuffer is how many
// outbound events the client end buffers before WriteEvent blocks; a small
// value models a client that is slow to read.
func NewMemPipe(outBuffer int) (*MemTransport, *MemClient) {
	t := &MemTransport{
		meta:   Meta{Kind: "mem", Remote: "mem", Secure: true},
		in:     make(chan Inbound, 64),
		out:    make(chan Outbound, outBuffer),
		closed: make(chan struct{}),
	}
	return t, &MemClient{t: t}
}

func (t *MemTransport) Meta() Meta { return t.meta }

func (t *MemTransport) ReadEvent() (Inbound, error) {
	select {
	case ev := <-t.in:
		return ev, nil
	case <-t.closed:
		return nil, io.EOF
	}
}

func (t *MemTransport) WriteEvent(o Outbound) error {
	select {
	case <-t.closed:
		return ErrClosed
	default:
	}
	select {
	case t.out <- o:
		return nil
	case <-t.closed:
		return ErrClosed
	}
}

func (t *MemTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

// ErrTimeout is returned by MemClient.Next when nothing arrives in time.
var ErrTimeout = errors.New("timed out waiting for output")

// Send delivers an inbound event as if the client produced it.
func (c *MemClient) Send(ev Inbound) error {
	select {
	case c.t.in <- ev:
		return nil
	case <-c.t.closed:
		return ErrClosed
	}
}

// Next returns the next outbound event, io.EOF once the transport is closed
// and drained, or ErrTimeout.
func (c *MemClient) Next(timeout time.Duration) (Outbound, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case o := <-c.t.out:
		return o, nil
	case <-c.t.closed:
		select {
		case o := <-c.t.out:
			return o, nil
		default:
			return nil, io.EOF
		}
	case <-timer.C:
		return nil, ErrTimeout
	}
}

// Closed is closed when the server side closes the transport.
func (c *MemClient) Closed() <-chan struct{} { return c.t.closed }

// Hangup closes the transport from the client side.
func (c *MemClient) Hangup() { c.t.Close() }
