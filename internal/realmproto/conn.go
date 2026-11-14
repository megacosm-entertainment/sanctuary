package realmproto

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"
)

// Conn is one end of a realm link: it reads messages the peer sends and
// writes this side's messages, one frame each. Recv is for one goroutine;
// Send may be called from several and is serialised.
type Conn struct {
	rw   io.ReadWriteCloser
	br   *bufio.Reader
	peer Sender // who sends the messages this end reads

	wmu sync.Mutex
}

// NewConn wraps a byte stream (in production, an mTLS connection). peer is
// the side at the other end: FromRealm on the gateway, FromGateway in a
// realm.
func NewConn(rw io.ReadWriteCloser, peer Sender) *Conn {
	return &Conn{rw: rw, br: bufio.NewReader(rw), peer: peer}
}

// Recv reads the next message, with frames capped at MaxFrame.
func (c *Conn) Recv() (Message, error) { return c.RecvLimit(MaxFrame) }

// RecvLimit reads the next message with a tighter frame limit, for the
// handshake (MaxHello).
func (c *Conn) RecvLimit(limit int) (Message, error) {
	payload, err := ReadFrame(c.br, limit)
	if err != nil {
		return nil, err
	}
	return Decode(payload, c.peer)
}

// Send encodes and writes one message.
func (c *Conn) Send(m Message) error {
	payload, err := Encode(m)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return WriteFrame(c.rw, payload)
}

// SetReadDeadline and SetWriteDeadline apply when the underlying stream
// supports deadlines (net.Conn, tls.Conn); otherwise they do nothing.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if d, ok := c.rw.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.rw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

// Close closes the underlying stream, unblocking Recv and Send.
func (c *Conn) Close() error { return c.rw.Close() }

// Pipe returns the two ends of an in-memory link (protocol.md §3): the
// gateway's end reads what the realm sends, and the other way round. It
// carries the same frames as a socket, so everything above it is the code
// that runs in production.
func Pipe() (gateway, realm *Conn) {
	g, r := net.Pipe()
	return NewConn(g, FromRealm), NewConn(r, FromGateway)
}
