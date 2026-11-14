package realmproto

import (
	"bufio"
	"errors"
	"fmt"
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

// ErrIdle reports that no frame started within the idle time. Nothing was
// consumed, so the link is intact and the caller may read again.
var ErrIdle = errors.New("realmproto: link idle")

// RecvIdle reads the next message, waiting at most idle for one to begin.
// If none begins it returns ErrIdle with the stream untouched. A frame that
// has begun must complete within frameTimeout; one that stalls part-way
// leaves the stream unusable, and the error says so. It requires a stream
// with read deadlines (net.Conn, tls.Conn, net.Pipe).
func (c *Conn) RecvIdle(idle, frameTimeout time.Duration) (Message, error) {
	c.SetReadDeadline(time.Now().Add(idle))
	if _, err := c.br.Peek(1); err != nil {
		c.SetReadDeadline(time.Time{})
		if isTimeout(err) {
			return nil, ErrIdle
		}
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(frameTimeout))
	m, err := c.Recv()
	c.SetReadDeadline(time.Time{})
	if err != nil && isTimeout(err) {
		return nil, fmt.Errorf("realmproto: frame stalled part-way: %w", err)
	}
	return m, err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
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

// SendRaw writes payload as one frame without encoding or validating it.
// It exists so tests can play a broken or newer peer (unknown types,
// malformed JSON); production code sends only through Send.
func (c *Conn) SendRaw(payload []byte) error { return c.writeFrame(payload) }

func (c *Conn) writeFrame(payload []byte) error {
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
