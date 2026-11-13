// Package wstest is a minimal WebSocket client for tests and the smoke
// client: one implementation of the client side of RFC 6455 framing, so
// unit tests, end-to-end tests and cmd/gateway-smoke agree on the wire.
//
// Writes are synchronous and return errors. Over net.Pipe a write blocks
// until the server reads, so run the server side in its own goroutine.
package wstest

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout bounds every read.
const DefaultTimeout = 3 * time.Second

// Client is the client end of a WebSocket connection.
type Client struct {
	Conn    net.Conn
	br      *bufio.Reader
	Timeout time.Duration
}

// NewClient wraps a connection that is already past the handshake, such as
// one end of net.Pipe whose other end is a websocket.Conn.
func NewClient(nc net.Conn) *Client {
	return &Client{Conn: nc, br: bufio.NewReader(nc), Timeout: DefaultTimeout}
}

// DialOptions configures Dial.
type DialOptions struct {
	TLS       bool     // wss:// (certificate not verified: dev certificates are self-signed)
	Protocols []string // Sec-WebSocket-Protocol values; empty sends none
	Origin    string   // Origin header; empty sends none (a non-browser client)
}

// Dial connects and performs the upgrade handshake. It returns the response
// whatever its status; the Client is usable only when the status is 101.
func Dial(addr string, opts DialOptions) (*Client, *http.Response, error) {
	d := &net.Dialer{Timeout: DefaultTimeout}
	var nc net.Conn
	var err error
	if opts.TLS {
		nc, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		})
	} else {
		nc, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return nil, nil, err
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		nc.Close()
		return nil, nil, err
	}
	var req strings.Builder
	fmt.Fprintf(&req, "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n", addr)
	fmt.Fprintf(&req, "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n", base64.StdEncoding.EncodeToString(key))
	if len(opts.Protocols) > 0 {
		fmt.Fprintf(&req, "Sec-WebSocket-Protocol: %s\r\n", strings.Join(opts.Protocols, ", "))
	}
	if opts.Origin != "" {
		fmt.Fprintf(&req, "Origin: %s\r\n", opts.Origin)
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(nc, req.String()); err != nil {
		nc.Close()
		return nil, nil, err
	}
	c := NewClient(nc)
	nc.SetReadDeadline(time.Now().Add(c.Timeout))
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		nc.Close()
	}
	return c, resp, nil
}

// maskKey is fixed: masking exists to defeat proxy cache poisoning, which
// does not apply to tests.
var maskKey = [4]byte{0x12, 0x34, 0x56, 0x78}

// WriteFrame writes one masked frame, as RFC 6455 requires of clients.
func (c *Client) WriteFrame(fin bool, op byte, payload []byte) error {
	return c.write(fin, op, payload, true)
}

// WriteUnmaskedFrame writes a frame without masking: a protocol violation,
// for testing that the server rejects it.
func (c *Client) WriteUnmaskedFrame(op byte, payload []byte) error {
	return c.write(true, op, payload, false)
}

// Send writes one complete masked message.
func (c *Client) Send(op byte, payload []byte) error { return c.WriteFrame(true, op, payload) }

// WriteRaw writes bytes as they are, for malformed-header tests.
func (c *Client) WriteRaw(b []byte) error {
	_, err := c.Conn.Write(b)
	return err
}

func (c *Client) write(fin bool, op byte, payload []byte, masked bool) error {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	var maskBit byte
	if masked {
		maskBit = 0x80
	}
	frame := []byte{b0}
	switch n := len(payload); {
	case n <= 125:
		frame = append(frame, maskBit|byte(n))
	case n <= 0xffff:
		frame = append(frame, maskBit|126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(n))
	default:
		frame = append(frame, maskBit|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(n))
	}
	body := bytes.Clone(payload)
	if masked {
		frame = append(frame, maskKey[:]...)
		for i := range body {
			body[i] ^= maskKey[i%4]
		}
	}
	_, err := c.Conn.Write(append(frame, body...))
	return err
}

// ReadFrame reads one frame from the server.
func (c *Client) ReadFrame() (op byte, payload []byte, err error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.Timeout))
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return 0, nil, err
	}
	if h[1]&0x80 != 0 {
		return 0, nil, errors.New("server frame is masked")
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 1<<20 {
		return 0, nil, fmt.Errorf("frame length %d too large for a test", n)
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	return h[0] & 0x0f, payload, nil
}

// ReadUntil reads frames, concatenating the payloads of those with opcode
// op and skipping others, until the result contains want.
func (c *Client) ReadUntil(op byte, want string) (string, error) {
	var got []byte
	for !bytes.Contains(got, []byte(want)) {
		o, p, err := c.ReadFrame()
		if err != nil {
			return string(got), fmt.Errorf("waiting for %q: %w (received %q)", want, err, got)
		}
		if o == op {
			got = append(got, p...)
		}
	}
	return string(got), nil
}

// CloseCode extracts the status code from a close frame's payload.
func CloseCode(payload []byte) int {
	if len(payload) < 2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(payload))
}

// Close closes the connection without a closing handshake.
func (c *Client) Close() error { return c.Conn.Close() }
