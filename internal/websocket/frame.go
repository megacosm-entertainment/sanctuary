// Package websocket is a minimal RFC 6455 server: the upgrade handshake with
// explicit MudStandards subprotocol negotiation and an origin check, and a
// frame codec. No extensions are supported.
package websocket

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf8"
)

// Opcodes.
const (
	OpContinuation byte = 0x0
	OpText         byte = 0x1
	OpBinary       byte = 0x2
	OpClose        byte = 0x8
	OpPing         byte = 0x9
	OpPong         byte = 0xA
)

// Close codes.
const (
	CloseNormal        = 1000
	CloseGoingAway     = 1001
	CloseProtocolError = 1002
	CloseUnsupported   = 1003
	CloseInvalidData   = 1007
	ClosePolicy        = 1008
	CloseTooBig        = 1009
)

// MaxMessage caps an assembled message from the client.
const MaxMessage = 64 << 10

// CloseError reports a close frame from the peer, or a protocol violation
// that made us close.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string { return fmt.Sprintf("websocket closed: %d %s", e.Code, e.Reason) }

// Conn is a server-side WebSocket connection.
type Conn struct {
	nc  net.Conn
	br  *bufio.Reader
	wmu sync.Mutex

	closeOnce sync.Once
	closeSent bool

	WriteTimeout time.Duration
}

func newConn(nc net.Conn, br *bufio.Reader) *Conn {
	return &Conn{nc: nc, br: br, WriteTimeout: 15 * time.Second}
}

// NewServerConn wraps an already-upgraded connection. Tests use it with
// net.Pipe.
func NewServerConn(nc net.Conn) *Conn { return newConn(nc, bufio.NewReader(nc)) }

// RemoteAddr returns the peer address.
func (c *Conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// SetWriteDeadline sets the underlying deadline; used to cut stalled writes.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.nc.SetWriteDeadline(t) }

// ReadMessage returns the next complete text or binary message, answering
// pings and assembling fragments. Protocol violations close the connection
// with the appropriate code and return a *CloseError.
func (c *Conn) ReadMessage() (op byte, msg []byte, err error) {
	var assembling bool
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			var ce *CloseError
			if errors.As(err, &ce) {
				c.writeClose(ce.Code, ce.Reason)
				c.nc.Close()
			}
			return 0, nil, err
		}
		switch opcode {
		case OpPing:
			if err := c.WriteMessage(OpPong, payload); err != nil {
				return 0, nil, err
			}
			continue
		case OpPong:
			continue
		case OpClose:
			// RFC 6455 §5.5.1: an empty close payload is allowed; otherwise
			// it is a 2-byte code that may be sent on the wire, then a
			// UTF-8 reason. Anything else fails the connection.
			code, reason := CloseNormal, ""
			switch {
			case len(payload) == 1:
				return c.fail(CloseProtocolError, "close payload of one byte")
			case len(payload) >= 2:
				code = int(binary.BigEndian.Uint16(payload))
				if !sendableCloseCode(code) {
					return c.fail(CloseProtocolError, "invalid close code")
				}
				if !utf8.Valid(payload[2:]) {
					return c.fail(CloseInvalidData, "close reason is not UTF-8")
				}
				reason = string(payload[2:])
			}
			c.writeClose(CloseNormal, "")
			c.nc.Close()
			return 0, nil, &CloseError{Code: code, Reason: reason}
		case OpText, OpBinary:
			if assembling {
				return c.fail(CloseProtocolError, "new message before previous finished")
			}
			op = opcode
			msg = append(msg[:0], payload...)
			assembling = !fin
		case OpContinuation:
			if !assembling {
				return c.fail(CloseProtocolError, "unexpected continuation")
			}
			if len(msg)+len(payload) > MaxMessage {
				return c.fail(CloseTooBig, "message too large")
			}
			msg = append(msg, payload...)
			assembling = !fin
		default:
			return c.fail(CloseProtocolError, "unknown opcode")
		}
		if !assembling {
			if op == OpText && !utf8.Valid(msg) {
				return c.fail(CloseInvalidData, "text frame is not UTF-8")
			}
			return op, msg, nil
		}
	}
}

// sendableCloseCode reports whether a close code may appear in a close
// frame (RFC 6455 §7.4): the defined codes except the reserved 1004-1006
// and 1015, plus the registered (3000-3999) and private (4000-4999) ranges.
func sendableCloseCode(code int) bool {
	switch {
	case code >= 1000 && code <= 1003, code >= 1007 && code <= 1011:
		return true
	case code >= 3000 && code <= 4999:
		return true
	}
	return false
}

func (c *Conn) fail(code int, reason string) (byte, []byte, error) {
	c.writeClose(code, reason)
	c.nc.Close()
	return 0, nil, &CloseError{Code: code, Reason: reason}
}

func (c *Conn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.br, h[:]); err != nil {
		return
	}
	fin = h[0]&0x80 != 0
	if h[0]&0x70 != 0 {
		err = &CloseError{CloseProtocolError, "reserved bits set"}
		return
	}
	opcode = h[0] & 0x0f
	masked := h[1]&0x80 != 0
	length := uint64(h[1] & 0x7f)
	if !masked {
		err = &CloseError{CloseProtocolError, "client frames must be masked"}
		return
	}
	isControl := opcode&0x8 != 0
	switch length {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		length = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		length = binary.BigEndian.Uint64(b[:])
	}
	if isControl && (length > 125 || !fin) {
		err = &CloseError{CloseProtocolError, "invalid control frame"}
		return
	}
	if length > MaxMessage {
		err = &CloseError{CloseTooBig, "frame too large"}
		return
	}
	var key [4]byte
	if _, err = io.ReadFull(c.br, key[:]); err != nil {
		return
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= key[i&3]
	}
	return
}

// WriteMessage sends one unfragmented frame.
func (c *Conn) WriteMessage(op byte, data []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return net.ErrClosed
	}
	return c.writeFrameLocked(op, data)
}

func (c *Conn) writeFrameLocked(op byte, data []byte) error {
	hdr := make([]byte, 0, 10)
	hdr = append(hdr, 0x80|op)
	switch n := len(data); {
	case n <= 125:
		hdr = append(hdr, byte(n))
	case n <= 0xffff:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	if c.WriteTimeout > 0 {
		c.nc.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}
	buf := append(hdr, data...)
	_, err := c.nc.Write(buf)
	return err
}

func (c *Conn) writeClose(code int, reason string) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return
	}
	c.closeSent = true
	if len(reason) > 123 {
		reason = reason[:123]
	}
	p := binary.BigEndian.AppendUint16(nil, uint16(code))
	p = append(p, reason...)
	c.nc.SetWriteDeadline(time.Now().Add(time.Second))
	c.writeFrameLocked(OpClose, p)
}

// Close sends a close frame (best effort) and closes the connection.
func (c *Conn) Close(code int, reason string) error {
	var err error
	c.closeOnce.Do(func() {
		c.nc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		c.writeClose(code, reason)
		err = c.nc.Close()
	})
	return err
}
