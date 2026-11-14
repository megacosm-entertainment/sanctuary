package websocket

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	"sanctuary/internal/gmcp"
	"sanctuary/internal/sanitize"
	"sanctuary/internal/session"
)

// GMCPTransport is the gmcp.mudstandards.org subprotocol as a
// session.Transport: player text travels in binary frames (UTF-8 with ANSI
// codes) and GMCP messages in text frames.
type GMCPTransport struct {
	c       *Conn
	meta    session.Meta
	log     *slog.Logger
	pending []session.Inbound
}

func NewGMCPTransport(c *Conn, meta session.Meta, log *slog.Logger) *GMCPTransport {
	return &GMCPTransport{c: c, meta: meta, log: log}
}

func (t *GMCPTransport) Meta() session.Meta { return t.meta }

func (t *GMCPTransport) ReadEvent() (session.Inbound, error) {
	for len(t.pending) == 0 {
		op, msg, err := t.c.ReadMessage()
		if err != nil {
			return nil, err
		}
		switch op {
		case OpBinary:
			// One or more lines of input. A trailing newline is optional.
			s := strings.TrimRight(string(msg), "\r\n")
			for _, ln := range strings.Split(s, "\n") {
				ln = strings.TrimSuffix(ln, "\r")
				if len(ln) > 4096 {
					ln = ln[:4096]
				}
				t.pending = append(t.pending, session.Line{Text: sanitize.Untrusted(ln)})
			}
		case OpText:
			pkg, data, err := gmcp.Parse(msg)
			if err != nil {
				t.log.Warn("rejected malformed GMCP", "err", err, "bytes", len(msg))
				continue
			}
			t.log.Info("GMCP received", "package", pkg, "bytes", len(data))
			t.pending = append(t.pending, session.GMCP{Package: pkg, Data: data})
		}
	}
	ev := t.pending[0]
	t.pending = t.pending[1:]
	return ev, nil
}

func (t *GMCPTransport) WriteEvent(o session.Outbound) error {
	switch v := o.(type) {
	case session.Text:
		return t.c.WriteMessage(OpBinary, crlf(v.Text))
	case session.Prompt:
		return t.c.WriteMessage(OpBinary, crlf(v.Text))
	case session.GMCPOut:
		msg, err := gmcp.Format(v.Package, v.Data)
		if err != nil {
			t.log.Warn("dropped invalid outbound GMCP", "err", err)
			return nil
		}
		return t.c.WriteMessage(OpText, msg)
	case session.InputMode:
		// No wire equivalent in this subprotocol; web clients learn input
		// masking through GMCP (Char.Login) in stage 03.
		return nil
	}
	return nil
}

func (t *GMCPTransport) Close() error { return t.c.Close(CloseGoingAway, "") }

func crlf(s string) []byte {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

// Stream presents the binary frames of a telnet.mudstandards.org connection
// as a byte stream, so the telnet transport can run over it unchanged. Each
// Write becomes one binary frame; text frames are a protocol error.
type Stream struct {
	c   *Conn
	buf bytes.Buffer
}

func NewStream(c *Conn) *Stream { return &Stream{c: c} }

func (s *Stream) Read(p []byte) (int, error) {
	for s.buf.Len() == 0 {
		op, msg, err := s.c.ReadMessage()
		if err != nil {
			var ce *CloseError
			if errors.As(err, &ce) {
				return 0, io.EOF
			}
			return 0, err
		}
		if op != OpBinary {
			s.c.fail(CloseUnsupported, "telnet subprotocol carries binary frames only")
			return 0, io.EOF
		}
		s.buf.Write(msg)
	}
	return s.buf.Read(p)
}

func (s *Stream) Write(p []byte) (int, error) {
	if err := s.c.WriteMessage(OpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error { return s.c.SetWriteDeadline(t) }

func (s *Stream) Close() error { return s.c.Close(CloseGoingAway, "") }
