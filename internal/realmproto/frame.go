// Package realmproto implements the realm protocol between the gateway and a
// realm: length-prefixed frames carrying one JSON object each. The contract
// is docs/protocol.md; this package is its Go implementation, used by both
// sides.
package realmproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxFrame is the largest payload a frame may carry: 256 KiB, the gateway's
// per-session outbound budget (session.DefaultPolicy.MaxBytes), so no single
// message can exceed what one session may queue (protocol.md §2).
const MaxFrame = 256 << 10

// MaxHello caps the first message on a link, which arrives before the peer
// has proved anything beyond holding an allowlisted key (protocol.md §4).
const MaxHello = 4 << 10

const headerLen = 4 // uint32 big-endian payload length

// ErrFrameTooLarge reports a frame header announcing more than the limit.
// The payload is not read: the link must be closed.
var ErrFrameTooLarge = errors.New("realmproto: frame too large")

// ReadFrame reads one frame and returns its payload. A header announcing more
// than limit bytes fails with ErrFrameTooLarge before any payload is read,
// so a peer cannot make the reader allocate on its say-so. A zero-length
// frame is an error: every frame carries a JSON object.
func ReadFrame(r io.Reader, limit int) ([]byte, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if uint64(n) > uint64(limit) {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, n, limit)
	}
	if n == 0 {
		return nil, errors.New("realmproto: empty frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}

// WriteFrame writes payload as one frame, in a single Write call so that
// concurrent writers serialised by a mutex never interleave a header with
// another frame's payload.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("realmproto: empty frame")
	}
	if len(payload) > MaxFrame {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, len(payload), MaxFrame)
	}
	buf := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	copy(buf[headerLen:], payload)
	_, err := w.Write(buf)
	return err
}
