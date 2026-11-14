package realmproto

import (
	"errors"
	"time"
)

// ErrPeerSilent: the peer sent nothing, not even a pong, within the
// keepalive window. The link is dead even if TCP has not noticed yet.
var ErrPeerSilent = errors.New("realmproto: peer silent past keepalive")

// Keepalive implements protocol.md §8 for one link's reader: after Idle
// with nothing received it sends a ping, and if nothing at all arrives
// within Grace after that, the link is declared dead. Any message counts as
// a sign of life, not only the pong.
type Keepalive struct {
	Idle  time.Duration // default 30s
	Grace time.Duration // default 10s; also the limit for one frame to arrive
	n     uint64        // last ping number sent
}

func (k *Keepalive) defaults() {
	if k.Idle == 0 {
		k.Idle = 30 * time.Second
	}
	if k.Grace == 0 {
		k.Grace = 10 * time.Second
	}
}

// Recv returns the next message from c, sending pings through w while the
// link is quiet.
func (k *Keepalive) Recv(c *Conn, w *Writer) (Message, error) {
	k.defaults()
	wait, pinged := k.Idle, false
	for {
		m, err := c.RecvIdle(wait, k.Grace)
		if !errors.Is(err, ErrIdle) {
			return m, err
		}
		if pinged {
			return nil, ErrPeerSilent
		}
		k.n++
		if err := w.Send(&Ping{N: k.n}); err != nil {
			return nil, err
		}
		wait, pinged = k.Grace, true
	}
}
