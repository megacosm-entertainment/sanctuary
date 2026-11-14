package realm

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"net"
	"time"

	"sanctuary/internal/realmproto"
)

// Dialer opens one link to the gateway.
type Dialer func(ctx context.Context) (*realmproto.Conn, error)

// TLSDialer dials addr over TCP and completes the TLS handshake (mutual
// authentication, protocol.md §3) within timeout.
func TLSDialer(addr string, conf *tls.Config, timeout time.Duration) Dialer {
	return func(ctx context.Context) (*realmproto.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		d := tls.Dialer{NetDialer: &net.Dialer{}, Config: conf}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return realmproto.NewConn(c, realmproto.FromGateway), nil
	}
}

// Backoff is the reconnect schedule (protocol.md §8): exponential from Min
// to Max with full jitter, so realms that restart together do not
// reconnect in step.
type Backoff struct {
	Min time.Duration // default 1s
	Max time.Duration // default 60s
}

func (b Backoff) withDefaults() Backoff {
	if b.Min == 0 {
		b.Min = time.Second
	}
	if b.Max == 0 {
		b.Max = 60 * time.Second
	}
	return b
}

// delay is the wait before reconnect attempt n (0-based): uniformly random
// in [0, min(Max, Min*2^n)].
func (b Backoff) delay(n int) time.Duration {
	ceiling := b.Max
	if n < 30 { // beyond this the shift overflows; Max applies anyway
		if c := b.Min << n; c > 0 && c < b.Max {
			ceiling = c
		}
	}
	return rand.N(ceiling + 1)
}

// Run keeps the realm connected: it dials, serves the link, and when the
// link ends waits per the backoff and dials again. A link that stayed up
// longer than Max resets the schedule. Run returns only when ctx is
// cancelled.
func Run(ctx context.Context, dial Dialer, cfg Config, backoff Backoff) error {
	cfg = withDefaults(cfg)
	backoff = backoff.withDefaults()
	log := cfg.Log.With("realm", cfg.ID)
	attempt := 0
	for {
		start := time.Now()
		c, err := dial(ctx)
		if err == nil {
			err = Serve(ctx, c, cfg)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(start) > backoff.Max {
			attempt = 0
		}
		wait := backoff.delay(attempt)
		attempt++
		var rej *RejectedError
		switch {
		case err == nil:
			log.Info("gateway closed the link; reconnecting", "in", wait.Round(time.Millisecond))
		case errors.As(err, &rej):
			log.Warn("gateway rejected the realm; retrying", "reason", rej.Reason, "in", wait.Round(time.Millisecond))
		default:
			log.Warn("link to gateway failed; retrying", "err", err, "in", wait.Round(time.Millisecond))
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
