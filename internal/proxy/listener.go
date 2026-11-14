package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"sanctuary/internal/realmproto"
)

// ListenerConfig configures the realm listener (design §04, "Registration
// must not be a saturation or attack surface"). Zero fields take defaults.
type ListenerConfig struct {
	// TLS must come from realmproto.ServerTLS: TLS 1.3, client certificate
	// required and verified.
	TLS *tls.Config
	// HandshakeTimeout bounds the TLS handshake; default 5s. Until it
	// completes a connection holds nothing but a pending slot.
	HandshakeTimeout time.Duration
	// MaxPending caps connections still in the TLS handshake; default 16.
	MaxPending int
	// PerSourcePerMinute caps connection attempts from one source address;
	// default 30. A crash-looping realm backs off well below this; a
	// scanner does not.
	PerSourcePerMinute int
}

func (c ListenerConfig) withDefaults() ListenerConfig {
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 5 * time.Second
	}
	if c.MaxPending == 0 {
		c.MaxPending = 16
	}
	if c.PerSourcePerMinute == 0 {
		c.PerSourcePerMinute = 30
	}
	return c
}

// ServeListener accepts realm links on l until ctx is cancelled, then
// closes l and waits for every link it started to end.
func (h *Hub) ServeListener(ctx context.Context, l net.Listener, lc ListenerConfig) error {
	if lc.TLS == nil || lc.TLS.ClientAuth != tls.RequireAnyClientCert || lc.TLS.VerifyConnection == nil {
		// Refuse rather than serve a realm port anyone could register on.
		return errors.New("proxy: realm listener needs a TLS config from realmproto.ServerTLS")
	}
	lc = lc.withDefaults()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()

	pending := make(chan struct{}, lc.MaxPending)
	limiter := newRateLimiter(lc.PerSourcePerMinute, time.Minute)
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		nc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		host := remoteHost(nc)
		if !limiter.allow(host) {
			h.log.Warn("realm connection refused: rate limit", "remote", host)
			nc.Close()
			continue
		}
		select {
		case pending <- struct{}{}:
		default:
			h.log.Warn("realm connection refused: too many handshakes in progress", "remote", host)
			nc.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc, ok := h.handshakeTLS(ctx, nc, lc)
			<-pending
			if !ok {
				return
			}
			conn := realmproto.NewConn(tc, realmproto.FromRealm)
			if err := h.Serve(ctx, conn); err != nil && ctx.Err() == nil {
				h.log.Info("realm link closed", "remote", host, "err", err)
			}
		}()
	}
}

func (h *Hub) handshakeTLS(ctx context.Context, nc net.Conn, lc ListenerConfig) (*tls.Conn, bool) {
	tc := tls.Server(nc, lc.TLS)
	hctx, cancel := context.WithTimeout(ctx, lc.HandshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		// Logged at warn with the cause: an untrusted certificate here is
		// either a misconfigured realm or someone probing the port.
		h.log.Warn("realm TLS handshake failed", "remote", remoteHost(nc), "err", err)
		nc.Close()
		return nil, false
	}
	return tc, true
}

func remoteHost(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

// rateLimiter allows n events per window per key (a sliding log, which is
// exact and cheap at the handful of sources a realm port sees).
type rateLimiter struct {
	n      int
	window time.Duration
	mu     sync.Mutex
	seen   map[string][]time.Time
	now    func() time.Time
}

func newRateLimiter(n int, window time.Duration) *rateLimiter {
	return &rateLimiter{n: n, window: window, seen: map[string][]time.Time{}, now: time.Now}
}

func (r *rateLimiter) allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	cutoff := now.Add(-r.window)
	times := r.seen[key]
	i := 0
	for i < len(times) && !times[i].After(cutoff) {
		i++
	}
	times = times[i:]
	if len(times) >= r.n {
		r.seen[key] = times
		return false
	}
	r.seen[key] = append(times, now)
	// Forget keys with nothing recent, so the map cannot grow without bound.
	if len(r.seen) > 1024 {
		for k, ts := range r.seen {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(r.seen, k)
			}
		}
	}
	return true
}
