// Package gateway owns the player-facing listeners and normalises every
// connection into a session.Session served by a session.Handler.
package gateway

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"sanctuary/internal/session"
	"sanctuary/internal/telnet"
	"sanctuary/internal/websocket"
)

//go:embed webclient
var webclient embed.FS

// Config configures the gateway. Empty listen addresses disable a listener.
type Config struct {
	Name        string // MUD name for MSSP
	PublicHost  string // hostname advertised in MSSP WEBSOCKET
	TelnetAddr  string // plain telnet, e.g. ":9000"
	TelnetsAddr string // telnet over TLS, e.g. ":9010"
	WSAddr      string // WebSocket, e.g. ":9020"
	// WSPlain serves ws:// instead of wss://. For local development only.
	WSPlain    bool
	WSOrigins  []string // allowed browser origins; empty means same-origin
	TLS        *tls.Config
	MaxClients int // total sessions; 0 = unlimited
	MaxPerHost int // sessions per remote IP; 0 = unlimited
	// HandshakeTimeout bounds a telnet+TLS handshake; default 10s. A client
	// that stalls mid-handshake holds a per-host slot until then.
	HandshakeTimeout time.Duration
	Policy           session.QueuePolicy
	Handler          session.Handler
	Log              *slog.Logger
}

// Gateway runs the listeners.
type Gateway struct {
	cfg     Config
	log     *slog.Logger
	reg     *session.Registry
	started time.Time

	mu         sync.Mutex
	listeners  []net.Listener
	wsListener net.Listener // also in listeners; closed by httpSrv.Shutdown
	httpSrv    *http.Server
}

func New(cfg Config) *Gateway {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.Policy == (session.QueuePolicy{}) {
		cfg.Policy = session.DefaultPolicy
	}
	return &Gateway{cfg: cfg, log: cfg.Log, reg: session.NewRegistry(), started: time.Now()}
}

// Registry exposes live sessions (for tests and diagnostics).
func (g *Gateway) Registry() *session.Registry { return g.reg }

// Addrs returns the bound listener addresses, in the order telnet, telnets,
// ws, skipping disabled ones. Useful when listening on port 0.
func (g *Gateway) Addrs() []net.Addr {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]net.Addr, len(g.listeners))
	for i, l := range g.listeners {
		out[i] = l.Addr()
	}
	return out
}

// Listen binds every configured listener. Run serves them.
func (g *Gateway) Listen() error {
	if (g.cfg.TelnetsAddr != "" || (g.cfg.WSAddr != "" && !g.cfg.WSPlain)) && g.cfg.TLS == nil {
		return errors.New("TLS listeners configured without a TLS config")
	}
	bind := func(addr string) (net.Listener, error) {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		g.listeners = append(g.listeners, l)
		return l, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, addr := range []string{g.cfg.TelnetAddr, g.cfg.TelnetsAddr, g.cfg.WSAddr} {
		if addr == "" {
			continue
		}
		l, err := bind(addr)
		if err == nil && i == 2 { // by position: addresses may be equal (":0")
			g.wsListener = l
		}
		if err != nil {
			for _, l := range g.listeners {
				l.Close()
			}
			g.listeners = nil
			return err
		}
	}
	return nil
}

// Run serves until ctx is cancelled, then shuts down: listeners close,
// handlers see ctx cancelled and say goodbye, and Run waits (bounded) for
// sessions to drain.
func (g *Gateway) Run(ctx context.Context) error {
	g.mu.Lock()
	ls := append([]net.Listener(nil), g.listeners...)
	g.mu.Unlock()

	var wg sync.WaitGroup
	i := 0
	if g.cfg.TelnetAddr != "" {
		l := ls[i]
		i++
		wg.Add(1)
		go func() { defer wg.Done(); g.acceptTelnet(ctx, l, "telnet", false) }()
		g.log.Info("listening", "transport", "telnet", "addr", l.Addr().String())
	}
	if g.cfg.TelnetsAddr != "" {
		l := tls.NewListener(ls[i], g.cfg.TLS)
		i++
		wg.Add(1)
		go func() { defer wg.Done(); g.acceptTelnet(ctx, l, "telnet+tls", true) }()
		g.log.Info("listening", "transport", "telnet+tls", "addr", l.Addr().String())
	}
	if g.cfg.WSAddr != "" {
		l := ls[i]
		srv := g.newHTTPServer(ctx)
		g.mu.Lock()
		g.httpSrv = srv
		g.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if g.cfg.WSPlain {
				err = srv.Serve(l)
			} else {
				err = srv.ServeTLS(l, "", "")
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				g.log.Error("websocket listener stopped", "err", err)
			}
		}()
		scheme := "wss"
		if g.cfg.WSPlain {
			scheme = "ws"
			g.log.Warn("serving plaintext WebSocket: development only; WSS is the deployed form")
		}
		g.log.Info("listening", "transport", scheme, "addr", l.Addr().String())
	}

	<-ctx.Done()
	g.log.Info("shutting down", "sessions", g.reg.Count())
	g.mu.Lock()
	srv := g.httpSrv
	for _, l := range g.listeners {
		// The HTTP server's Shutdown closes its own listener; closing it
		// here first makes Serve report an error instead of ErrServerClosed.
		if srv != nil && l == g.wsListener {
			continue
		}
		l.Close()
	}
	g.mu.Unlock()
	if srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		srv.Shutdown(sctx) // hijacked WebSocket conns are not tracked by Shutdown
		cancel()
	}
	wg.Wait()

	done := make(chan struct{})
	go func() { g.reg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(g.cfg.Policy.DrainTimeout + 2*time.Second):
		g.log.Warn("sessions did not drain in time", "remaining", g.reg.Count())
	}
	return nil
}

func (g *Gateway) acceptTelnet(ctx context.Context, l net.Listener, kind string, secure bool) {
	for {
		nc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			g.log.Warn("accept failed", "transport", kind, "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go g.serveTelnet(ctx, nc, kind, secure)
	}
}

func (g *Gateway) serveTelnet(ctx context.Context, nc net.Conn, kind string, secure bool) {
	host := hostOf(nc.RemoteAddr())
	if !g.reg.Reserve(host, g.cfg.MaxClients, g.cfg.MaxPerHost) {
		g.log.Warn("connection refused: limit reached", "transport", kind, "remote", host)
		nc.SetWriteDeadline(time.Now().Add(2 * time.Second))
		nc.Write([]byte("Too many connections. Please try again later.\r\n"))
		nc.Close()
		return
	}
	if tc, ok := nc.(*tls.Conn); ok {
		tc.SetDeadline(time.Now().Add(g.cfg.HandshakeTimeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			g.log.Info("TLS handshake failed", "remote", host, "err", err)
			nc.Close()
			g.reg.Release(host)
			return
		}
		tc.SetDeadline(time.Time{})
	}
	meta := session.Meta{Kind: kind, Remote: nc.RemoteAddr().String(), Secure: secure}
	g.serveConn(ctx, host, meta, nc)
}

// serveConn runs a telnet transport over any byte stream.
func (g *Gateway) serveConn(ctx context.Context, host string, meta session.Meta, rw telnetStream) {
	id := session.AllocID()
	tc := telnet.NewConn(rw, telnet.Config{
		Meta: meta,
		MSSP: g.msspVars,
		Log:  g.connLog(id, meta),
	})
	if err := tc.Start(); err != nil {
		tc.Close()
		g.reg.Release(host)
		return
	}
	s := session.NewWithID(id, tc, g.cfg.Policy, g.log)
	g.reg.Serve(ctx, host, s, g.cfg.Handler)
}

type telnetStream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

func (g *Gateway) newHTTPServer(ctx context.Context) *http.Server {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webclient, "webclient")
	files := http.FileServer(http.FS(static))
	origins := websocket.OriginPolicy{Allowed: g.cfg.WSOrigins}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			files.ServeHTTP(w, r)
			return
		}
		g.serveWebSocket(ctx, w, r, origins)
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(g.log.Handler(), slog.LevelDebug),
	}
	if !g.cfg.WSPlain {
		srv.TLSConfig = g.cfg.TLS.Clone()
		srv.TLSConfig.NextProtos = []string{"http/1.1"} // upgrades need HTTP/1.1
	}
	return srv
}

func (g *Gateway) serveWebSocket(ctx context.Context, w http.ResponseWriter, r *http.Request, origins websocket.OriginPolicy) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !g.reg.Reserve(host, g.cfg.MaxClients, g.cfg.MaxPerHost) {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	wc, proto, err := websocket.Upgrade(w, r, origins)
	if err != nil {
		g.log.Info("websocket upgrade refused", "remote", host, "err", err)
		g.reg.Release(host)
		return
	}
	meta := session.Meta{Remote: r.RemoteAddr, Secure: r.TLS != nil}
	switch proto {
	case websocket.ProtoGMCP:
		meta.Kind = "ws/gmcp"
		id := session.AllocID()
		t := websocket.NewGMCPTransport(wc, meta, g.connLog(id, meta))
		s := session.NewWithID(id, t, g.cfg.Policy, g.log)
		g.reg.Serve(ctx, host, s, g.cfg.Handler)
	case websocket.ProtoTelnet:
		meta.Kind = "ws/telnet"
		g.serveConn(ctx, host, meta, websocket.NewStream(wc))
	}
}

// connLog is the logger for a transport, with the same session, transport
// and remote fields the session's own log lines carry.
func (g *Gateway) connLog(id uint64, meta session.Meta) *slog.Logger {
	return g.log.With("session", id, "transport", meta.Kind, "remote", meta.Remote)
}

// msspVars reports MSSP variables at request time.
func (g *Gateway) msspVars() []telnet.MSSPVar {
	v := []telnet.MSSPVar{
		{Name: "NAME", Values: []string{g.cfg.Name}},
		{Name: "PLAYERS", Values: []string{strconv.Itoa(g.reg.Count())}},
		{Name: "UPTIME", Values: []string{strconv.FormatInt(g.started.Unix(), 10)}},
		{Name: "CODEBASE", Values: []string{"Sanctuary"}},
		{Name: "FAMILY", Values: []string{"Custom"}},
	}
	if p := portOf(g.cfg.TelnetAddr); p != "" {
		v = append(v, telnet.MSSPVar{Name: "PORT", Values: []string{p}})
	}
	if p := portOf(g.cfg.TelnetsAddr); p != "" {
		v = append(v, telnet.MSSPVar{Name: "SSL", Values: []string{p}})
	}
	if p := portOf(g.cfg.WSAddr); p != "" && g.cfg.PublicHost != "" {
		scheme := "wss"
		if g.cfg.WSPlain {
			scheme = "ws"
		}
		v = append(v,
			telnet.MSSPVar{Name: "WEBSOCKET", Values: []string{fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(g.cfg.PublicHost, p))}},
			telnet.MSSPVar{Name: "WEBSOCKET_SUBPROTOCOLS", Values: websocket.Supported},
		)
	}
	return v
}

func portOf(addr string) string {
	if addr == "" {
		return ""
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil || p == "0" {
		return ""
	}
	return p
}

func hostOf(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}
