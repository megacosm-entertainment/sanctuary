// Command sanctuary-gateway runs the gateway: telnet, telnet over TLS and
// WebSocket listeners, normalised into sessions and routed to a realm over
// the realm protocol (docs/protocol.md).
//
// Realms dial in over mTLS on -realm-listen. For a zero-configuration start
// the gateway also runs the stub realm in-process over the in-memory link
// (-stub-realm, on by default); the proxy and realm code are the same either
// way, only the transport between them differs.
//
// Every setting can come from a flag, an environment variable or an
// env-format config file (see internal/config): -telnet is SANCTUARY_TELNET.
// Run with -help for the list.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"sanctuary/internal/cli"
	"sanctuary/internal/config"
	"sanctuary/internal/echo"
	"sanctuary/internal/gateway"
	"sanctuary/internal/proxy"
	"sanctuary/internal/realm"
	"sanctuary/internal/realmproto"
	"sanctuary/internal/session"
)

// declare declares every setting. It is separate from main so tests can
// check the example config files in deploy/ against the real settings.
func declare() (*config.Set, settings) {
	s := config.New("sanctuary-gateway")
	return s, settings{
		name:       s.String("NAME", "Sanctuary", "MUD name reported over MSSP"),
		host:       s.String("PUBLIC_HOST", "localhost", "public hostname, advertised in MSSP"),
		telnetAddr: s.String("TELNET", ":9000", "plain telnet listen address (empty disables)"),
		tlsAddr:    s.String("TELNETS", ":9010", "telnet+TLS listen address (empty disables)"),
		wsAddr:     s.String("WS", ":9020", "WebSocket listen address (empty disables)"),
		wsPlain:    s.Bool("WS_PLAIN", false, "serve ws:// instead of wss:// (local development only)"),
		origins:    s.String("WS_ORIGINS", "", "comma-separated allowed browser origins (default: same-origin only)"),
		tlsCert:    s.Blob("TLS_CERT", false, "player TLS certificate; a self-signed dev certificate is generated if unset"),
		tlsKey:     s.Blob("TLS_KEY", true, "player TLS private key"),
		maxClients: s.Int("MAX_CLIENTS", 1024, "maximum concurrent sessions"),
		maxPerHost: s.Int("MAX_PER_HOST", 32, "maximum concurrent sessions per remote IP"),
		logLevel:   s.String("LOG_LEVEL", "info", "debug, info, warn or error"),
		stubRealm:  s.Bool("STUB_REALM", true, "run the stub realm in-process over the in-memory link"),
		echoOnly:   s.Bool("ECHO", false, "stage-01 behaviour: echo in the gateway, no realm protocol"),

		realmListen: s.String("REALM_LISTEN", "", "realm port, mTLS only, e.g. 127.0.0.1:9030 (empty disables); keep it off the internet"),
		realmCert:   s.Blob("REALM_CERT", false, "gateway identity certificate for the realm port"),
		realmKey:    s.Blob("REALM_KEY", true, "gateway identity key for the realm port"),
		realmPins:   s.String("REALM_PINS", "", "comma-separated realm pins (sha256/...) or files of pins"),
		realmCA:     s.Blob("REALM_CA", false, "CA bundle whose client certificates realms may present"),
	}
}

// settings are the gateway's operational settings.
type settings struct {
	name, host, telnetAddr, tlsAddr, wsAddr, origins, logLevel *string
	wsPlain, stubRealm, echoOnly                               *bool
	maxClients, maxPerHost                                     *int
	tlsCert, tlsKey                                            config.Blob
	realmListen, realmPins                                     *string
	realmCert, realmKey, realmCA                               config.Blob
}

func main() {
	s, o := declare()
	genIdentity := s.Flags().String("gen-identity", "", "write a new realm-link identity to PREFIX.crt, .key and .pin, print the pin, and exit")
	cli.Parse(s, os.Args[1:])
	if *genIdentity != "" {
		pin, err := realmproto.WriteIdentity(*genIdentity, "Sanctuary gateway")
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen-identity:", err)
			os.Exit(1)
		}
		fmt.Println(pin)
		return
	}
	log := cli.Logger(*o.logLevel)
	cli.Report(log, s)
	fail := func(what string, err error) {
		log.Error(what, "err", err)
		os.Exit(1)
	}

	var cert tls.Certificate
	var err error
	if o.tlsCert.Set() || o.tlsKey.Set() {
		cert, err = cli.KeyPair(o.tlsCert, o.tlsKey, "player TLS")
	} else {
		log.Warn("no TLS_CERT given: using a generated self-signed certificate (development only)")
		cert, err = gateway.SelfSigned([]string{*o.host, "localhost", "127.0.0.1", "::1"})
	}
	if err != nil {
		fail("loading TLS certificate", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var handler session.Handler = echo.Handler{}
	var background sync.WaitGroup
	if !*o.echoOnly {
		hub := proxy.NewHub(proxy.HubConfig{Gateway: "dev", Log: log})
		handler = proxy.Handler{Hub: hub}
		if *o.stubRealm {
			gwEnd, realmEnd := realmproto.Pipe()
			background.Add(2)
			go func() {
				defer background.Done()
				if err := hub.Serve(ctx, gwEnd); err != nil && ctx.Err() == nil {
					log.Error("stub realm link ended", "err", err)
				}
			}()
			go func() {
				defer background.Done()
				// Not ctx: a realm ends when its gateway says shutdown (or
				// the link closes), as a separate realm process would.
				// Sharing the signal would race the gateway's shutdown
				// message.
				err := realm.Serve(context.Background(), realmEnd, realm.Config{
					ID:      "stub",
					Name:    "Stub realm",
					Build:   "dev",
					Handler: realm.StubHandler,
					Log:     log.With("component", "realm"),
				})
				if err != nil && ctx.Err() == nil {
					log.Error("stub realm stopped", "err", err)
				}
			}()
		}
		if *o.realmListen != "" {
			id, err := cli.KeyPair(o.realmCert, o.realmKey, "realm port identity (REALM_CERT, REALM_KEY; make one with -gen-identity)")
			if err != nil {
				fail("realm port", err)
			}
			trust, err := cli.Trust(*o.realmPins, o.realmCA)
			if err != nil {
				fail("realm port", err)
			}
			conf, err := realmproto.ServerTLS(id, trust)
			if err != nil {
				fail("realm port", err)
			}
			l, err := net.Listen("tcp", *o.realmListen)
			if err != nil {
				fail("realm port", err)
			}
			log.Info("listening", "transport", "realm (mTLS)", "addr", l.Addr().String())
			background.Add(1)
			go func() {
				defer background.Done()
				if err := hub.ServeListener(ctx, l, proxy.ListenerConfig{TLS: conf}); err != nil {
					log.Error("realm listener stopped", "err", err)
				}
			}()
		}
		if !*o.stubRealm && *o.realmListen == "" {
			log.Warn("STUB_REALM off and no REALM_LISTEN: players will find no realm")
		}
	}

	g := gateway.New(gateway.Config{
		Name:        *o.name,
		PublicHost:  *o.host,
		TelnetAddr:  *o.telnetAddr,
		TelnetsAddr: *o.tlsAddr,
		WSAddr:      *o.wsAddr,
		WSPlain:     *o.wsPlain,
		WSOrigins:   cli.SplitList(*o.origins),
		TLS:         gateway.TLSConfig(cert),
		MaxClients:  *o.maxClients,
		MaxPerHost:  *o.maxPerHost,
		Handler:     handler,
		Log:         log,
	})
	if err := g.Listen(); err != nil {
		fail("listen", err)
	}
	err = g.Run(ctx)
	stop()
	background.Wait()
	if err != nil {
		fail("gateway stopped", err)
	}
}
