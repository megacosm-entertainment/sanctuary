// Command sanctuary-gateway runs the gateway: telnet, telnet over TLS and
// WebSocket listeners, normalised into sessions and routed to a realm over
// the realm protocol (docs/protocol.md).
//
// Realms dial in over mTLS on -realm-listen. For a zero-configuration start
// the gateway also runs the stub realm in-process over the in-memory link
// (-stub-realm, on by default); the proxy and realm code are the same either
// way, only the transport between them differs.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"sanctuary/internal/echo"
	"sanctuary/internal/gateway"
	"sanctuary/internal/proxy"
	"sanctuary/internal/realm"
	"sanctuary/internal/realmproto"
	"sanctuary/internal/session"
)

func main() {
	var (
		name       = flag.String("name", "Sanctuary", "MUD name reported over MSSP")
		host       = flag.String("public-host", "localhost", "public hostname, advertised in MSSP")
		telnetAddr = flag.String("telnet", ":9000", "plain telnet listen address (empty disables)")
		tlsAddr    = flag.String("telnets", ":9010", "telnet+TLS listen address (empty disables)")
		wsAddr     = flag.String("ws", ":9020", "WebSocket listen address (empty disables)")
		wsPlain    = flag.Bool("ws-plain", false, "serve ws:// instead of wss:// (local development only)")
		origins    = flag.String("ws-origins", "", "comma-separated allowed browser origins (default: same-origin only)")
		certFile   = flag.String("tls-cert", "", "TLS certificate (PEM); a self-signed dev certificate is generated if unset")
		keyFile    = flag.String("tls-key", "", "TLS private key (PEM)")
		maxClients = flag.Int("max-clients", 1024, "maximum concurrent sessions")
		maxPerHost = flag.Int("max-per-host", 32, "maximum concurrent sessions per remote IP")
		logLevel   = flag.String("log-level", "info", "debug, info, warn or error")
		stubRealm  = flag.Bool("stub-realm", true, "run the stub realm in-process over the in-memory link")
		echoOnly   = flag.Bool("echo", false, "stage-01 behaviour: echo in the gateway, no realm protocol")

		realmListen = flag.String("realm-listen", "", "realm port, mTLS only, e.g. 127.0.0.1:9030 (empty disables); keep it off the internet")
		realmCert   = flag.String("realm-cert", "", "gateway identity certificate for the realm port (PEM)")
		realmKey    = flag.String("realm-key", "", "gateway identity key for the realm port (PEM)")
		realmPins   = flag.String("realm-pins", "", "comma-separated realm pins (sha256/...) or files of pins")
		realmCA     = flag.String("realm-ca", "", "PEM bundle of CAs whose client certificates realms may present")
		genIdentity = flag.String("gen-identity", "", "write a new realm-link identity to PREFIX.crt, .key and .pin, print the pin, and exit")
	)
	flag.Parse()
	if *genIdentity != "" {
		pin, err := realmproto.WriteIdentity(*genIdentity, "Sanctuary gateway")
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen-identity:", err)
			os.Exit(1)
		}
		fmt.Println(pin)
		return
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintln(os.Stderr, "bad -log-level:", err)
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	var cert tls.Certificate
	var err error
	if *certFile != "" || *keyFile != "" {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	} else {
		log.Warn("no -tls-cert given: using a generated self-signed certificate (development only)")
		cert, err = gateway.SelfSigned([]string{*host, "localhost", "127.0.0.1", "::1"})
	}
	if err != nil {
		log.Error("loading TLS certificate", "err", err)
		os.Exit(1)
	}

	var originList []string
	for _, o := range strings.Split(*origins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			originList = append(originList, o)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var handler session.Handler = echo.Handler{}
	var background sync.WaitGroup
	if !*echoOnly {
		hub := proxy.NewHub(proxy.HubConfig{Gateway: "dev", Log: log})
		handler = proxy.Handler{Hub: hub}
		if *stubRealm {
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
		if *realmListen != "" {
			conf, err := realmServerTLS(*realmCert, *realmKey, *realmPins, *realmCA)
			if err != nil {
				log.Error("realm port", "err", err)
				os.Exit(1)
			}
			l, err := net.Listen("tcp", *realmListen)
			if err != nil {
				log.Error("realm port", "err", err)
				os.Exit(1)
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
		if !*stubRealm && *realmListen == "" {
			log.Warn("no -stub-realm and no -realm-listen: players will find no realm")
		}
	}

	g := gateway.New(gateway.Config{
		Name:        *name,
		PublicHost:  *host,
		TelnetAddr:  *telnetAddr,
		TelnetsAddr: *tlsAddr,
		WSAddr:      *wsAddr,
		WSPlain:     *wsPlain,
		WSOrigins:   originList,
		TLS:         gateway.TLSConfig(cert),
		MaxClients:  *maxClients,
		MaxPerHost:  *maxPerHost,
		Handler:     handler,
		Log:         log,
	})
	if err := g.Listen(); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	err = g.Run(ctx)
	stop()
	background.Wait()
	if err != nil {
		log.Error("gateway stopped", "err", err)
		os.Exit(1)
	}
}

// realmServerTLS builds the realm port's TLS config from flags. At least one
// pin or a CA is required: the realm port never accepts any certificate.
func realmServerTLS(certFile, keyFile, pinList, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("-realm-listen needs -realm-cert and -realm-key (make them with -gen-identity)")
	}
	id, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pins, err := realmproto.ReadPins(strings.Split(pinList, ","))
	if err != nil {
		return nil, err
	}
	trust := realmproto.Trust{Pins: pins}
	if caFile != "" {
		if trust.CAs, err = realmproto.LoadCAs(caFile); err != nil {
			return nil, err
		}
	}
	return realmproto.ServerTLS(id, trust)
}
