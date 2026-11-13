// Command sentience-gateway is the stage-01 gateway prototype: telnet,
// telnet over TLS and WebSocket, normalised into one session abstraction,
// echoing input back.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"sentience/internal/echo"
	"sentience/internal/gateway"
)

func main() {
	var (
		name       = flag.String("name", "Sentience", "MUD name reported over MSSP")
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
	)
	flag.Parse()

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
		Handler:     echo.Handler{},
		Log:         log,
	})
	if err := g.Listen(); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := g.Run(ctx); err != nil {
		log.Error("gateway stopped", "err", err)
		os.Exit(1)
	}
}
