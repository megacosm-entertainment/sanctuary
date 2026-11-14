// Command sanctuary-realm runs a realm as its own process: it dials the
// gateway's realm port over mTLS (docs/protocol.md §3), registers, serves
// the players the gateway routes to it, and reconnects with backoff when
// the link drops. In stage 02 the realm is the stub (the echo handler).
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
	"syscall"
	"time"

	"sanctuary/internal/realm"
	"sanctuary/internal/realmproto"
)

func main() {
	var (
		gateway     = flag.String("gateway", "127.0.0.1:9030", "gateway realm port to dial")
		serverName  = flag.String("gateway-name", "", "gateway name to check in CA mode (default: the host in -gateway)")
		gatewayPins = flag.String("gateway-pins", "", "comma-separated gateway pins (sha256/...) or files of pins")
		gatewayCA   = flag.String("gateway-ca", "", "PEM bundle of CAs that may issue the gateway's certificate")
		certFile    = flag.String("cert", "", "this realm's identity certificate (PEM)")
		keyFile     = flag.String("key", "", "this realm's identity key (PEM)")
		id          = flag.String("id", "stub", "realm id: 1-32 of [a-z0-9-], unique per gateway")
		name        = flag.String("name", "Stub realm", "name shown in the gateway's realm list")
		build       = flag.String("build", "dev", "build identity reported to the gateway")
		logLevel    = flag.String("log-level", "info", "debug, info, warn or error")
		genIdentity = flag.String("gen-identity", "", "write a new realm-link identity to PREFIX.crt, .key and .pin, print the pin, and exit")
	)
	flag.Parse()
	if *genIdentity != "" {
		pin, err := realmproto.WriteIdentity(*genIdentity, "Sanctuary realm "+*id)
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

	conf, err := clientTLS(*certFile, *keyFile, *gatewayPins, *gatewayCA, *serverName, *gateway)
	if err != nil {
		log.Error("realm link TLS", "err", err)
		os.Exit(1)
	}

	// SIGTERM ends the realm. The drain sequence (protocol.md §8: tell
	// players, save, hand them back) arrives later in stage 02; for now the
	// gateway tells players the realm has gone.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("realm starting", "realm", *id, "gateway", *gateway)
	err = realm.Run(ctx, realm.TLSDialer(*gateway, conf, 10*time.Second), realm.Config{
		ID:      *id,
		Name:    *name,
		Build:   *build,
		Handler: realm.StubHandler,
		Log:     log,
	}, realm.Backoff{})
	if err != nil && ctx.Err() == nil {
		log.Error("realm stopped", "err", err)
		os.Exit(1)
	}
	log.Info("realm stopped")
}

func clientTLS(certFile, keyFile, pinList, caFile, serverName, addr string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("-cert and -key are required (make them with -gen-identity)")
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
	if serverName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			serverName = host
		}
	}
	return realmproto.ClientTLS(id, trust, serverName)
}
