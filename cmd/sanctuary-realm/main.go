// Command sanctuary-realm runs a realm as its own process: it dials the
// gateway's realm port over mTLS (docs/protocol.md §3), registers, serves
// the players the gateway routes to it, and reconnects with backoff when
// the link drops. In stage 02 the realm is the stub (the echo handler).
//
// Every setting can come from a flag, an environment variable or an
// env-format config file (see internal/config): -gateway is
// SANCTUARY_GATEWAY. Run with -help for the list.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sanctuary/internal/cli"
	"sanctuary/internal/config"
	"sanctuary/internal/realm"
	"sanctuary/internal/realmproto"
)

func main() {
	s := config.New("sanctuary-realm")
	var (
		gateway     = s.String("GATEWAY", "127.0.0.1:9030", "gateway realm port to dial (host:port)")
		gatewayName = s.String("GATEWAY_NAME", "", "gateway name checked in CA mode (default: the host in GATEWAY)")
		gatewayPins = s.String("GATEWAY_PINS", "", "comma-separated gateway pins (sha256/...) or files of pins")
		gatewayCA   = s.Blob("GATEWAY_CA", false, "CA bundle that may issue the gateway's certificate")
		cert        = s.Blob("CERT", false, "this realm's identity certificate")
		key         = s.Blob("KEY", true, "this realm's identity key")
		id          = s.String("ID", "stub", "realm id: 1-32 of [a-z0-9-], unique per gateway")
		name        = s.String("NAME", "Stub realm", "name shown in the gateway's realm list")
		build       = s.String("BUILD", "dev", "build identity reported to the gateway")
		logLevel    = s.String("LOG_LEVEL", "info", "debug, info, warn or error")
		dialTimeout = s.Duration("DIAL_TIMEOUT", 10*time.Second, "time allowed to connect and complete the TLS handshake")
	)
	genIdentity := s.Flags().String("gen-identity", "", "write a new realm-link identity to PREFIX.crt, .key and .pin, print the pin, and exit")
	cli.Parse(s, os.Args[1:])
	if *genIdentity != "" {
		pin, err := realmproto.WriteIdentity(*genIdentity, "Sanctuary realm "+*id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen-identity:", err)
			os.Exit(1)
		}
		fmt.Println(pin)
		return
	}
	log := cli.Logger(*logLevel)
	cli.Report(log, s)
	fail := func(err error) {
		log.Error("realm link TLS", "err", err)
		os.Exit(1)
	}

	identity, err := cli.KeyPair(cert, key, "realm identity (CERT, KEY; make one with -gen-identity)")
	if err != nil {
		fail(err)
	}
	trust, err := cli.Trust(*gatewayPins, gatewayCA)
	if err != nil {
		fail(err)
	}
	serverName := *gatewayName
	if serverName == "" {
		if h, _, err := net.SplitHostPort(*gateway); err == nil {
			serverName = h
		}
	}
	conf, err := realmproto.ClientTLS(identity, trust, serverName)
	if err != nil {
		fail(err)
	}

	// SIGTERM ends the realm. The drain sequence (protocol.md §8: tell
	// players, save, hand them back) arrives later in stage 02; for now the
	// gateway tells players the realm has gone.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("realm starting", "realm", *id, "gateway", *gateway)
	err = realm.Run(ctx, realm.TLSDialer(*gateway, conf, *dialTimeout), realm.Config{
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
