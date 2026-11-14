// Package cli holds what the sanctuary commands share at startup: reading
// settings, setting up logging, reporting where each setting came from,
// and turning certificate and trust settings into TLS material.
package cli

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"sanctuary/internal/config"
	"sanctuary/internal/realmproto"
)

// Parse reads settings from args and the process environment. On -help it
// prints usage and exits 0; on a bad setting it prints the error and exits
// 2, before anything starts.
func Parse(s *config.Set, args []string) {
	err := s.Parse(args, os.LookupEnv)
	if errors.Is(err, flag.ErrHelp) {
		s.Usage(os.Stdout)
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// Logger returns the JSON logger at level ("debug", "info", ...), installed
// as the default, or exits on a bad level.
func Logger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		fmt.Fprintf(os.Stderr, "bad %sLOG_LEVEL / -log-level %q: %v\n", config.Prefix, level, err)
		os.Exit(2)
	}
	log := slog.New(NewHandler(os.Stdout, l))
	slog.SetDefault(log)
	return log
}

// NewHandler is the commands' log format: JSON, with durations written as
// Go duration text ("20s", "2m0s") rather than slog's default of integer
// nanoseconds, which nobody reading a log can take in at a glance.
func NewHandler(w io.Writer, level slog.Leveler) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: readableDurations})
}

func readableDurations(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindDuration {
		return slog.String(a.Key, a.Value.Duration().String())
	}
	return a
}

// Report logs every setting that is not at its default (value and source)
// at info, the rest at debug, and any warnings. Secret content is never
// included.
func Report(log *slog.Logger, s *config.Set) {
	for _, e := range s.Effective() {
		if e.Source != config.FromDefault {
			log.Info("setting", "name", e.Name, "value", e.Value, "from", string(e.Source))
		} else {
			log.Debug("setting", "name", e.Name, "value", e.Value, "from", string(e.Source))
		}
	}
	for _, w := range s.Warnings() {
		log.Warn("settings", "problem", w)
	}
}

// KeyPair loads a certificate and key given as config blobs.
func KeyPair(cert, key config.Blob, what string) (tls.Certificate, error) {
	if !cert.Set() || !key.Set() {
		return tls.Certificate{}, fmt.Errorf("%s needs both a certificate and a key", what)
	}
	c, err := cert.Bytes()
	if err != nil {
		return tls.Certificate{}, err
	}
	k, err := key.Bytes()
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%s: %w", what, err)
	}
	return pair, nil
}

// Trust builds realm-link trust from a comma-separated list of pins or pin
// files and an optional CA bundle.
func Trust(pins string, ca config.Blob) (realmproto.Trust, error) {
	list, err := realmproto.ReadPins(strings.Split(pins, ","))
	if err != nil {
		return realmproto.Trust{}, err
	}
	t := realmproto.Trust{Pins: list}
	if ca.Set() {
		b, err := ca.Bytes()
		if err != nil {
			return realmproto.Trust{}, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return realmproto.Trust{}, errors.New("CA bundle contains no certificates")
		}
		t.CAs = pool
	}
	return t, nil
}

// SplitList splits a comma-separated setting, dropping empty items.
func SplitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// RealmTrust is the gateway's trust in realms: bindings of realm ids to
// pinned keys (id=sha256/..., literal or in files) and an optional CA whose
// certificates may register as their Common Name or DNS names. It returns
// the TLS trust (any bound key or the CA) and the bindings the listener
// checks each hello against (RT-3-1).
func RealmTrust(pins string, ca config.Blob) (realmproto.Trust, realmproto.RealmPins, *x509.CertPool, error) {
	bound, err := realmproto.ParseRealmPins(strings.Split(pins, ","))
	if err != nil {
		return realmproto.Trust{}, nil, nil, err
	}
	t := realmproto.Trust{Pins: bound.Pins()}
	if ca.Set() {
		b, err := ca.Bytes()
		if err != nil {
			return realmproto.Trust{}, nil, nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return realmproto.Trust{}, nil, nil, errors.New("CA bundle contains no certificates")
		}
		t.CAs = pool
	}
	return t, bound, t.CAs, nil
}
