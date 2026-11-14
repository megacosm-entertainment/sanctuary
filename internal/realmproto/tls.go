package realmproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// Realm links are TLS 1.3 with certificates on both sides (protocol.md §3).
// A peer is trusted if its certificate's public key is pinned, or if its
// certificate chains to a configured CA. Pinning needs no infrastructure;
// the CA mode lets a certificate manager (cert-manager, for one) rotate keys
// without editing an allowlist. Both may be configured at once.

// PinPrefix starts every pin: "sha256/" then the base64 of the SHA-256 of
// the certificate's SubjectPublicKeyInfo (the form HPKP used). Pinning the
// key rather than the certificate means a renewed certificate for the same
// key keeps working.
const PinPrefix = "sha256/"

// Pin returns cert's public-key pin.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// ParsePin checks that s is a well-formed pin and returns it normalised.
func ParsePin(s string) (string, error) {
	s = strings.TrimSpace(s)
	b64, ok := strings.CutPrefix(s, PinPrefix)
	if !ok {
		return "", fmt.Errorf("realmproto: pin %q does not start with %q", s, PinPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("realmproto: pin %q is not a base64 SHA-256", s)
	}
	return s, nil
}

// Trust says which peers to accept.
type Trust struct {
	Pins []string       // accepted public-key pins
	CAs  *x509.CertPool // accepted issuers; nil for pins only
}

// Errors from verification.
var (
	ErrNoTrust   = errors.New("realmproto: no pins and no CA configured: refusing to trust every peer")
	ErrUntrusted = errors.New("realmproto: peer certificate is neither pinned nor issued by a trusted CA")
)

func (t Trust) check() (map[string]bool, error) {
	if len(t.Pins) == 0 && t.CAs == nil {
		return nil, ErrNoTrust
	}
	pins := make(map[string]bool, len(t.Pins))
	for _, p := range t.Pins {
		norm, err := ParsePin(p)
		if err != nil {
			return nil, err
		}
		pins[norm] = true
	}
	return pins, nil
}

func (t Trust) verifier(pins map[string]bool, usage x509.ExtKeyUsage, serverName string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return ErrUntrusted
		}
		leaf := cs.PeerCertificates[0]
		if pins[Pin(leaf)] {
			return nil
		}
		if t.CAs == nil {
			return ErrUntrusted
		}
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         t.CAs,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{usage},
			DNSName:       serverName,
		})
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUntrusted, err)
		}
		return nil
	}
}

// ServerTLS is the gateway's TLS config for its realm listener: it requires
// a client certificate and accepts only realms that realms trusts.
func ServerTLS(identity tls.Certificate, realms Trust) (*tls.Config, error) {
	pins, err := realms.check()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{identity},
		// Chain checking is ours (pin or CA), so ask for any certificate
		// and verify in VerifyConnection.
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyConnection: realms.verifier(pins, x509.ExtKeyUsageClientAuth, ""),
	}, nil
}

// ClientTLS is a realm's TLS config for dialling the gateway. serverName is
// checked only in CA mode; a pinned key is the identity.
func ClientTLS(identity tls.Certificate, gateway Trust, serverName string) (*tls.Config, error) {
	pins, err := gateway.check()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{identity},
		ServerName:   serverName,
		// The standard hostname-and-roots check is replaced by ours, not
		// skipped: VerifyConnection runs on every handshake.
		InsecureSkipVerify: true,
		VerifyConnection:   gateway.verifier(pins, x509.ExtKeyUsageServerAuth, serverName),
	}, nil
}

// identityLifetime is long because a pinned identity is replaced by
// generating a new key and updating the pin, not by expiry. CA-issued
// certificates have whatever lifetime their issuer gives them.
const identityLifetime = 5 * 365 * 24 * time.Hour

// GenerateIdentity makes an ECDSA P-256 key and a self-signed certificate
// usable on either end of a realm link, and returns them as PEM.
func GenerateIdentity(name string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(identityLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

// WriteIdentity generates an identity and writes prefix.crt, prefix.key
// (mode 0600) and prefix.pin. It never overwrites an existing file: losing a
// key by accident would silently break every peer that pinned it.
func WriteIdentity(prefix, name string) (pin string, err error) {
	certPEM, keyPEM, err := GenerateIdentity(name)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	pin = Pin(cert)
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{prefix + ".key", keyPEM, 0o600},
		{prefix + ".crt", certPEM, 0o644},
		{prefix + ".pin", []byte(pin + "\n"), 0o644},
	} {
		fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
		if err != nil {
			return "", err
		}
		_, werr := fh.Write(f.data)
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return "", werr
		}
	}
	return pin, nil
}

// ReadPins reads pins from files (one per line, '#' comments allowed) and
// literal values, for command-line flags that accept either.
func ReadPins(values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, PinPrefix) {
			p, err := ParsePin(v)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
			continue
		}
		b, err := os.ReadFile(v)
		if err != nil {
			return nil, fmt.Errorf("realmproto: %q is neither a pin nor a readable pin file: %w", v, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			line, _, _ = strings.Cut(line, "#")
			if line = strings.TrimSpace(line); line == "" {
				continue
			}
			p, err := ParsePin(line)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", v, err)
			}
			out = append(out, p)
		}
	}
	return out, nil
}
