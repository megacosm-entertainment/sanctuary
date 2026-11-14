package realmproto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/realmproto"
)

// identity is a self-signed realm-link identity, as GenerateIdentity makes.
func identity(t *testing.T, name string) (tls.Certificate, string) {
	t.Helper()
	certPEM, keyPEM, err := realmproto.GenerateIdentity(name)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return c, realmproto.Pin(leaf)
}

// testCA issues certificates, standing in for cert-manager.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) issue(t *testing.T, name string, usage x509.ExtKeyUsage, dns ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake runs both sides over loopback TCP and returns each side's
// handshake error. Loopback rather than net.Pipe: TLS 1.3 refusals arrive
// as alerts after one side has finished, and only a buffered socket
// delivers them the way production does.
func handshake(t *testing.T, server, client *tls.Config) (serverErr, clientErr error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	b, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	deadline := time.Now().Add(timeout)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	srv, cli := tls.Server(a, server), tls.Client(b, client)
	// In TLS 1.3 one side can finish before the other decides to refuse;
	// the refusal then arrives as an alert. net.Pipe has no buffer, so keep
	// reading after a successful handshake, as a real socket's buffer would
	// take the alert.
	drain := func(c *tls.Conn) {
		buf := make([]byte, 64)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}
	done := make(chan error, 1)
	go func() {
		err := srv.Handshake()
		if err != nil {
			a.Close() // unblock the client as a real server's close would
		} else {
			go drain(srv)
		}
		done <- err
	}()
	clientErr = cli.Handshake()
	if clientErr != nil {
		b.Close()
	} else {
		go drain(cli)
	}
	serverErr = <-done
	if clientErr == nil && serverErr != nil {
		// The client finished first; the server's refusal reaches it on
		// the first read, which a realm would see as the link failing.
		clientErr = errors.New("server refused after the client finished")
	}
	return serverErr, clientErr
}

func mustServer(t *testing.T, id tls.Certificate, trust realmproto.Trust) *tls.Config {
	t.Helper()
	c, err := realmproto.ServerTLS(id, trust)
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	return c
}

func mustClient(t *testing.T, id tls.Certificate, trust realmproto.Trust, name string) *tls.Config {
	t.Helper()
	c, err := realmproto.ClientTLS(id, trust, name)
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
	return c
}

// ── Pinning ──────────────────────────────────────────────────

func TestPinnedPeersConnect(t *testing.T) {
	gwID, gwPin := identity(t, "gateway")
	realmID, realmPin := identity(t, "realm")
	s, c := handshake(t,
		mustServer(t, gwID, realmproto.Trust{Pins: []string{realmPin}}),
		mustClient(t, realmID, realmproto.Trust{Pins: []string{gwPin}}, "gateway"))
	if s != nil || c != nil {
		t.Fatalf("handshake between pinned peers: server %v, client %v", s, c)
	}
}

func TestUnpinnedRealmRefused(t *testing.T) {
	gwID, gwPin := identity(t, "gateway")
	_, otherPin := identity(t, "someone else")
	stranger, _ := identity(t, "stranger")
	s, _ := handshake(t,
		mustServer(t, gwID, realmproto.Trust{Pins: []string{otherPin}}),
		mustClient(t, stranger, realmproto.Trust{Pins: []string{gwPin}}, "gateway"))
	if !errors.Is(s, realmproto.ErrUntrusted) {
		t.Fatalf("gateway handshake with an unpinned realm = %v, want ErrUntrusted", s)
	}
}

// A realm must not register with an impostor gateway either: it would hand
// over every session routed to it.
func TestRealmRefusesUnpinnedGateway(t *testing.T) {
	impostor, _ := identity(t, "impostor")
	_, realGwPin := identity(t, "gateway")
	realmID, realmPin := identity(t, "realm")
	_, c := handshake(t,
		mustServer(t, impostor, realmproto.Trust{Pins: []string{realmPin}}),
		mustClient(t, realmID, realmproto.Trust{Pins: []string{realGwPin}}, "gateway"))
	if !errors.Is(c, realmproto.ErrUntrusted) {
		t.Fatalf("realm handshake with an impostor gateway = %v, want ErrUntrusted", c)
	}
}

func TestRealmWithoutCertificateRefused(t *testing.T) {
	gwID, gwPin := identity(t, "gateway")
	_, realmPin := identity(t, "realm")
	client := mustClient(t, tls.Certificate{}, realmproto.Trust{Pins: []string{gwPin}}, "gateway")
	client.Certificates = nil
	s, _ := handshake(t, mustServer(t, gwID, realmproto.Trust{Pins: []string{realmPin}}), client)
	if s == nil {
		t.Fatal("gateway accepted a realm that presented no certificate")
	}
}

// ── CA mode (certificate rotation) ───────────────────────────

func TestCAIssuedRealmAcceptedWithoutPin(t *testing.T) {
	ca := newCA(t)
	gwID, gwPin := identity(t, "gateway")
	realmCert := ca.issue(t, "realm", x509.ExtKeyUsageClientAuth)
	s, c := handshake(t,
		mustServer(t, gwID, realmproto.Trust{CAs: ca.pool}),
		mustClient(t, realmCert, realmproto.Trust{Pins: []string{gwPin}}, "gateway"))
	if s != nil || c != nil {
		t.Fatalf("CA-issued realm: server %v, client %v", s, c)
	}
}

func TestCAModeRefuses(t *testing.T) {
	ca, otherCA := newCA(t), newCA(t)
	gwID, gwPin := identity(t, "gateway")
	cases := []struct {
		name string
		cert tls.Certificate
	}{
		{"issued by another CA", otherCA.issue(t, "realm", x509.ExtKeyUsageClientAuth)},
		// A server certificate from the same CA must not be usable as a realm.
		{"wrong key usage", ca.issue(t, "realm", x509.ExtKeyUsageServerAuth)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := handshake(t,
				mustServer(t, gwID, realmproto.Trust{CAs: ca.pool}),
				mustClient(t, tc.cert, realmproto.Trust{Pins: []string{gwPin}}, "gateway"))
			if !errors.Is(s, realmproto.ErrUntrusted) {
				t.Fatalf("gateway handshake = %v, want ErrUntrusted", s)
			}
		})
	}
}

// In CA mode the gateway's name is checked: any certificate the CA issued
// is not enough.
func TestCAModeChecksGatewayName(t *testing.T) {
	ca := newCA(t)
	realmID, realmPin := identity(t, "realm")
	gwCert := ca.issue(t, "gateway", x509.ExtKeyUsageServerAuth, "gateway.example")
	server := mustServer(t, gwCert, realmproto.Trust{Pins: []string{realmPin}})
	if s, c := handshake(t, server, mustClient(t, realmID, realmproto.Trust{CAs: ca.pool}, "gateway.example")); s != nil || c != nil {
		t.Fatalf("right name: server %v, client %v", s, c)
	}
	if _, c := handshake(t, server, mustClient(t, realmID, realmproto.Trust{CAs: ca.pool}, "other.example")); !errors.Is(c, realmproto.ErrUntrusted) {
		t.Fatalf("wrong name: client %v, want ErrUntrusted", c)
	}
}

// Pins and a CA together: either is enough.
func TestPinsAndCATogether(t *testing.T) {
	ca := newCA(t)
	gwID, gwPin := identity(t, "gateway")
	pinned, pinnedPin := identity(t, "pinned realm")
	trust := realmproto.Trust{Pins: []string{pinnedPin}, CAs: ca.pool}
	for name, cert := range map[string]tls.Certificate{
		"pinned":    pinned,
		"CA-issued": ca.issue(t, "issued realm", x509.ExtKeyUsageClientAuth),
	} {
		s, c := handshake(t, mustServer(t, gwID, trust), mustClient(t, cert, realmproto.Trust{Pins: []string{gwPin}}, "gateway"))
		if s != nil || c != nil {
			t.Errorf("%s realm with pins+CA trust: server %v, client %v", name, s, c)
		}
	}
}

// ── Configuration ────────────────────────────────────────────

// Security ranks first: an empty trust is a configuration error, never
// "accept everyone".
func TestEmptyTrustRefused(t *testing.T) {
	id, _ := identity(t, "x")
	if _, err := realmproto.ServerTLS(id, realmproto.Trust{}); !errors.Is(err, realmproto.ErrNoTrust) {
		t.Fatalf("ServerTLS(no trust) err = %v, want ErrNoTrust", err)
	}
	if _, err := realmproto.ClientTLS(id, realmproto.Trust{}, "x"); !errors.Is(err, realmproto.ErrNoTrust) {
		t.Fatalf("ClientTLS(no trust) err = %v, want ErrNoTrust", err)
	}
}

func TestTLS12Refused(t *testing.T) {
	gwID, gwPin := identity(t, "gateway")
	realmID, realmPin := identity(t, "realm")
	client := mustClient(t, realmID, realmproto.Trust{Pins: []string{gwPin}}, "gateway")
	client.MinVersion, client.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if s, _ := handshake(t, mustServer(t, gwID, realmproto.Trust{Pins: []string{realmPin}}), client); s == nil {
		t.Fatal("gateway accepted TLS 1.2 on the realm port")
	}
}

func TestParsePin(t *testing.T) {
	_, good := identity(t, "x")
	if got, err := realmproto.ParsePin("  " + good + "\n"); err != nil || got != good {
		t.Fatalf("ParsePin(%q) = %q, %v", good, got, err)
	}
	for _, bad := range []string{"", "sha1/abc", "sha256/not base64!", "sha256/" + strings.Repeat("A", 8), strings.TrimPrefix(good, realmproto.PinPrefix)} {
		if _, err := realmproto.ParsePin(bad); err == nil {
			t.Errorf("ParsePin(%q) accepted a malformed pin", bad)
		}
	}
	id, _ := identity(t, "x")
	if _, err := realmproto.ServerTLS(id, realmproto.Trust{Pins: []string{"sha256/bad"}}); err == nil {
		t.Error("ServerTLS accepted a malformed pin")
	}
}

func TestWriteIdentity(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "realm-stub")
	pin, err := realmproto.WriteIdentity(prefix, "stub")
	if err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	st, err := os.Stat(prefix + ".key")
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", st.Mode().Perm())
	}
	c, err := tls.LoadX509KeyPair(prefix+".crt", prefix+".key")
	if err != nil {
		t.Fatalf("written identity does not load: %v", err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	if realmproto.Pin(leaf) != pin {
		t.Fatalf("returned pin %q does not match the written certificate", pin)
	}
	pins, err := realmproto.ReadPins([]string{prefix + ".pin"})
	if err != nil || len(pins) != 1 || pins[0] != pin {
		t.Fatalf("ReadPins(pin file) = %v, %v; want [%s]", pins, err, pin)
	}
	// Never overwrite: an accidental rerun must not break every peer that
	// pinned the old key.
	if _, err := realmproto.WriteIdentity(prefix, "stub"); err == nil {
		t.Fatal("WriteIdentity overwrote an existing identity")
	}
	if c2, _ := tls.LoadX509KeyPair(prefix+".crt", prefix+".key"); !c2.Leaf.Equal(c.Leaf) && string(c2.Certificate[0]) != string(c.Certificate[0]) {
		t.Fatal("the existing identity changed after a refused rewrite")
	}
}

func TestReadPinsMixesLiteralsAndFiles(t *testing.T) {
	_, a := identity(t, "a")
	_, b := identity(t, "b")
	file := filepath.Join(t.TempDir(), "pins")
	if err := os.WriteFile(file, []byte("# realms\n"+b+"  # second realm\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := realmproto.ReadPins([]string{a, file, ""})
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("ReadPins = %v, %v; want [%s %s]", got, err, a, b)
	}
	if _, err := realmproto.ReadPins([]string{"/no/such/file"}); err == nil {
		t.Fatal("ReadPins accepted a missing file")
	}
}

// ── Realm ids bound to keys (RT-3-1) ─────────────────────────

func peer(t *testing.T, c tls.Certificate) tls.ConnectionState {
	t.Helper()
	var chain []*x509.Certificate
	for _, der := range c.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	return tls.ConnectionState{PeerCertificates: chain}
}

func TestRealmIDsFromPins(t *testing.T) {
	live, livePin := identity(t, "live")
	other, _ := identity(t, "other")
	bound, err := realmproto.ParseRealmPins([]string{"live=" + livePin, "beta=" + livePin})
	if err != nil {
		t.Fatalf("ParseRealmPins: %v", err)
	}
	allowed := realmproto.RealmIDs(peer(t, live), bound, nil)
	for id, want := range map[string]bool{"live": true, "beta": true, "stub": false} {
		if allowed(id) != want {
			t.Errorf("live's key may register as %q: %v, want %v", id, allowed(id), want)
		}
	}
	if realmproto.RealmIDs(peer(t, other), bound, nil)("live") {
		t.Error("an unbound key may register as live")
	}
}

// A CA-issued certificate may register as its Common Name or a DNS name,
// and nothing else. A pinned self-signed key gets nothing from its own
// subject, even with a CA configured: nobody vouched for that name.
func TestRealmIDsFromCA(t *testing.T) {
	ca := newCA(t)
	issued := ca.issue(t, "live", x509.ExtKeyUsageClientAuth, "live-b")
	allowed := realmproto.RealmIDs(peer(t, issued), nil, ca.pool)
	for id, want := range map[string]bool{"live": true, "live-b": true, "stub": false} {
		if allowed(id) != want {
			t.Errorf("CA-issued live may register as %q: %v, want %v", id, allowed(id), want)
		}
	}
	serverOnly := ca.issue(t, "live", x509.ExtKeyUsageServerAuth)
	if realmproto.RealmIDs(peer(t, serverOnly), nil, ca.pool)("live") {
		t.Error("a server-auth-only certificate from the CA may register as a realm")
	}
	certPEM, keyPEM, err := realmproto.GenerateIdentity("live") // CN "live", self-signed
	if err != nil {
		t.Fatal(err)
	}
	self, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if realmproto.RealmIDs(peer(t, self), nil, ca.pool)("live") {
		t.Error("a self-signed key with CN live may register as live because a CA is configured")
	}
}

// Base64 can spell the same 32 bytes two ways (the unused low bits of the
// last character); both must name the same key (RT-3-5).
func TestParsePinCanonicalises(t *testing.T) {
	_, good := identity(t, "x")
	b := []byte(good)
	last := b[len(b)-2] // the character before '='
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, last)
	b[len(b)-2] = alphabet[i|1] // set an unused bit; the decoded bytes are unchanged
	if string(b) == good {
		b[len(b)-2] = alphabet[i&^1]
	}
	got, err := realmproto.ParsePin(string(b))
	if err != nil || got != good {
		t.Fatalf("ParsePin(%q) = %q, %v; want the canonical %q", b, got, err, good)
	}
}
