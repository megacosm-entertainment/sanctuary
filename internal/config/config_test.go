package config_test

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/config"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func file(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "settings.env")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func source(s *config.Set, name string) config.Source {
	for _, e := range s.Effective() {
		if e.Name == name {
			return e.Source
		}
	}
	return ""
}

// Precedence: default < file < env < flag (design §06's chain).
func TestPrecedence(t *testing.T) {
	cfgFile := file(t, "SANCTUARY_TELNET=:1001\nSANCTUARY_TELNETS=:2001\nSANCTUARY_WS=:3001\n")
	s := config.New("gw")
	telnet := s.String("TELNET", ":9000", "telnet")
	telnets := s.String("TELNETS", ":9010", "telnets")
	ws := s.String("WS", ":9020", "ws")
	other := s.String("OTHER", "default", "untouched")
	err := s.Parse([]string{"-config", cfgFile, "-ws", ":3003"},
		env(map[string]string{"SANCTUARY_TELNETS": ":2002", "SANCTUARY_WS": ":3002"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, c := range []struct {
		name, got, want string
		src             config.Source
	}{
		{"TELNET", *telnet, ":1001", config.FromFile},
		{"TELNETS", *telnets, ":2002", config.FromEnv},
		{"WS", *ws, ":3003", config.FromFlag},
		{"OTHER", *other, "default", config.FromDefault},
	} {
		if c.got != c.want || source(s, c.name) != c.src {
			t.Errorf("%s = %q from %s, want %q from %s", c.name, c.got, source(s, c.name), c.want, c.src)
		}
	}
}

func TestConfigPathFromEnvironment(t *testing.T) {
	s := config.New("gw")
	port := s.Int("MAX_CLIENTS", 1024, "max")
	if err := s.Parse(nil, env(map[string]string{"SANCTUARY_CONFIG": file(t, "SANCTUARY_MAX_CLIENTS=7\n")})); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *port != 7 {
		t.Fatalf("MAX_CLIENTS = %d, want 7 from the file named by SANCTUARY_CONFIG", *port)
	}
}

func TestTypedValues(t *testing.T) {
	s := config.New("gw")
	n := s.Int("MAX_CLIENTS", 1, "")
	on := s.Bool("STUB_REALM", true, "")
	d := s.Duration("WAIT", time.Second, "")
	err := s.Parse([]string{"-stub-realm=false"}, env(map[string]string{"SANCTUARY_MAX_CLIENTS": "64", "SANCTUARY_WAIT": "2m"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *n != 64 || *on || *d != 2*time.Minute {
		t.Fatalf("got %d %v %v, want 64 false 2m", *n, *on, *d)
	}
	for name, bad := range map[string]map[string]string{
		"int":      {"SANCTUARY_MAX_CLIENTS": "lots"},
		"bool":     {"SANCTUARY_STUB_REALM": "maybe"},
		"duration": {"SANCTUARY_WAIT": "soon"},
	} {
		s := config.New("gw")
		s.Int("MAX_CLIENTS", 1, "")
		s.Bool("STUB_REALM", true, "")
		s.Duration("WAIT", time.Second, "")
		if err := s.Parse(nil, env(bad)); err == nil {
			t.Errorf("Parse with a bad %s value succeeded", name)
		}
	}
}

// ── Blobs and secrets ────────────────────────────────────────

func TestBlobContentOrPath(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(keyFile, []byte("FROM FILE"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{"flag is a path", []string{"-realm-key", keyFile}, nil, "FROM FILE"},
		{"_FILE variable is a path", nil, map[string]string{"SANCTUARY_REALM_KEY_FILE": keyFile}, "FROM FILE"},
		// How Doppler, Vault agents or Kubernetes env secrets deliver it.
		{"variable is the content", nil, map[string]string{"SANCTUARY_REALM_KEY": "FROM ENV"}, "FROM ENV"},
		{"content beats path in the environment", nil, map[string]string{"SANCTUARY_REALM_KEY": "FROM ENV", "SANCTUARY_REALM_KEY_FILE": keyFile}, "FROM ENV"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := config.New("gw")
			key := s.Blob("REALM_KEY", true, "key")
			if err := s.Parse(c.args, env(c.env)); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := key.Bytes()
			if err != nil || string(got) != c.want {
				t.Fatalf("Bytes() = %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

// A secret's content may not sit in a config file, which may be committed;
// a path to it may.
func TestSecretContentRefusedInFile(t *testing.T) {
	s := config.New("gw")
	s.Blob("REALM_KEY", true, "key")
	err := s.Parse([]string{"-config", file(t, "SANCTUARY_REALM_KEY=-----BEGIN PRIVATE KEY-----\n")}, env(nil))
	if err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("Parse with a key in the config file = %v, want a refusal", err)
	}
	s2 := config.New("gw")
	key := s2.Blob("REALM_KEY", true, "key")
	if err := s2.Parse([]string{"-config", file(t, "SANCTUARY_REALM_KEY_FILE=/run/secrets/realm.key\n")}, env(nil)); err != nil {
		t.Fatalf("Parse with a key path in the config file: %v", err)
	}
	if !key.Set() {
		t.Fatal("key path from the config file was not applied")
	}
}

// A certificate is not secret, so its content may be in a file.
func TestPublicBlobContentAllowedInFile(t *testing.T) {
	s := config.New("gw")
	cert := s.Blob("REALM_CERT", false, "cert")
	if err := s.Parse([]string{"-config", file(t, "SANCTUARY_REALM_CERT=\"-----BEGIN CERTIFICATE-----\\nabc\"\n")}, env(nil)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	b, err := cert.Bytes()
	if err != nil || string(b) != "-----BEGIN CERTIFICATE-----\nabc" {
		t.Fatalf("cert content = %q, %v", b, err)
	}
}

// The startup log must never print a secret.
func TestEffectiveHidesSecrets(t *testing.T) {
	s := config.New("gw")
	s.Blob("REALM_KEY", true, "key")
	s.Blob("TLS_KEY", true, "key")
	s.String("TELNET", ":9000", "")
	err := s.Parse([]string{"-tls-key", "/run/secrets/tls.key"}, env(map[string]string{"SANCTUARY_REALM_KEY": "PRIVATE-KEY-CANARY"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, e := range s.Effective() {
		if strings.Contains(e.Value, "CANARY") {
			t.Fatalf("Effective() leaks secret content: %+v", e)
		}
		switch e.Name {
		case "REALM_KEY":
			if e.Value != "[secret]" || e.Source != config.FromEnv {
				t.Errorf("REALM_KEY entry = %+v, want [secret] from env", e)
			}
		case "TLS_KEY":
			if e.Value != "[file]" {
				t.Errorf("TLS_KEY entry = %+v, want [file]: a secret's path is not shown either", e)
			}
		}
	}
}

// ── Files ────────────────────────────────────────────────────

// Formats seen in practice: compose env_file, Doppler's --format env,
// shell-style export lines.
func TestParseEnvFile(t *testing.T) {
	in := `# gateway settings
SANCTUARY_TELNET=:9000
export SANCTUARY_WS=":9020"
SANCTUARY_NAME='Sanctuary "dev"'
SANCTUARY_PUBLIC_HOST=mud.example   # inline comment
SANCTUARY_PEM="line1\nline2"
SANCTUARY_EMPTY=

OTHER_TOOL=keep
`
	got, err := config.ParseEnvFile(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseEnvFile: %v", err)
	}
	want := map[string]string{
		"SANCTUARY_TELNET": ":9000", "SANCTUARY_WS": ":9020", "SANCTUARY_NAME": `Sanctuary "dev"`,
		"SANCTUARY_PUBLIC_HOST": "mud.example", "SANCTUARY_PEM": "line1\nline2", "SANCTUARY_EMPTY": "",
		"OTHER_TOOL": "keep",
	}
	if len(got) != len(want) {
		t.Fatalf("ParseEnvFile = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseEnvFileRejects(t *testing.T) {
	for name, in := range map[string]string{
		"no equals":         "SANCTUARY_TELNET\n",
		"space in key":      "SANCTUARY TELNET=1\n",
		"unterminated":      "SANCTUARY_NAME=\"abc\n",
		"duplicate key":     "SANCTUARY_TELNET=1\nSANCTUARY_TELNET=2\n",
		"stray inner quote": "SANCTUARY_NAME=\"a\"b\"\n",
	} {
		if _, err := config.ParseEnvFile(strings.NewReader(in)); err == nil {
			t.Errorf("%s: ParseEnvFile(%q) succeeded", name, in)
		}
	}
}

// A typo in a config file is reported rather than silently ignored; other
// programs' variables in a shared file are left alone.
func TestUnknownFileKeysWarned(t *testing.T) {
	s := config.New("gw")
	s.String("TELNET", ":9000", "")
	s.Blob("REALM_KEY", true, "")
	err := s.Parse([]string{"-config", file(t, "SANCTUARY_TELENT=:1\nSANCTUARY_REALM_KEY_FILE=/x\nDOPPLER_PROJECT=mud\n")}, env(nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	w := s.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], "SANCTUARY_TELENT") {
		t.Fatalf("Warnings() = %q, want one about SANCTUARY_TELENT", w)
	}
}

func TestMissingConfigFileIsAnError(t *testing.T) {
	s := config.New("gw")
	if err := s.Parse([]string{"-config", "/no/such/file.env"}, env(nil)); err == nil {
		t.Fatal("Parse with a missing config file succeeded")
	}
}

func TestHelpIsReported(t *testing.T) {
	s := config.New("gw")
	if err := s.Parse([]string{"-help"}, env(nil)); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Parse(-help) = %v, want flag.ErrHelp", err)
	}
}

// Doppler's --format env (and compose) put multi-line values, such as PEM
// certificates, inside one double-quoted value over several lines.
func TestParseEnvFileMultilineValue(t *testing.T) {
	in := "SANCTUARY_A=1\nSANCTUARY_CERT=\"-----BEGIN CERTIFICATE-----\nMIIB\nabc=\n-----END CERTIFICATE-----\"\nSANCTUARY_B=\"ends with \\\\\"\nSANCTUARY_C=2\n"
	got, err := config.ParseEnvFile(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseEnvFile: %v", err)
	}
	if want := "-----BEGIN CERTIFICATE-----\nMIIB\nabc=\n-----END CERTIFICATE-----"; got["SANCTUARY_CERT"] != want {
		t.Fatalf("CERT = %q, want %q", got["SANCTUARY_CERT"], want)
	}
	if got["SANCTUARY_B"] != `ends with \` || got["SANCTUARY_A"] != "1" || got["SANCTUARY_C"] != "2" {
		t.Fatalf("neighbouring values wrong: %q", got)
	}
	if _, err := config.ParseEnvFile(strings.NewReader("SANCTUARY_CERT=\"never closed\nSANCTUARY_X=1\n")); err == nil {
		t.Fatal("a quote never closed was accepted")
	}
}

// RT-3-3: a secret pasted where its path belongs (an easy slip:
// -realm-key "$SANCTUARY_REALM_KEY") must not end up in a log or an error.
func TestSecretPastedAsPathNeverShown(t *testing.T) {
	const canary = "-----BEGIN PRIVATE KEY-----\nCANARY-SECRET\n-----END PRIVATE KEY-----"
	for name, c := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"flag":         {[]string{"-realm-key", canary}, nil},
		"_FILE":        {nil, map[string]string{"SANCTUARY_REALM_KEY_FILE": canary}},
		"one-line PEM": {[]string{"-realm-key", "-----BEGIN PRIVATE KEY----- CANARY-SECRET -----END PRIVATE KEY-----"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			s := config.New("gw")
			s.Blob("REALM_KEY", true, "key")
			err := s.Parse(c.args, env(c.env))
			if err == nil {
				t.Fatal("Parse accepted key content as a path")
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("the error repeats the secret: %v", err)
			}
		})
	}
}

// A secret's file that cannot be read is reported without its path.
func TestSecretFileErrorOmitsPath(t *testing.T) {
	s := config.New("gw")
	key := s.Blob("REALM_KEY", true, "key")
	if err := s.Parse([]string{"-realm-key", "/no/such/CANARY-PATH"}, env(nil)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err := key.Bytes()
	if err == nil || strings.Contains(err.Error(), "CANARY") || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Bytes() = %v, want a not-exist error that does not repeat the path", err)
	}
}
