package main

import (
	"testing"
)

// The example settings in deploy/ must use only real settings: a renamed or
// removed setting would otherwise leave compose silently using a default.
func TestDeployFileUsesRealSettings(t *testing.T) {
	s, _ := declare()
	noEnv := func(string) (string, bool) { return "", false }
	if err := s.Parse([]string{"-config", "../../deploy/gateway.env"}, noEnv); err != nil {
		t.Fatalf("deploy/gateway.env: %v", err)
	}
	if w := s.Warnings(); len(w) > 0 {
		t.Fatalf("deploy/gateway.env has keys that are not settings: %q", w)
	}
}

func TestPublicPortsAreChecked(t *testing.T) {
	for _, c := range []struct {
		env map[string]string
		ok  bool
	}{
		{map[string]string{}, true},
		{map[string]string{"SANCTUARY_PUBLIC_TELNETS_PORT": "19010"}, true},
		{map[string]string{"SANCTUARY_PUBLIC_TELNETS_PORT": "0"}, false},
		{map[string]string{"SANCTUARY_PUBLIC_WS_PORT": "65536"}, false},
		{map[string]string{"SANCTUARY_PUBLIC_TELNET_PORT": "telnet"}, false},
	} {
		s, o := declare()
		if err := s.Parse(nil, func(k string) (string, bool) { v, ok := c.env[k]; return v, ok }); err != nil {
			t.Fatal(err)
		}
		if err := checkPorts(o); (err == nil) != c.ok {
			t.Errorf("checkPorts with %v = %v, want ok %v", c.env, err, c.ok)
		}
	}
}
