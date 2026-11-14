package main

import (
	"testing"
)

// The example settings in deploy/ must use only real settings: a renamed or
// removed setting would otherwise leave compose silently using a default.
func TestDeployFileUsesRealSettings(t *testing.T) {
	s, _ := declare()
	noEnv := func(string) (string, bool) { return "", false }
	if err := s.Parse([]string{"-config", "../../deploy/realm-stub.env"}, noEnv); err != nil {
		t.Fatalf("deploy/realm-stub.env: %v", err)
	}
	if w := s.Warnings(); len(w) > 0 {
		t.Fatalf("deploy/realm-stub.env has keys that are not settings: %q", w)
	}
}
