package cli_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/cli"
)

// Durations in the commands' logs read as "20s", not 20000000000.
func TestDurationsLogReadably(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(cli.NewHandler(&buf, slog.LevelInfo))
	log.Info("draining", "deadline", 20*time.Second, "for", 2*time.Minute, "players", 2)
	out := buf.String()
	for _, want := range []string{`"deadline":"20s"`, `"for":"2m0s"`, `"players":2`} {
		if !strings.Contains(out, want) {
			t.Errorf("log line %s lacks %s", out, want)
		}
	}
}

func TestSplitList(t *testing.T) {
	got := cli.SplitList(" a, ,b,,c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("SplitList = %q, want [a b c]", got)
	}
}
