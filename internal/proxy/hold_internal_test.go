package proxy

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/realmproto"
	"sanctuary/internal/session"
	"sanctuary/internal/session/sessiontest"
)

// A realm whose link has failed but which the hub has not yet removed (the
// moment between its writer stopping and its reader noticing) must not
// send a held player round attach, fail, hold, attach... with a hold
// message each time (red team round 3 suspect). In-package, because that
// moment cannot be held open from outside.
func TestFailingRealmDoesNotSpinHeldPlayers(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewHub(HubConfig{Log: quiet})
	gw, realmEnd := realmproto.Pipe()
	t.Cleanup(func() { gw.Close(); realmEnd.Close() })
	w := realmproto.NewWriter(gw, realmproto.WriterLimits{})
	w.Close() // the writer has stopped: every Send now fails
	r := &Realm{ID: "live", conn: gw, w: w, log: quiet, sessions: map[uint64]*attached{}, gone: make(chan struct{})}
	h.mu.Lock()
	h.realms["live"] = r
	h.notify()
	h.mu.Unlock()

	p := sessiontest.New(t, Handler{Hub: h, Realm: "live", Hold: time.Second})
	holds := 0
	for end := time.Now().Add(250 * time.Millisecond); time.Now().Before(end); {
		o, err := p.Client.Next(10 * time.Millisecond)
		if err != nil {
			continue // nothing within 10ms; keep watching until the end
		}
		if txt, ok := o.(session.Text); ok && strings.Contains(txt.Text, "unavailable for the moment") {
			holds++
		}
	}
	if holds > 1 {
		t.Fatalf("held player was told %d times in 250ms: attaching to a failing realm loops", holds)
	}
}
