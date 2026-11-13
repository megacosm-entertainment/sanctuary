// Package sessiontest drives sessions through the in-memory transport: no
// sockets, no ports, no byte encoding. A test plays the client by sending
// Inbound events and asserting on Outbound ones.
package sessiontest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sentience/internal/session"
)

// Timeout bounds every wait.
const Timeout = 2 * time.Second

// Harness runs one Handler on one in-memory session.
type Harness struct {
	T       testing.TB
	Session *session.Session
	Client  *session.MemClient
	Reg     *session.Registry

	cancel context.CancelFunc
	served chan struct{}
}

// Options adjusts a Harness.
type Options struct {
	Policy    session.QueuePolicy // zero means session.DefaultPolicy
	OutBuffer int                 // client-side buffer; 0 means 256
}

// New starts h on a fresh in-memory session.
func New(t testing.TB, h session.Handler, opts ...Options) *Harness {
	t.Helper()
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.Policy == (session.QueuePolicy{}) {
		o.Policy = session.DefaultPolicy
	}
	if o.OutBuffer == 0 {
		o.OutBuffer = 256
	}
	tr, client := session.NewMemPipe(o.OutBuffer)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := session.New(tr, o.Policy, log)
	ctx, cancel := context.WithCancel(context.Background())
	hr := &Harness{T: t, Session: s, Client: client, Reg: session.NewRegistry(), cancel: cancel, served: make(chan struct{})}
	hr.Reg.Reserve("mem", 0, 0) // limits of 0 mean unlimited, so this always succeeds
	go func() {
		hr.Reg.Serve(ctx, "mem", s, h)
		close(hr.served)
	}()
	t.Cleanup(hr.Close)
	return hr
}

// Type sends a line of input.
func (h *Harness) Type(line string) {
	h.T.Helper()
	if err := h.Client.Send(session.Line{Text: line}); err != nil {
		h.T.Fatalf("send %q: %v", line, err)
	}
}

// Send sends any inbound event.
func (h *Harness) Send(ev session.Inbound) {
	h.T.Helper()
	if err := h.Client.Send(ev); err != nil {
		h.T.Fatalf("send %T: %v", ev, err)
	}
}

// Next returns the next outbound event or fails the test.
func (h *Harness) Next() session.Outbound {
	h.T.Helper()
	o, err := h.Client.Next(Timeout)
	if err != nil {
		h.T.Fatalf("waiting for output: %v", err)
	}
	return o
}

// UntilPrompt collects output up to and including the next Prompt and
// returns the concatenated Text plus the prompt. Events other than Text
// and Prompt (InputMode, GMCPOut) are skipped; use Expect or Next when
// they matter.
func (h *Harness) UntilPrompt() (text string, prompt session.Prompt) {
	h.T.Helper()
	var b strings.Builder
	for {
		switch v := h.Next().(type) {
		case session.Text:
			b.WriteString(v.Text)
		case session.Prompt:
			return b.String(), v
		}
	}
}

// ExpectText waits for Text containing want, skipping other events and
// non-matching text.
func (h *Harness) ExpectText(want string) string {
	h.T.Helper()
	var seen []string
	for {
		o, err := h.Client.Next(Timeout)
		if err != nil {
			h.T.Fatalf("waiting for text containing %q: %v; saw %q", want, err, seen)
		}
		if txt, ok := o.(session.Text); ok {
			if strings.Contains(txt.Text, want) {
				return txt.Text
			}
			seen = append(seen, txt.Text)
		}
	}
}

// Expect waits for the next event of type T and returns it, skipping
// events of other types. Use ExpectNext when order matters.
func Expect[T session.Outbound](h *Harness) T {
	h.T.Helper()
	var seen []string
	for {
		o, err := h.Client.Next(Timeout)
		if err != nil {
			var zero T
			h.T.Fatalf("waiting for %T: %v; saw %v", zero, err, seen)
		}
		if v, ok := o.(T); ok {
			return v
		}
		seen = append(seen, fmt.Sprintf("%#v", o))
	}
}

// ExpectNext returns the very next event, failing unless it has type T.
func ExpectNext[T session.Outbound](h *Harness) T {
	h.T.Helper()
	o := h.Next()
	v, ok := o.(T)
	if !ok {
		var zero T
		h.T.Fatalf("next event is %#v, want %T", o, zero)
	}
	return v
}

// ExpectClosed waits for the server to close the session.
func (h *Harness) ExpectClosed() {
	h.T.Helper()
	for {
		_, err := h.Client.Next(Timeout)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			h.T.Fatalf("waiting for close: %v", err)
		}
	}
}

// Shutdown cancels the handler's context, as gateway shutdown does.
func (h *Harness) Shutdown() { h.cancel() }

// Close hangs up and waits for the handler to finish.
func (h *Harness) Close() {
	h.cancel()
	h.Client.Hangup()
	select {
	case <-h.served:
	case <-time.After(Timeout):
		h.T.Errorf("handler did not exit after hangup")
	}
}
