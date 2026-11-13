package session_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sentience/internal/session"
)

var discardLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// smallQueuePolicy makes overflow reachable with a handful of messages.
var smallQueuePolicy = session.QueuePolicy{
	MaxBytes:      1000,
	MaxMessages:   100,
	GMCPSoftBytes: 300,
	DrainTimeout:  time.Second,
}

const waitTimeout = 2 * time.Second

// newSession returns a session over an in-memory pipe whose client end
// buffers outBuffer events. outBuffer 0 models a client that never reads:
// the session's writer blocks on the first message and the rest queue.
func newSession(t *testing.T, policy session.QueuePolicy, outBuffer int) (*session.Session, *session.MemClient) {
	t.Helper()
	tr, client := session.NewMemPipe(outBuffer)
	s := session.New(tr, policy, discardLog)
	t.Cleanup(func() { s.Close(); client.Hangup() })
	return s, client
}

func waitDone(t *testing.T, s *session.Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(waitTimeout):
		t.Fatalf("session not closed within %v", waitTimeout)
	}
}

// ---------------------------------------------------------------- queue policy

// A slow client must never stall the code producing output (in stage 02, a
// realm's tick), so Send never blocks.
func TestSendDoesNotBlockOnStalledClient(t *testing.T) {
	s, _ := newSession(t, smallQueuePolicy, 0)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			s.Send(session.Text{Text: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("Send blocked on a stalled client")
	}
}

// Text is never dropped silently: a screen-reader user cannot glance back
// at what scrolled past. Overflow disconnects instead.
func TestTextOverflowDisconnects(t *testing.T) {
	s, _ := newSession(t, smallQueuePolicy, 0)
	line := session.Text{Text: strings.Repeat("x", 100)}
	var err error
	for i := 0; i < 50 && err == nil; i++ {
		err = s.Send(line)
	}
	if !errors.Is(err, session.ErrOverflow) {
		t.Fatalf("Send error = %v, want ErrOverflow", err)
	}
	waitDone(t, s)
	if !errors.Is(s.Err(), session.ErrOverflow) {
		t.Fatalf("Err() = %v, want ErrOverflow", s.Err())
	}
}

// GMCP is state, superseded by the next update, so it is dropped above the
// soft limit, leaving headroom for text before the hard limit.
func TestGMCPDroppedAboveSoftLimit(t *testing.T) {
	s, _ := newSession(t, smallQueuePolicy, 0)
	vitals := session.GMCPOut{Package: "Char.Vitals", Data: json.RawMessage(`{"hp":100,"maxhp":100,"padding":"............"}`)}
	for i := 0; i < 40; i++ {
		if err := s.Send(vitals); err != nil {
			t.Fatalf("GMCP send %d: %v, want nil (drops are silent)", i, err)
		}
	}
	if s.Dropped() == 0 {
		t.Fatal("Dropped() = 0, want GMCP drops above the soft limit")
	}
	select {
	case <-s.Done():
		t.Fatal("session closed; GMCP overflow must not disconnect")
	default:
	}
	if err := s.Send(session.Text{Text: "still here"}); err != nil {
		t.Fatalf("text after GMCP drops: %v, want nil", err)
	}
}

// ---------------------------------------------------------------- close

func TestCloseDrainsQueuedOutputInOrder(t *testing.T) {
	s, client := newSession(t, session.DefaultPolicy, 0)
	for i := 0; i < 5; i++ {
		if err := s.Send(session.Text{Text: string(rune('a' + i))}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	s.Close()
	if err := s.Send(session.Text{Text: "late"}); !errors.Is(err, session.ErrClosed) {
		t.Fatalf("Send after Close = %v, want ErrClosed", err)
	}
	var got []string
	for {
		o, err := client.Next(waitTimeout)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("after %q: %v", got, err)
		}
		txt, ok := o.(session.Text)
		if !ok {
			t.Fatalf("got %#v, want Text", o)
		}
		got = append(got, txt.Text)
	}
	if strings.Join(got, "") != "abcde" {
		t.Fatalf("drained %q, want a b c d e in order", got)
	}
}

// A client that never reads must not hold a closing session open forever.
func TestCloseGivesUpAfterDrainTimeout(t *testing.T) {
	policy := smallQueuePolicy
	policy.DrainTimeout = 100 * time.Millisecond
	s, _ := newSession(t, policy, 0)
	if err := s.Send(session.Text{Text: "never read"}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s.Close()
	waitDone(t, s)
	// If Close skipped draining, it would finish well before the timeout.
	if elapsed := time.Since(start); elapsed < policy.DrainTimeout {
		t.Fatalf("closed after %v, before the %v drain timeout: queued output was not given a chance", elapsed, policy.DrainTimeout)
	}
}

// ---------------------------------------------------------------- client identity

func TestClientUpdateTracked(t *testing.T) {
	s, client := newSession(t, session.DefaultPolicy, 8)
	if err := client.Send(session.ClientUpdate{Info: session.ClientInfo{Name: "TinTin++", MTTS: session.MTTSScreenReader, HasMTTS: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recv(); err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if c := s.Client(); c.Name != "TinTin++" || !c.ScreenReader() {
		t.Fatalf("Client() = %q screen reader %v, want TinTin++ true", c.Name, c.ScreenReader())
	}
}

// Name and version come as a pair from one source: MNES, then Core.Hello,
// then the TTYPE name.
func TestClientIdentityPrecedence(t *testing.T) {
	hello := session.GMCP{Package: "Core.Hello", Data: json.RawMessage(`{"client":"Mudlet\u001b[2J","version":"5.1.1"}`)}
	tests := []struct {
		name        string
		events      []session.Inbound
		wantName    string
		wantVersion string
	}{
		{"Core.Hello alone (a WebSocket client); escapes stripped",
			[]session.Inbound{hello}, "Mudlet", "5.1.1"},
		{"a later snapshot without a name keeps Core.Hello's",
			[]session.Inbound{hello, session.ClientUpdate{Info: session.ClientInfo{Terminal: "ANSI"}}}, "Mudlet", "5.1.1"},
		{"Core.Hello's spelling and version replace the TTYPE name",
			[]session.Inbound{hello, session.ClientUpdate{Info: session.ClientInfo{Name: "MUDLET", NameSource: session.SourceTTYPE}}}, "Mudlet", "5.1.1"},
		{"an MNES name wins, without another client's version",
			[]session.Inbound{hello, session.ClientUpdate{Info: session.ClientInfo{Name: "TinTin++", NameSource: session.SourceMNES}}}, "TinTin++", ""},
		{"an MNES name for the same client borrows Core.Hello's version",
			[]session.Inbound{hello, session.ClientUpdate{Info: session.ClientInfo{Name: "mudlet", NameSource: session.SourceMNES}}}, "mudlet", "5.1.1"},
		{"Core.Hello without a version keeps one reported elsewhere for the same client",
			[]session.Inbound{
				session.ClientUpdate{Info: session.ClientInfo{Name: "MUDLET", Version: "4.19", NameSource: session.SourceTTYPE}},
				session.GMCP{Package: "Core.Hello", Data: json.RawMessage(`{"client":"Mudlet"}`)},
			}, "Mudlet", "4.19"},
		{"non-object and non-string payloads are ignored",
			[]session.Inbound{hello,
				session.GMCP{Package: "Core.Hello", Data: json.RawMessage(`["not","an","object"]`)},
				session.GMCP{Package: "Core.Hello", Data: json.RawMessage(`{"client":42}`)},
			}, "Mudlet", "5.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, client := newSession(t, session.DefaultPolicy, 8)
			for i, ev := range tt.events {
				if err := client.Send(ev); err != nil {
					t.Fatalf("event %d: send: %v", i, err)
				}
				if _, err := s.Recv(); err != nil {
					t.Fatalf("event %d: Recv: %v", i, err)
				}
			}
			if c := s.Client(); c.Name != tt.wantName || c.Version != tt.wantVersion {
				t.Fatalf("Client() = %q %q, want %q %q", c.Name, c.Version, tt.wantName, tt.wantVersion)
			}
		})
	}
}

// ---------------------------------------------------------------- registry

func TestRegistryLimits(t *testing.T) {
	r := session.NewRegistry()
	const maxTotal, maxPerHost = 2, 1
	steps := []struct {
		do   string // "reserve" or "release"
		host string
		want bool // for reserve: whether it succeeds
	}{
		{"reserve", "a", true},
		{"reserve", "a", false}, // per-host limit
		{"reserve", "b", true},
		{"reserve", "c", false}, // total limit
		{"release", "a", false},
		{"reserve", "c", true}, // the released slot is reusable
	}
	for i, st := range steps {
		if st.do == "release" {
			r.Release(st.host)
			continue
		}
		if got := r.Reserve(st.host, maxTotal, maxPerHost); got != st.want {
			t.Fatalf("step %d: Reserve(%q) = %v, want %v", i, st.host, got, st.want)
		}
	}
}

// MaxBytes bounds bytes queued, not bytes ever sent: a client that keeps
// reading must be able to receive far more than MaxBytes over a session.
func TestQueueBytesReleasedAfterWrite(t *testing.T) {
	s, client := newSession(t, smallQueuePolicy, 0)
	line := strings.Repeat("x", 100) // about 116 bytes with overhead; 9 fit in MaxBytes
	for i := 0; i < 50; i++ {        // 50 lines, about 5800 bytes in all, one at a time
		if err := s.Send(session.Text{Text: line}); err != nil {
			t.Fatalf("Send %d = %v, want nil (the client is reading)", i, err)
		}
		if _, err := client.Next(waitTimeout); err != nil {
			t.Fatalf("Next %d: %v", i, err)
		}
	}
}

// MaxMessages is a hard limit separate from MaxBytes.
func TestQueueMessageLimitDisconnects(t *testing.T) {
	policy := smallQueuePolicy
	policy.MaxBytes = 1 << 20 // only the message count can trip
	s, _ := newSession(t, policy, 0)
	var err error
	for i := 0; i <= policy.MaxMessages+1 && err == nil; i++ {
		err = s.Send(session.Prompt{})
	}
	if !errors.Is(err, session.ErrOverflow) {
		t.Fatalf("Send past MaxMessages = %v, want ErrOverflow", err)
	}
}
