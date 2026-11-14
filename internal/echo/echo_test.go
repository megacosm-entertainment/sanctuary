package echo_test

import (
	"encoding/json"
	"strings"
	"testing"

	"sanctuary/internal/echo"
	"sanctuary/internal/session"
	"sanctuary/internal/session/sessiontest"
)

// start runs the echo handler and consumes its banner and first prompt.
func start(t *testing.T) *sessiontest.Harness {
	t.Helper()
	h := sessiontest.New(t, echo.Handler{})
	h.UntilPrompt()
	return h
}

// infoFields parses /info output ("Key:   value" lines) into a map, so
// tests check values without depending on column alignment.
func infoFields(out string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && !strings.HasPrefix(line, " ") {
			fields[k] = strings.TrimSpace(v)
		}
	}
	return fields
}

func TestBannerAndPrompt(t *testing.T) {
	h := sessiontest.New(t, echo.Handler{})
	banner, p := h.UntilPrompt()
	if !strings.Contains(banner, "echo mode") || p.Text != "> " {
		t.Fatalf("banner %q prompt %q, want an echo-mode banner and \"> \"", banner, p.Text)
	}
}

func TestEchoesInput(t *testing.T) {
	h := start(t)
	h.Type("hello, world")
	if out, _ := h.UntilPrompt(); out != "You said: hello, world\n" {
		t.Fatalf("got %q, want %q", out, "You said: hello, world\n")
	}
}

// The handler must be safe on its own even though transports sanitise
// input too: the in-memory transport does not, so this exercises the
// handler's own defence.
func TestEchoStripsControlSequences(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"SGR colour", "a\x1b[31mred\x1b[0m", "ared"},
		{"OSC 8 hyperlink", "\x1b]8;;http://evil\x07link\x1b]8;;\x07", "link"},
		{"window title", "\x1b]0;pwned\x07x", "x"},
		{"bidi override", "‮txt", "txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := start(t)
			h.Type(tt.in)
			if out, _ := h.UntilPrompt(); out != "You said: "+tt.want+"\n" {
				t.Fatalf("got %q, want %q", out, "You said: "+tt.want+"\n")
			}
		})
	}
}

func TestSecretHidesInputThenRestoresEcho(t *testing.T) {
	h := start(t)
	h.Type("/secret")
	// Order matters: echo must be off before the prompt invites typing.
	if m := sessiontest.ExpectNext[session.InputMode](h); !m.Hidden {
		t.Fatal("first event: InputMode{Hidden: false}, want hidden")
	}
	if p := sessiontest.ExpectNext[session.Prompt](h); p.Text != "Secret: " {
		t.Fatalf("prompt %q, want \"Secret: \"", p.Text)
	}
	h.Type("hunter2")
	if m := sessiontest.ExpectNext[session.InputMode](h); m.Hidden {
		t.Fatal("after the secret: InputMode{Hidden: true}, want echo restored")
	}
	out, _ := h.UntilPrompt()
	if strings.Contains(out, "hunter2") {
		t.Fatalf("secret echoed back: %q", out)
	}
	if !strings.Contains(out, "7 characters") {
		t.Fatalf("got %q, want a character count of 7", out)
	}
}

func TestInfoReportsClient(t *testing.T) {
	h := start(t)
	h.Send(session.ClientUpdate{Info: session.ClientInfo{
		Name: "MUDLET", Version: "4.19", NameSource: session.SourceTTYPE,
		Terminal: "ANSI-TRUECOLOR\x1b[2J", // client-supplied: the escape must not reach output
		MTTS:     session.MTTSScreenReader | session.MTTSUTF8, HasMTTS: true,
		Charset: "UTF-8", Width: 120, Height: 40,
	}})
	h.Send(session.GMCP{Package: "Core.Hello", Data: json.RawMessage(`{"client":"Mudlet"}`)})
	h.Type("/info")
	out, _ := h.UntilPrompt()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("client-supplied escape reached output: %q", out)
	}
	got := infoFields(out)
	want := map[string]string{
		"Client":   "Mudlet 4.19", // Core.Hello spelling, version kept for the same client
		"Terminal": "ANSI-TRUECOLOR",
		"Window":   "120 x 40",
		"MTTS":     "68 (screen reader: true)",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("/info %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestQuitCloses(t *testing.T) {
	for _, cmd := range []string{"/quit", "/QUIT", "  /Quit  "} { // commands ignore case and padding
		t.Run(cmd, func(t *testing.T) {
			h := start(t)
			h.Type(cmd)
			h.ExpectText("Goodbye")
			h.ExpectClosed()
		})
	}
}

func TestInfoWithoutClientReports(t *testing.T) {
	h := start(t)
	h.Type("/info")
	out, _ := h.UntilPrompt()
	got := infoFields(out)
	for k, want := range map[string]string{"Client": "(not reported)", "Window": "not reported", "MTTS": "not reported"} {
		if got[k] != want {
			t.Errorf("/info %s = %q, want %q", k, got[k], want)
		}
	}
}

func TestShutdownSaysGoodbye(t *testing.T) {
	h := start(t)
	h.Shutdown()
	h.ExpectText("shutting down")
	h.ExpectClosed()
}
