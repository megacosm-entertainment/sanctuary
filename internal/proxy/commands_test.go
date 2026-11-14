package proxy_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/proxy"
	"sanctuary/internal/realmproto"
	rpt "sanctuary/internal/realmproto/realmprototest"
	"sanctuary/internal/session"
	"sanctuary/internal/session/sessiontest"
)

func TestParseCommand(t *testing.T) {
	for _, c := range []struct {
		prefix, line, name, rest string
		ok                       bool
	}{
		{">", ">lobby", "lobby", "", true},
		{">", "  >LOBBY  now please ", "lobby", "now please", true},
		{">", "> quoted text", "", "", false}, // a pasted quote is ordinary text
		{">", ">", "", "", false},
		{">", ">1", "", "", false},
		{">", "lobby", "", "", false},
		{">", "/lobby", "", "", false},
		{"/", "/lobby", "lobby", "", true},
		{"/", ">lobby", "", "", false},
	} {
		name, rest, ok := proxy.ParseCommand(c.prefix, c.line)
		if name != c.name || rest != c.rest || ok != c.ok {
			t.Errorf("ParseCommand(%q, %q) = %q, %q, %v; want %q, %q, %v", c.prefix, c.line, name, rest, ok, c.name, c.rest, c.ok)
		}
	}
}

func TestCheckPrefix(t *testing.T) {
	for _, good := range []string{">", "/", "!", "~", "+"} {
		if err := proxy.CheckPrefix(good); err != nil {
			t.Errorf("CheckPrefix(%q) = %v", good, err)
		}
	}
	for _, bad := range []string{"", ">>", "a", "Z", "7", " ", "\t", "é", "\x7f"} {
		if proxy.CheckPrefix(bad) == nil {
			t.Errorf("CheckPrefix(%q) accepted", bad)
		}
	}
}

// expectInput fails unless the realm's next input for the player is want:
// anything typed before it was kept from the realm.
func expectInput(t *testing.T, realm *rpt.Peer, want string) {
	t.Helper()
	if in := rpt.Expect[*realmproto.Input](realm); in.Text != want {
		t.Fatalf("realm received %q, want %q (a gateway command leaked through?)", in.Text, want)
	}
}

func TestGatewayCommandsInARealm(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	h.register(t, "other")
	p, _ := player(t, h, realm, proxy.Handler{Realm: "live"})

	p.Type(">help")
	p.ExpectText("leave this realm")
	p.Type(">realms")
	text := p.ExpectText("Realms:")
	if !strings.Contains(text, "Realm live (you are here)") || !strings.Contains(text, "Realm other") {
		t.Fatalf(">realms = %q", text)
	}
	p.Type(">frobnicate")
	p.ExpectText("no gateway command '>frobnicate'")
	p.Type("> a quoted line")
	expectInput(t, realm, "> a quoted line")

	p.Type(">lobby")
	p.ExpectText("Leaving the realm")
	if c := rpt.Expect[*realmproto.SessionClosed](realm); c.Reason != realmproto.ClosedQuit {
		t.Fatalf("realm told %q, want quit", c.Reason)
	}
	p.ExpectClosed() // ServeSession has no lobby to go back to
}

func TestGatewayQuitFromARealm(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, _ := player(t, h, realm, proxy.Handler{})
	p.Type(">quit")
	p.ExpectText("Goodbye")
	if c := rpt.Expect[*realmproto.SessionClosed](realm); c.Reason != realmproto.ClosedQuit {
		t.Fatalf("realm told %q, want quit", c.Reason)
	}
	p.ExpectClosed()
}

// While the realm hides input (a password prompt), every line is the
// realm's, even one that looks like a gateway command.
func TestHiddenInputIsNeverACommand(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, open := player(t, h, realm, proxy.Handler{})
	realm.Send(&realmproto.InputMode{Session: open.Session, Hidden: true})
	sessiontest.Expect[session.InputMode](p)
	p.Type(">lobby")
	expectInput(t, realm, ">lobby")
}

func TestCustomPrefix(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p := sessiontest.New(t, proxy.Handler{Hub: h.Hub, Prefix: "/"})
	rpt.Expect[*realmproto.SessionOpen](realm)
	if txt := sessiontest.ExpectNext[session.Text](p); !strings.Contains(txt.Text, "'/lobby'") {
		t.Fatalf("entry hint %q, want /lobby", txt.Text)
	}
	p.Type(">lobby") // just text, with this prefix
	expectInput(t, realm, ">lobby")
	p.Type("/lobby")
	rpt.Expect[*realmproto.SessionClosed](realm)
	p.ExpectClosed()
}

// A player held for a realm that went away can leave instead of waiting.
func TestLobbyWhileHeld(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, _ := player(t, h, realm, proxy.Handler{Hold: time.Minute})
	realm.Conn.Close()
	p.ExpectText("Hold on")
	p.Type("hello?")
	p.ExpectText("Still waiting")
	p.Type(">lobby")
	p.ExpectText("Leaving the realm")
	p.ExpectClosed()
}

// Realms learn the prefix from welcome, so their help can name it.
func TestWelcomeCarriesThePrefix(t *testing.T) {
	h := newHub(t, proxy.HubConfig{CommandPrefix: "/"})
	realm, _ := h.connect(t)
	realm.Send(&realmproto.Hello{Versions: []int{realmproto.Version}, Realm: "live"})
	if w := rpt.Expect[*realmproto.Welcome](realm); w.CommandPrefix != "/" {
		t.Fatalf("welcome = %+v, want command_prefix /", w)
	}
}

// Under a lobby, >lobby and >quit while held differ: one comes Back, the
// other is Gone.
func TestHeldCommandOutcomes(t *testing.T) {
	for cmd, want := range map[string]proxy.Outcome{">lobby": proxy.Back, ">quit": proxy.Gone} {
		t.Run(cmd, func(t *testing.T) {
			h := newHub(t, proxy.HubConfig{})
			realm := h.register(t, "live")
			got := make(chan proxy.Outcome, 1)
			handler := proxy.Handler{Hub: h.Hub, Hold: time.Minute}
			p := sessiontest.New(t, session.HandlerFunc(func(ctx context.Context, s *session.Session) {
				got <- handler.Play(ctx, s, session.NewInbox(s))
			}))
			rpt.Expect[*realmproto.SessionOpen](realm)
			realm.Conn.Close()
			p.ExpectText("Hold on")
			p.Type(cmd)
			select {
			case o := <-got:
				if o != want {
					t.Fatalf("Play = %v, want %v", o, want)
				}
			case <-time.After(rpt.Timeout):
				t.Fatal("Play did not return")
			}
		})
	}
}

// The realm never sees a gateway command, so it will not prompt again; the
// gateway repeats the realm's last prompt after answering.
func TestPromptRepeatedAfterGatewayCommand(t *testing.T) {
	h := newHub(t, proxy.HubConfig{})
	realm := h.register(t, "live")
	p, open := player(t, h, realm, proxy.Handler{})
	realm.Send(&realmproto.Prompt{Session: open.Session, Text: "HP 10> "})
	if got := sessiontest.ExpectNext[session.Prompt](p); got.Text != "HP 10> " {
		t.Fatalf("prompt %q", got.Text)
	}
	p.Type(">help")
	sessiontest.ExpectNext[session.Text](p)
	if got := sessiontest.ExpectNext[session.Prompt](p); got.Text != "HP 10> " {
		t.Fatalf("after >help, prompt %q, want the realm's last", got.Text)
	}
}
