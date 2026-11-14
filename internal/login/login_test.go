package login

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/account"
	"sanctuary/internal/proxy"
	"sanctuary/internal/realm"
	"sanctuary/internal/realmproto"
	"sanctuary/internal/session"
	"sanctuary/internal/session/sessiontest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// cheap keeps hashing fast in tests; the cost is not what is under test.
var cheap = account.Params{MemoryKiB: 64, Passes: 1, Lanes: 1}

const goodPassword = "correct horse battery"

type fixture struct {
	t     *testing.T
	store *account.FileStore
	cfg   Config
	key   *account.SecretKey
}

// newFixture is a front door with a file store and the stub realm (the
// echo handler) registered on its hub.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	store, err := account.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := account.NewSecretKey(make([]byte, account.KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	hub := proxy.NewHub(proxy.HubConfig{Gateway: "test", Log: quiet})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	gwEnd, realmEnd := realmproto.Pipe()
	go hub.Serve(ctx, gwEnd)
	go realm.Serve(ctx, realmEnd, realm.Config{ID: "stub", Name: "Stub realm", Build: "test", Handler: realm.StubHandler, Log: quiet})
	deadline := time.Now().Add(sessiontest.Timeout)
	for len(hub.Realms()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("stub realm did not register")
		}
		time.Sleep(time.Millisecond)
	}
	return &fixture{t: t, store: store, key: key, cfg: Config{
		Store:    store,
		Names:    account.DefaultNames,
		Hasher:   account.NewHasher(cheap, 4),
		Key:      key,
		Throttle: NewThrottle(),
		Signup:   SignupOpen,
		Realms:   proxy.Handler{Hub: hub, Wait: time.Second, Hold: time.Second},
	}}
}

func (f *fixture) start(opts ...sessiontest.Options) *sessiontest.Harness {
	f.t.Helper()
	h, err := New(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return sessiontest.New(f.t, h, opts...)
}

// add stores an account with password pw.
func (f *fixture) add(name, pw string, edit ...func(*account.Account)) *account.Account {
	f.t.Helper()
	hash, err := f.cfg.Hasher.Hash(context.Background(), pw)
	if err != nil {
		f.t.Fatal(err)
	}
	id, _ := account.NewID()
	a := &account.Account{ID: id, Name: name, Created: time.Now(), Password: hash}
	for _, e := range edit {
		e(a)
	}
	if err := f.store.Create(context.Background(), a); err != nil {
		f.t.Fatal(err)
	}
	return a
}

// prompt reads up to the next prompt and checks it, returning the text
// before it.
func prompt(t *testing.T, h *sessiontest.Harness, want string) string {
	t.Helper()
	text, p := h.UntilPrompt()
	if !strings.Contains(p.Text, want) {
		t.Fatalf("prompt = %q (after %q), want one containing %q", p.Text, text, want)
	}
	return text
}

// hiddenPrompt checks that echo is off when a password prompt arrives.
func hiddenPrompt(t *testing.T, h *sessiontest.Harness, want string) string {
	t.Helper()
	var b strings.Builder
	hidden := false
	for {
		switch v := h.Next().(type) {
		case session.Text:
			b.WriteString(v.Text)
		case session.InputMode:
			hidden = v.Hidden
		case session.Prompt:
			if !hidden {
				t.Fatalf("prompt %q arrived with echo on (wanted %q, hidden)", v.Text, want)
			}
			if !strings.Contains(v.Text, want) {
				t.Fatalf("prompt = %q (after %q), want one containing %q", v.Text, b.String(), want)
			}
			return b.String()
		}
	}
}

func contains(t *testing.T, text, want string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Fatalf("output %q does not contain %q", text, want)
	}
}

func login(t *testing.T, h *sessiontest.Harness, name, pw string) string {
	t.Helper()
	prompt(t, h, "Account name")
	h.Type(name)
	hiddenPrompt(t, h, "Password")
	h.Type(pw)
	return prompt(t, h, "")
}

func TestSignUpThenPlayThenLogBackIn(t *testing.T) {
	f := newFixture(t)
	h := f.start()
	contains(t, prompt(t, h, "Account name"), "Welcome")
	h.Type("new")
	prompt(t, h, "Choose an account name")
	h.Type("Alice")
	hiddenPrompt(t, h, "New password")
	h.Type("short")
	contains(t, hiddenPrompt(t, h, "New password"), "at least 10")
	h.Type(goodPassword)
	hiddenPrompt(t, h, "again")
	h.Type(goodPassword + "x")
	contains(t, hiddenPrompt(t, h, "New password"), "different")
	h.Type(goodPassword)
	hiddenPrompt(t, h, "again")
	h.Type(goodPassword)
	lobby := prompt(t, h, "Enter for Stub realm")
	contains(t, lobby, "Account Alice created")
	contains(t, lobby, "1. Stub realm")
	if a := h.Session.Account(); a.Name != "Alice" || a.ID == "" {
		t.Fatalf("session account = %+v, want Alice with an id", a)
	}

	// Into the realm, which learns who this is from session.open.
	h.Type("")
	prompt(t, h, ">")
	h.Type("info")
	contains(t, prompt(t, h, ">"), "Account:       Alice")
	// Quitting the realm comes back to the lobby, still connected.
	h.Type("quit")
	contains(t, prompt(t, h, "Realm"), "back in the lobby")
	h.Type("quit")
	h.ExpectText("Goodbye")
	h.ExpectClosed()

	// The account is stored, and the name is not case-sensitive.
	h2 := f.start()
	contains(t, login(t, h2, "alice", goodPassword), "Hello, Alice")
}

func TestWrongNameAndWrongPasswordLookTheSame(t *testing.T) {
	f := newFixture(t)
	f.add("Bob", goodPassword)
	h := f.start()
	unknown := login(t, h, "Nobody", goodPassword)
	h.Type("Bob")
	hiddenPrompt(t, h, "Password")
	h.Type("wrong password")
	wrong := prompt(t, h, "Account name")
	if unknown != wrong || !strings.Contains(wrong, msgWrong) {
		t.Fatalf("unknown name said %q, wrong password said %q; want the same %q", unknown, wrong, msgWrong)
	}
	if h.Session.Account().LoggedIn() {
		t.Fatal("logged in after failures")
	}
	h.Type("Bob")
	hiddenPrompt(t, h, "Password")
	h.Type("wrong again")
	h.ExpectText(msgTooMany)
	h.ExpectClosed()
}

func TestThrottleSpansConnections(t *testing.T) {
	f := newFixture(t)
	f.add("Bob", goodPassword)
	now := time.Unix(1_000_000, 0)
	f.cfg.Throttle.now = func() time.Time { return now }
	// Fill the free attempts and the queue for Bob, as many connections
	// from elsewhere would.
	for i := 0; i < 20; i++ {
		f.cfg.Throttle.Begin(nameKey("bob"))
	}
	h := f.start()
	text := login(t, h, "Bob", goodPassword) // the right password, refused unchecked
	contains(t, text, "Too many recent failed logins")
	if h.Session.Account().LoggedIn() {
		t.Fatal("logged in past the throttle")
	}
}

func TestSignupModes(t *testing.T) {
	t.Run("staff", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.Signup = SignupStaff
		h := f.start()
		prompt(t, h, "Account name")
		h.Type("new")
		contains(t, prompt(t, h, "Account name"), "created by staff")
	})
	t.Run("invite", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.Signup = SignupInvite
		code, _ := account.NewInviteCode()
		if err := f.store.AddInvite(context.Background(), code, "staff", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		signup := func(h *sessiontest.Harness, code, name string) string {
			prompt(t, h, "Account name")
			h.Type("new")
			prompt(t, h, "Invite code")
			h.Type(code)
			prompt(t, h, "Choose")
			h.Type(name)
			hiddenPrompt(t, h, "New password")
			h.Type(goodPassword)
			hiddenPrompt(t, h, "again")
			h.Type(goodPassword)
			return prompt(t, h, "")
		}
		contains(t, signup(f.start(), "AAAAA-BBBBB", "Carol"), "not valid")
		contains(t, signup(f.start(), code, "Carol"), "Account Carol created")
		contains(t, signup(f.start(), code, "Dave"), "not valid") // used once only
	})
}

func TestNewNamesAreChecked(t *testing.T) {
	f := newFixture(t)
	f.add("Erin", goodPassword)
	f.cfg.Names, _ = account.NewNames([]string{"Thoth"}, false)
	h := f.start()
	prompt(t, h, "Account name")
	h.Type("new")
	prompt(t, h, "Choose")
	for name, want := range map[string]string{"erin": "taken", "Thoth": "reserved", "admin": "reserved", "x": "letters and digits"} {
		h.Type(name)
		contains(t, prompt(t, h, "Choose"), want)
	}
}

func TestPlaintextConnections(t *testing.T) {
	plain := &session.Meta{Kind: "telnet", Remote: "192.0.2.1:5000", Secure: false}
	t.Run("warned", func(t *testing.T) {
		f := newFixture(t)
		f.add("Bob", goodPassword)
		f.cfg.SecureHint = "telnet over TLS on port 9010"
		h := f.start(sessiontest.Options{Meta: plain})
		prompt(t, h, "Account name")
		h.Type("Bob")
		text := hiddenPrompt(t, h, "Password")
		contains(t, text, "not encrypted")
		contains(t, text, "port 9010")
	})
	t.Run("encrypted is not warned", func(t *testing.T) {
		f := newFixture(t)
		h := f.start()
		prompt(t, h, "Account name")
		h.Type("Bob")
		if text := hiddenPrompt(t, h, "Password"); strings.Contains(text, "not encrypted") {
			t.Fatalf("warned on an encrypted connection: %q", text)
		}
	})
	t.Run("refused", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.RefusePlaintext = true
		h := f.start(sessiontest.Options{Meta: plain})
		h.ExpectText("only accepts logins over an encrypted connection")
		h.ExpectClosed()
	})
}

func TestLoginTimesOut(t *testing.T) {
	f := newFixture(t)
	f.cfg.Timeout = 100 * time.Millisecond
	h := f.start()
	prompt(t, h, "Account name")
	h.ExpectText("took too long")
	h.ExpectClosed()
}

func TestShutdownDuringLogin(t *testing.T) {
	f := newFixture(t)
	h := f.start()
	prompt(t, h, "Account name")
	h.Shutdown()
	h.ExpectText("shutting down")
	h.ExpectClosed()
}

func TestSecondFactor(t *testing.T) {
	f := newFixture(t)
	now := time.Unix(1_700_000_000, 0)
	f.cfg.now = func() time.Time { return now }
	secret, _ := account.NewTOTPSecret()
	shown, stored, _ := account.NewRecoveryCodes()
	a := f.add("Fay", goodPassword, func(a *account.Account) {
		sealed, err := f.key.Seal(secret, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		a.TOTP = &account.TOTPState{Sealed: sealed}
		a.Recovery = stored
	})

	h := f.start()
	contains(t, login(t, h, "Fay", goodPassword), "")
	h.Type("000000")
	contains(t, prompt(t, h, "Authenticator code"), "not right")
	code := account.TOTPCode(secret, now)
	h.Type(code)
	prompt(t, h, "Realm")
	if !h.Session.Account().LoggedIn() {
		t.Fatal("not logged in after a good code")
	}

	// The same code again (an observer replaying it) is refused.
	h2 := f.start()
	login(t, h2, "Fay", goodPassword)
	h2.Type(code)
	contains(t, prompt(t, h2, "Authenticator code"), "not right")
	// A recovery code works once.
	h2.Type(strings.ToLower(shown[3]))
	contains(t, prompt(t, h2, "Realm"), "You have 9 left")
	got, _ := f.store.Get(context.Background(), a.Name)
	if len(got.Recovery) != 9 || got.TOTP.LastStep != now.Unix()/30 {
		t.Fatalf("stored: %d recovery codes, last step %d; want 9 and %d", len(got.Recovery), got.TOTP.LastStep, now.Unix()/30)
	}
	h3 := f.start()
	login(t, h3, "Fay", goodPassword)
	h3.Type(shown[3])
	contains(t, prompt(t, h3, "Authenticator code"), "not right")
}

func TestDisabledAccounts(t *testing.T) {
	f := newFixture(t)
	f.add("Gus", goodPassword, func(a *account.Account) { a.Disabled = "spam" })
	h := f.start()
	// A wrong password says nothing about the account being disabled.
	contains(t, login(t, h, "Gus", "wrong password"), msgWrong)
	h.Type("Gus")
	hiddenPrompt(t, h, "Password")
	h.Type(goodPassword)
	text := h.ExpectText("disabled")
	if strings.Contains(text, "spam") {
		t.Fatalf("staff's reason shown to the player: %q", text)
	}
	h.ExpectClosed()
	if h.Session.Account().LoggedIn() {
		t.Fatal("disabled account logged in")
	}
}

func TestMustChangePassword(t *testing.T) {
	f := newFixture(t)
	f.add("Hal", goodPassword, func(a *account.Account) { a.MustChangePassword = true })
	h := f.start()
	prompt(t, h, "Account name")
	h.Type("Hal")
	hiddenPrompt(t, h, "Password")
	h.Type(goodPassword)
	contains(t, hiddenPrompt(t, h, "New password"), "reset your password")
	h.Type("a brand new passphrase")
	hiddenPrompt(t, h, "again")
	h.Type("a brand new passphrase")
	contains(t, prompt(t, h, "Realm"), "Password changed")
	got, _ := f.store.Get(context.Background(), "Hal")
	if got.MustChangePassword {
		t.Fatal("MustChangePassword still set")
	}
	if ok, _ := f.cfg.Hasher.Verify(context.Background(), got.Password, "a brand new passphrase"); !ok {
		t.Fatal("new password not stored")
	}
}

func TestWeakHashIsUpgraded(t *testing.T) {
	f := newFixture(t)
	weak := account.NewHasher(account.Params{MemoryKiB: 32, Passes: 1, Lanes: 1}, 1)
	hash, _ := weak.Hash(context.Background(), goodPassword)
	f.add("Ida", "unused password", func(a *account.Account) { a.Password = hash })
	h := f.start()
	login(t, h, "Ida", goodPassword)
	got, _ := f.store.Get(context.Background(), "Ida")
	if got.Password == hash || f.cfg.Hasher.NeedsRehash(got.Password) {
		t.Fatalf("hash not upgraded: %q", got.Password)
	}
}

func TestLobbyChoices(t *testing.T) {
	realms := []proxy.RealmInfo{{ID: "alpha", Name: "First"}, {ID: "beta", Name: "Second"}}
	for choice, want := range map[string]string{"": "alpha", "2": "beta", "BETA": "beta", "second": "beta"} {
		if got, ok := pick(realms, choice); !ok || got != want {
			t.Errorf("pick(%q) = %q, %v; want %q", choice, got, ok, want)
		}
	}
	for _, bad := range []string{"0", "3", "gamma"} {
		if got, ok := pick(realms, bad); ok {
			t.Errorf("pick(%q) = %q, want no realm", bad, got)
		}
	}
	if got, ok := pick(nil, ""); !ok || got != "" {
		t.Errorf("pick with no realms = %q, %v; want any realm", got, ok)
	}
}

func TestSignupsFromOneAddressAreLimited(t *testing.T) {
	f := newFixture(t)
	key := "signup:" + sourceOf("mem")
	// Changing your mind part way does not use up the allowance.
	h := f.start()
	prompt(t, h, "Account name")
	h.Type("new")
	prompt(t, h, "Choose")
	h.Type("")
	prompt(t, h, "Account name")
	if r := f.cfg.Throttle.recs[key]; r == nil || r.n != 0 {
		t.Fatalf("after backing out, signup record = %+v, want counted then refunded", r)
	}
	// Creating one does.
	h.Type("new")
	prompt(t, h, "Choose")
	h.Type("Jo1")
	hiddenPrompt(t, h, "New password")
	h.Type(goodPassword)
	hiddenPrompt(t, h, "again")
	h.Type(goodPassword)
	prompt(t, h, "Realm")
	if r := f.cfg.Throttle.recs[key]; r.n != 1 {
		t.Fatalf("after a signup, n = %d, want 1", r.n)
	}
	// A burst of signups is refused.
	for i := 0; i < 20; i++ {
		f.cfg.Throttle.Begin(key)
	}
	h2 := f.start()
	prompt(t, h2, "Account name")
	h2.Type("new")
	contains(t, prompt(t, h2, "Account name"), "Too many accounts")
}

// A correct login clears the account's failures and refunds the address's
// count, so a household or a NAT logging in all evening is never slowed.
func TestSuccessClearsThrottle(t *testing.T) {
	f := newFixture(t)
	f.add("Kim", goodPassword)
	f.cfg.Throttle.Begin(nameKey("kim"))
	h := f.start()
	login(t, h, "Kim", goodPassword)
	if r := f.cfg.Throttle.recs[nameKey("kim")]; r != nil {
		t.Fatalf("account's record after success = %+v, want cleared", r)
	}
	if r := f.cfg.Throttle.recs[sourceOf("mem")]; r == nil || r.n != 0 {
		t.Fatalf("address's record after success = %+v, want counted then refunded", r)
	}
}

// Two connections racing with the same code: both read the account before
// either recorded it, so only the re-check on write stops the second.
func TestRacingCodeIsUsedOnce(t *testing.T) {
	f := newFixture(t)
	now := time.Unix(1_700_000_000, 0)
	f.cfg.now = func() time.Time { return now }
	secret, _ := account.NewTOTPSecret()
	f.add("Lee", goodPassword, func(a *account.Account) {
		sealed, _ := f.key.Seal(secret, a.ID)
		a.TOTP = &account.TOTPState{Sealed: sealed}
	})
	h, err := New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	read := func() *account.Account {
		a, err := f.store.Get(context.Background(), "Lee")
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	first, second := read(), read()
	tr := &turn{h: h, ctx: context.Background()}
	code := account.TOTPCode(secret, now)
	if _, err := tr.useCode(first, secret, code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := tr.useCode(second, secret, code); !errors.Is(err, errReplay) {
		t.Fatalf("second use with a stale copy = %v, want errReplay", err)
	}
}
