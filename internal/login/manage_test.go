package login

import (
	"context"
	"encoding/base32"
	"regexp"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/account"
	"sanctuary/internal/session"
	"sanctuary/internal/session/sessiontest"
)

// clock is a test clock a fixture reads through cfg.now.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }
func (c *clock) step()          { c.t = c.t.Add(30 * time.Second) }
func (f *fixture) useClock() *clock {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	f.cfg.now = c.now
	return c
}

// inLobby logs in and waits at the lobby prompt.
func inLobby(t *testing.T, h *sessiontest.Harness, name, pw string) {
	t.Helper()
	login(t, h, name, pw)
}

var uriSecret = regexp.MustCompile(`otpauth://totp/[^?]+\?[^\s]*secret=([A-Z2-7]+)`)

// enrol sets up an authenticator from the lobby and returns its secret and
// the recovery codes shown.
func enrol(t *testing.T, h *sessiontest.Harness, clk *clock, pw string) ([]byte, []string) {
	t.Helper()
	h.Type("totp")
	hiddenPrompt(t, h, "current password")
	h.Type(pw)
	intro := prompt(t, h, "6-digit code")
	m := uriSecret.FindStringSubmatch(intro)
	if m == nil {
		t.Fatalf("no otpauth link with a secret in %q", intro)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	// The key typed by hand is the same secret, in groups of four.
	contains(t, intro, account.TOTPDisplay(secret))
	contains(t, intro, "issuer=Sanctuary")
	h.Type("123456")
	contains(t, prompt(t, h, "6-digit code"), "not right")
	h.Type(account.TOTPCode(secret, clk.now()))
	done := prompt(t, h, "Realm")
	contains(t, done, "authenticator is set up")
	codes := regexp.MustCompile(`\d+\. ([A-Z0-9]{5}-[A-Z0-9]{5})`).FindAllStringSubmatch(done, -1)
	if len(codes) != account.RecoveryCodes {
		t.Fatalf("%d recovery codes shown in %q, want %d", len(codes), done, account.RecoveryCodes)
	}
	var shown []string
	for _, c := range codes {
		shown = append(shown, c[1])
	}
	return secret, shown
}

func TestEnrolTOTPFromTheLobby(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h := f.start()
	inLobby(t, h, "Mara", goodPassword)
	secret, shown := enrol(t, h, clk, goodPassword)

	a, _ := f.store.Get(context.Background(), "Mara")
	if a.TOTP == nil || len(a.Recovery) != account.RecoveryCodes {
		t.Fatalf("stored: TOTP %v, %d recovery codes", a.TOTP, len(a.Recovery))
	}
	if strings.Contains(a.TOTP.Sealed, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)) {
		t.Fatal("secret stored unsealed")
	}
	// The code used to confirm cannot be used again to log in.
	h2 := f.start()
	login(t, h2, "Mara", goodPassword)
	h2.Type(account.TOTPCode(secret, clk.now()))
	contains(t, prompt(t, h2, "Authenticator code"), "not right")
	clk.step()
	h2.Type(account.TOTPCode(secret, clk.now()))
	prompt(t, h2, "Realm")
	// A shown recovery code works.
	h3 := f.start()
	login(t, h3, "Mara", goodPassword)
	h3.Type(shown[0])
	contains(t, prompt(t, h3, "Realm"), "You have 9 left")

	// Asking again says it is already there.
	h.Type("totp")
	contains(t, prompt(t, h, "Realm"), "already have an authenticator")
}

func TestEnrolNeedsThePassword(t *testing.T) {
	f := newFixture(t)
	f.useClock()
	f.add("Mara", goodPassword)
	h := f.start()
	inLobby(t, h, "Mara", goodPassword)
	h.Type("totp")
	hiddenPrompt(t, h, "current password")
	h.Type("not my password")
	text := prompt(t, h, "Realm")
	contains(t, text, "wrong")
	if strings.Contains(text, "otpauth") {
		t.Fatal("secret shown without the password")
	}
	h.Type("totp")
	hiddenPrompt(t, h, "current password")
	h.Type("")
	contains(t, prompt(t, h, "Realm"), "Cancelled")
	if a, _ := f.store.Get(context.Background(), "Mara"); a.TOTP != nil {
		t.Fatal("enrolled without confirming")
	}
}

func TestRemoveTOTPAndNewCodes(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h := f.start()
	inLobby(t, h, "Mara", goodPassword)
	secret, old := enrol(t, h, clk, goodPassword)

	// New codes need the password and a current code; old codes stop working.
	clk.step()
	h.Type("codes")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	prompt(t, h, "Authenticator code")
	h.Type(account.TOTPCode(secret, clk.now()))
	text := prompt(t, h, "Realm")
	contains(t, text, "no longer work")
	a, _ := f.store.Get(context.Background(), "Mara")
	if _, ok := account.UseRecoveryCode(a.Recovery, old[0]); ok {
		t.Fatal("an old recovery code still works")
	}

	// Removing needs a code too: a wrong one changes nothing.
	clk.step()
	h.Type("totp off")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	prompt(t, h, "Authenticator code")
	h.Type("")
	contains(t, prompt(t, h, "Realm"), "Cancelled")
	if a, _ := f.store.Get(context.Background(), "Mara"); a.TOTP == nil {
		t.Fatal("removed without a code")
	}
	h.Type("totp off")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	prompt(t, h, "Authenticator code")
	h.Type(account.TOTPCode(secret, clk.now()))
	contains(t, prompt(t, h, "Realm"), "authenticator is removed")
	if a, _ := f.store.Get(context.Background(), "Mara"); a.TOTP != nil || a.Recovery != nil {
		t.Fatal("authenticator still stored")
	}
	// Login no longer asks for a code.
	h2 := f.start()
	login(t, h2, "Mara", goodPassword)
}

func TestChangePasswordFromTheLobby(t *testing.T) {
	f := newFixture(t)
	f.add("Mara", goodPassword)
	h := f.start()
	inLobby(t, h, "Mara", goodPassword)
	h.Type("password")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	hiddenPrompt(t, h, "New password")
	h.Type("")
	contains(t, prompt(t, h, "Realm"), "Cancelled")

	h.Type("password")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	hiddenPrompt(t, h, "New password")
	h.Type("another long passphrase")
	hiddenPrompt(t, h, "again")
	h.Type("another long passphrase")
	contains(t, prompt(t, h, "Realm"), "Password changed")

	h2 := f.start()
	contains(t, login(t, h2, "Mara", goodPassword), "wrong")
	h3 := f.start()
	contains(t, login(t, h3, "Mara", "another long passphrase"), "Hello")
}

func TestLobbyHelpListsAccountCommands(t *testing.T) {
	f := newFixture(t)
	f.add("Mara", goodPassword)
	h := f.start()
	contains(t, login(t, h, "Mara", goodPassword), "'help'")
	h.Type("help")
	text := prompt(t, h, "Realm")
	for _, w := range []string{"password", "totp", "totp off", "codes", ">lobby", ">help"} {
		contains(t, text, w)
	}
}

// With an authenticator, a password change needs a code as well.
func TestChangePasswordNeedsCodeWithTOTP(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h := f.start()
	inLobby(t, h, "Mara", goodPassword)
	enrol(t, h, clk, goodPassword)
	h.Type("password")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	contains(t, prompt(t, h, "Authenticator code"), "confirm it is you")
	h.Type("")
	contains(t, prompt(t, h, "Realm"), "Cancelled")
}

// Authy and some other apps show 7 digits for a key entered by hand; say
// so instead of a bare "not right".
func TestWrongLengthCodeIsExplained(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h := f.start()
	inLobby(t, h, "Mara", goodPassword)
	h.Type("totp")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	intro := prompt(t, h, "6-digit code")
	// The link starts its line, so copying the line copies a valid link.
	if !strings.Contains(intro, "\notpauth://totp/") {
		t.Fatalf("link not at the start of a line: %q", intro)
	}
	contains(t, intro, "digits=6")
	h.Type("1234567")
	contains(t, prompt(t, h, "6-digit code"), "that one has 7")
	m := uriSecret.FindStringSubmatch(intro)
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	h.Type(account.TOTPCode(secret, clk.now()))
	prompt(t, h, "Realm")

	clk.step()
	h2 := f.start()
	login(t, h2, "Mara", goodPassword)
	h2.Type("123 4567")
	contains(t, prompt(t, h2, "Authenticator code"), "that one has 7")
	h2.Type(account.TOTPCode(secret, clk.now()))
	prompt(t, h2, "Realm")
}

// A failed set-up does not change the key: the app may already hold it.
func TestRetriedSetupKeepsTheKey(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h := f.start()
	inLobby(t, h, "Mara", goodPassword)
	start := func() string {
		h.Type("totp")
		hiddenPrompt(t, h, "current password")
		h.Type(goodPassword)
		intro := prompt(t, h, "6-digit code")
		return uriSecret.FindStringSubmatch(intro)[1]
	}
	first := start()
	h.Type("")
	prompt(t, h, "Realm")
	h.Type("totp")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	intro := prompt(t, h, "6-digit code")
	contains(t, intro, "Continuing the set-up you began")
	if again := uriSecret.FindStringSubmatch(intro)[1]; again != first {
		t.Fatal("a retried set-up showed a different key")
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(first)
	h.Type(account.TOTPCode(secret, clk.now()))
	contains(t, prompt(t, h, "Realm"), "authenticator is set up")
}

// A key cut short in the app (seen with Authy) is named, not just refused.
func TestTruncatedKeyIsExplained(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h := f.start()
	inLobby(t, h, "Mara", goodPassword)
	h.Type("totp")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	full := uriSecret.FindStringSubmatch(prompt(t, h, "6-digit code"))[1]
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	short, err := b32.DecodeString(full[:21])
	if err != nil {
		t.Fatal(err)
	}
	h.Type(account.TOTPCode(short, clk.now()))
	contains(t, prompt(t, h, "6-digit code"), "only the first 21 of the 32 characters")
	secret, _ := b32.DecodeString(full)
	h.Type(account.TOTPCode(secret, clk.now()))
	contains(t, prompt(t, h, "Realm"), "authenticator is set up")
}

// setupWith starts a set-up for a client that has described itself as
// info, and returns the text before the code prompt.
func setupWith(t *testing.T, f *fixture, info session.ClientInfo) (*sessiontest.Harness, string) {
	t.Helper()
	h := f.start()
	h.Send(session.ClientUpdate{Info: info})
	inLobby(t, h, "Mara", goodPassword)
	h.Type("totp")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	return h, prompt(t, h, "6-digit code")
}

func TestQRCodeOnRequest(t *testing.T) {
	f := newFixture(t)
	f.useClock()
	f.add("Mara", goodPassword)
	utf8 := session.ClientInfo{Charset: "UTF-8", Width: 100}
	h, intro := setupWith(t, f, utf8)
	if strings.ContainsAny(intro, "▀▄█") || strings.Contains(intro, "\x1b[4") {
		t.Fatal("QR code drawn without being asked for")
	}
	contains(t, intro, "'qr'")
	h.Type("qr")
	text := prompt(t, h, "6-digit code")
	if !strings.ContainsAny(text, "▀▄█") {
		t.Fatalf("no half-block QR code for a UTF-8 client: %q", text)
	}
	contains(t, text, "Scan it with your app")

	// Without UTF-8, plain spaces on coloured backgrounds, when it fits.
	h2, _ := setupWith(t, f, session.ClientInfo{Width: 120})
	h2.Type("qr")
	text = prompt(t, h2, "6-digit code")
	if strings.ContainsAny(text, "▀▄█") || !strings.Contains(text, "\x1b[40m  ") {
		t.Fatalf("want the ASCII drawing for a client without UTF-8: %q", text)
	}
	// Too narrow for it.
	h3, _ := setupWith(t, f, session.ClientInfo{Width: 60})
	h3.Type("qr")
	contains(t, prompt(t, h3, "6-digit code"), "too narrow")

	// A screen reader is told, and can insist.
	h4, _ := setupWith(t, f, session.ClientInfo{Charset: "UTF-8", HasMTTS: true, MTTS: session.MTTSScreenReader | session.MTTSUTF8, Width: 100})
	h4.Type("qr")
	text = prompt(t, h4, "6-digit code")
	contains(t, text, "screen reader")
	if strings.ContainsAny(text, "▀▄█") {
		t.Fatal("QR code drawn for a screen reader")
	}
	h4.Type("qr show")
	if text = prompt(t, h4, "6-digit code"); !strings.ContainsAny(text, "▀▄█") {
		t.Fatal("qr show did not draw it")
	}
}

// A set-up can be left and continued in another session with the same
// key; it changes nothing about logging in until confirmed.
func TestPendingSetupAcrossSessions(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h, intro := setupWith(t, f, session.ClientInfo{})
	key := uriSecret.FindStringSubmatch(intro)[1]
	h.Type("")
	contains(t, prompt(t, h, "Realm"), "Set-up paused")

	a, _ := f.store.Get(context.Background(), "Mara")
	if a.TOTP != nil || a.TOTPPending == nil {
		t.Fatalf("after pausing: TOTP %v, pending %v; want pending only", a.TOTP, a.TOTPPending)
	}
	if strings.Contains(a.TOTPPending.Sealed, key) {
		t.Fatal("pending key stored unsealed")
	}
	// Logging in is unchanged: no code asked for.
	h2 := f.start()
	contains(t, login(t, h2, "Mara", goodPassword), "Hello")

	h2.Type("totp")
	hiddenPrompt(t, h2, "current password")
	h2.Type(goodPassword)
	intro = prompt(t, h2, "6-digit code")
	contains(t, intro, "Continuing the set-up you began")
	if again := uriSecret.FindStringSubmatch(intro)[1]; again != key {
		t.Fatal("a new session showed a different key")
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(key)
	h2.Type(account.TOTPCode(secret, clk.now()))
	contains(t, prompt(t, h2, "Realm"), "authenticator is set up")
	if a, _ := f.store.Get(context.Background(), "Mara"); a.TOTP == nil || a.TOTPPending != nil {
		t.Fatal("confirmed set-up left pending, or not enabled")
	}
}

func TestPendingSetupExpiresAndCanBeDiscarded(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h, intro := setupWith(t, f, session.ClientInfo{})
	first := uriSecret.FindStringSubmatch(intro)[1]
	h.Type("")
	prompt(t, h, "Realm")

	// A day later it is gone: a new key.
	clk.t = clk.t.Add(account.PendingTTL + time.Minute)
	h.Type("totp")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	intro = prompt(t, h, "6-digit code")
	if strings.Contains(intro, "Continuing") || uriSecret.FindStringSubmatch(intro)[1] == first {
		t.Fatal("an expired set-up was continued")
	}
	h.Type("")
	prompt(t, h, "Realm")

	// totp off discards it, with the password alone.
	h.Type("totp off")
	hiddenPrompt(t, h, "current password")
	h.Type(goodPassword)
	contains(t, prompt(t, h, "Realm"), "discarded")
	if a, _ := f.store.Get(context.Background(), "Mara"); a.TOTPPending != nil {
		t.Fatal("still pending")
	}
}

// Asking for the QR code is not a wrong code: it never uses up a try.
func TestQRDoesNotCountAsAnAttempt(t *testing.T) {
	f := newFixture(t)
	clk := f.useClock()
	f.add("Mara", goodPassword)
	h, intro := setupWith(t, f, session.ClientInfo{Charset: "UTF-8", Width: 100})
	for i := 0; i < maxCodeTries+1; i++ {
		h.Type("qr")
		prompt(t, h, "6-digit code")
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(uriSecret.FindStringSubmatch(intro)[1])
	h.Type(account.TOTPCode(secret, clk.now()))
	contains(t, prompt(t, h, "Realm"), "authenticator is set up")
}
