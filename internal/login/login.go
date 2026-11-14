// Package login is the gateway's front door: it logs a player in (or signs
// them up), then keeps them in a lobby where they choose a realm, and
// brings them back to it when they leave one. It runs before the realm
// proxy, on the same session and the same reader (session.Inbox).
//
// The account's identity travels to the realm in session.open; the realm
// never sees a password (design §06).
package login

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"sanctuary/internal/account"
	"sanctuary/internal/proxy"
	"sanctuary/internal/session"
)

// Signup is who may create accounts.
type Signup string

const (
	SignupOpen   Signup = "open"   // anyone, from the login prompt
	SignupInvite Signup = "invite" // anyone with an invite code from staff
	SignupStaff  Signup = "staff"  // staff only, with the account command
)

// ParseSignup reads a SIGNUP setting.
func ParseSignup(s string) (Signup, error) {
	switch m := Signup(strings.ToLower(strings.TrimSpace(s))); m {
	case SignupOpen, SignupInvite, SignupStaff:
		return m, nil
	}
	return "", fmt.Errorf("login: signup must be open, invite or staff, not %q", s)
}

// Config is what the front door needs. Store, Hasher, Key and Throttle are
// shared by every session.
type Config struct {
	Store    account.Store
	Names    account.Names // policy for new names; checked before asking for a password
	Hasher   *account.Hasher
	Key      *account.SecretKey // opens TOTP secrets
	Throttle *Throttle
	Signup   Signup

	// RefusePlaintext refuses logins on connections that are not
	// encrypted; otherwise they are allowed with a warning.
	RefusePlaintext bool
	// SecureHint says how to connect securely, for those messages, e.g.
	// "telnet over TLS on port 9010". Optional.
	SecureHint string

	// Timeout is how long a connection may take to log in. Default 2 min.
	Timeout time.Duration
	// Issuer names this server in authenticator apps; default "Sanctuary".
	Issuer string
	// Banner is shown on connect. Optional.
	Banner string

	// Realms is the proxy that takes a player into a realm. Its Realm
	// field is ignored: the lobby sets it from the player's choice.
	Realms proxy.Handler

	now func() time.Time // tests
}

// Handler is the session handler for a gateway with accounts.
type Handler struct{ cfg Config }

// New checks cfg and returns the handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Store == nil || cfg.Hasher == nil || cfg.Key == nil || cfg.Throttle == nil || cfg.Realms.Hub == nil {
		return nil, errors.New("login: Store, Hasher, Key, Throttle and Realms.Hub are required")
	}
	if cfg.Signup == "" {
		cfg.Signup = SignupOpen
	}
	if _, err := ParseSignup(string(cfg.Signup)); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &Handler{cfg: cfg}, nil
}

// Limits on one connection's attempts, on top of the shared Throttle.
const (
	maxPasswordTries = 3
	maxCodeTries     = 3
)

// Messages. Wording matters here: one message for every wrong-name and
// wrong-password case, so the login prompt does not tell anyone which
// account names exist.
const (
	msgWelcome      = "Welcome to Sanctuary.\n"
	msgNamePrompt   = "Account name (or 'new' to create one): "
	msgHelp         = "Type your account name, then your password.\nType 'new' to create an account, or 'quit' to leave.\n"
	msgWrong        = "That name or password is wrong.\n"
	msgTooMany      = "Too many failed attempts. Goodbye.\n"
	msgThrottled    = "Too many recent failed logins for that account or from your address. Please try again in a few minutes.\n"
	msgWaitFmt      = "Please wait %s...\n"
	msgBusy         = "The server is busy checking other logins. Please try again in a moment.\n"
	msgTrouble      = "Something went wrong on our side. Please try again later.\n"
	msgDisabled     = "This account has been disabled. Please contact staff if you think this is a mistake.\n"
	msgTimeout      = "\nYou took too long to log in. Goodbye.\n"
	msgShutdown     = "\nThe gateway is shutting down. Goodbye.\n"
	msgGoodbye      = "Goodbye.\n"
	msgPlainWarn    = "Warning: this connection is not encrypted, so your password can be read on the way.%s\n"
	msgPlainRefuse  = "This server only accepts logins over an encrypted connection.%s\nGoodbye.\n"
	msgCodePrompt   = "Authenticator code (or a recovery code): "
	msgCodeWrong    = "That code is not right.\n"
	msgCodeTries    = "Too many wrong codes.\n"
	msgRecoveryLeft = "Recovery code accepted. You have %d left; set up new ones when you can.\n"
	msgMustChange   = "Staff have reset your password: please choose a new one.\n"
	msgPwPrompt     = "Password: "
	msgNewPwPrompt  = "New password (at least %d characters): "
	msgPwAgain      = "The same password again: "
	msgPwMismatch   = "Those passwords are different. Let's try again.\n"
	msgPwChanged    = "Password changed.\n"

	msgStaffOnly    = "New accounts are created by staff on this server. Please ask them for one.\n"
	msgInvitePrompt = "Invite code: "
	msgInviteBad    = "That invite code is not valid (or has expired, or has been used).\n"
	msgChoosePrompt = "Choose an account name (letters and digits, starting with a letter): "
	msgTaken        = "That name is taken.\n"
	msgReserved     = "That name is reserved.\n"
	msgCreated      = "Account %s created.\n"
	msgSignupLimit  = "Too many accounts have been created from your address recently. Please try again later.\n"
)

func secureHint(h string) string {
	if h == "" {
		return ""
	}
	return " Use " + h + " if your client supports it."
}

// errStop means the session is over: the player left, the login timed
// out, or the gateway is stopping. The message has been sent.
var errStop = errors.New("login: session over")

func (h *Handler) ServeSession(ctx context.Context, s *session.Session) {
	in := session.NewInbox(s)
	t := &turn{h: h, s: s, in: in, ctx: ctx, base: ctx, src: sourceOf(s.Meta().Remote)}
	t.say(msgWelcome)
	if h.cfg.Banner != "" {
		t.say(h.cfg.Banner)
	}
	if !s.Meta().Secure && h.cfg.RefusePlaintext {
		t.say(fmt.Sprintf(msgPlainRefuse, secureHint(h.cfg.SecureHint)))
		return
	}

	lctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	t.ctx = lctx
	a, err := t.login()
	cancel()
	t.ctx = ctx
	if err != nil {
		return
	}
	s.SetAccount(session.Account{ID: a.ID, Name: a.Name, Roles: a.Roles})
	s.Log().Info("logged in", "account", a.Name)
	t.lobby(a)
}

// sourceOf is the throttle key for where a connection comes from.
func sourceOf(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	return "src:" + proxy.SourceKey(host)
}

func nameKey(name string) string { return "name:" + account.Key(name) }

// turn is one session's time at the front door.
type turn struct {
	h    *Handler
	s    *session.Session
	in   *session.Inbox
	ctx  context.Context // what ends this stage: the login deadline while logging in
	base context.Context // the gateway's: cancelled at shutdown
	src  string
	// pendingTOTP is a key shown for set-up but not yet confirmed.
	pendingTOTP []byte
}

func (t *turn) say(text string) { t.s.Send(session.Text{Text: text}) }

// ask prompts and waits for a line. hidden turns local echo off for the
// answer (passwords), and back on afterwards whatever happens.
func (t *turn) ask(prompt string, hidden bool) (string, error) {
	if hidden {
		t.s.Send(session.InputMode{Hidden: true})
		defer t.s.Send(session.InputMode{Hidden: false})
	}
	t.s.Send(session.Prompt{Text: prompt})
	for {
		select {
		case <-t.ctx.Done():
			return "", t.stop()
		case <-t.in.Done:
			return "", errStop
		case <-t.s.Done():
			return "", errStop
		case ev := <-t.in.Events:
			if l, ok := ev.(session.Line); ok {
				if hidden {
					t.say("\n") // the client did not echo the newline either
				}
				return l.Text, nil
			}
		}
	}
}

// stop says why the session is ending, when the deadline or the gateway
// ended it.
func (t *turn) stop() error {
	if t.base.Err() == nil && errors.Is(t.ctx.Err(), context.DeadlineExceeded) {
		t.say(msgTimeout)
	} else {
		t.say(msgShutdown)
	}
	return errStop
}

// wait sleeps d, telling the player when it is long enough to notice.
func (t *turn) wait(d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if d >= time.Second {
		t.say(fmt.Sprintf(msgWaitFmt, spoken(d)))
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-t.ctx.Done():
		return t.stop()
	case <-t.in.Done:
		return errStop
	}
}

func spoken(d time.Duration) string {
	if s := int(d.Round(time.Second) / time.Second); s != 1 {
		return strconv.Itoa(s) + " seconds"
	}
	return "1 second"
}

// login runs the name and password prompts until someone logs in or
// signs up.
func (t *turn) login() (*account.Account, error) {
	plainWarned := false
	tries := 0
	for {
		line, err := t.ask(msgNamePrompt, false)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSpace(line)
		switch strings.ToLower(name) {
		case "":
			continue
		case "quit":
			t.say(msgGoodbye)
			return nil, errStop
		case "help":
			t.say(msgHelp)
			continue
		case "new":
			a, err := t.signup(&plainWarned)
			if err != nil || a != nil {
				return a, err
			}
			continue
		}
		if !t.s.Meta().Secure && !plainWarned {
			t.say(fmt.Sprintf(msgPlainWarn, secureHint(t.h.cfg.SecureHint)))
			plainWarned = true
		}
		pw, err := t.ask(msgPwPrompt, true)
		if err != nil {
			return nil, err
		}
		a, err := t.check(name, pw)
		switch {
		case errors.Is(err, errStop):
			return nil, err
		case err != nil:
			tries++
			if tries >= maxPasswordTries {
				t.say(msgTooMany)
				return nil, errStop
			}
			continue
		}
		if a, err = t.secondFactor(a, false); err != nil {
			if errors.Is(err, errFailed) {
				t.say(msgTooMany)
				return nil, errStop
			}
			return nil, err
		}
		if a.Disabled != "" {
			t.s.Log().Info("login refused: account disabled", "account", a.Name)
			t.say(msgDisabled)
			return nil, errStop
		}
		if a.MustChangePassword {
			if a, err = t.changePassword(a); err != nil {
				return nil, err
			}
		}
		return a, nil
	}
}

// errFailed is a failed check whose message has been sent.
var errFailed = errors.New("login: failed")

// check verifies a password, through the throttle. The same message and,
// as nearly as possible, the same time for an unknown name and a wrong
// password: Verify checks a dummy hash when there is no account.
func (t *turn) check(name, pw string) (*account.Account, error) {
	keys := []string{nameKey(name), t.src}
	wait, ok := t.h.cfg.Throttle.Begin(keys...)
	if !ok {
		t.say(msgThrottled)
		return nil, errFailed
	}
	if err := t.wait(wait); err != nil {
		return nil, err
	}
	a, err := t.h.cfg.Store.Get(t.ctx, name)
	stored := ""
	switch {
	case err == nil:
		stored = a.Password
	case errors.Is(err, account.ErrNotFound):
		a = nil
	default:
		t.s.Log().Error("reading account", "err", err)
		t.say(msgTrouble)
		return nil, errFailed
	}
	good, err := t.h.cfg.Hasher.Verify(t.ctx, stored, pw)
	if errors.Is(err, account.ErrBusy) {
		t.h.cfg.Throttle.Refund(keys...)
		if t.ctx.Err() != nil {
			return nil, t.stop()
		}
		t.say(msgBusy)
		return nil, errFailed
	}
	if err != nil {
		// A stored hash we cannot read: say no more than for a wrong one.
		t.s.Log().Error("checking password", "err", err)
		good = false
	}
	if !good || a == nil {
		t.s.Log().Info("login failed")
		t.say(msgWrong)
		return nil, errFailed
	}
	t.h.cfg.Throttle.Refund(t.src)
	t.h.cfg.Throttle.Clear(keys[0])
	if t.h.cfg.Hasher.NeedsRehash(a.Password) {
		t.rehash(a, pw)
	}
	return a, nil
}

// rehash stores a hash at the current cost; failing is not fatal, the
// old hash still works.
func (t *turn) rehash(a *account.Account, pw string) {
	hash, err := t.h.cfg.Hasher.Hash(t.ctx, pw)
	if err == nil {
		_, err = t.modify(a, func(a *account.Account) error {
			a.Password = hash
			return nil
		})
	}
	if err != nil {
		t.s.Log().Warn("upgrading password hash", "account", a.Name, "err", err)
	}
}

// modify applies fn to the stored account and writes it, reading again and
// re-applying when someone else wrote in between. fn sees the latest copy
// and may refuse the change.
func (t *turn) modify(a *account.Account, fn func(*account.Account) error) (*account.Account, error) {
	cur := a
	for i := 0; ; i++ {
		next := *cur
		next.Roles = append([]string(nil), cur.Roles...)
		next.Recovery = append([]string(nil), cur.Recovery...)
		if cur.TOTP != nil {
			tt := *cur.TOTP
			next.TOTP = &tt
		}
		if err := fn(&next); err != nil {
			return nil, err
		}
		err := t.h.cfg.Store.Update(t.ctx, &next)
		if err == nil {
			return &next, nil
		}
		if !errors.Is(err, account.ErrConflict) || i == 3 {
			return nil, err
		}
		if cur, err = t.h.cfg.Store.Get(t.ctx, a.Name); err != nil {
			return nil, err
		}
	}
}

var errReplay = errors.New("login: code already used")

// errCancelled: the player left a prompt empty to back out.
var errCancelled = errors.New("login: cancelled")

// secondFactor asks for an authenticator or recovery code when the account
// has TOTP enrolled. errFailed means the tries ran out or the throttle
// refused (the player has been told); the caller decides what follows.
func (t *turn) secondFactor(a *account.Account, cancellable bool) (*account.Account, error) {
	if a.TOTP == nil {
		return a, nil
	}
	secret, err := t.h.cfg.Key.Open(a.TOTP.Sealed, a.ID)
	if err != nil {
		t.s.Log().Error("opening TOTP secret (is ACCOUNT_KEY the one it was sealed with?)", "account", a.Name, "err", err)
		t.say(msgTrouble)
		return nil, errStop
	}
	key := "code:" + a.ID
	for tries := 0; tries < maxCodeTries; tries++ {
		line, err := t.ask(msgCodePrompt, false)
		if err != nil {
			return nil, err
		}
		code := strings.TrimSpace(line)
		if code == "" && cancellable {
			return nil, errCancelled
		}
		if code == "" {
			tries--
			continue
		}
		wait, ok := t.h.cfg.Throttle.Begin(key)
		if !ok {
			t.say(msgThrottled)
			return nil, errFailed
		}
		if err := t.wait(wait); err != nil {
			return nil, err
		}
		next, err := t.useCode(a, secret, code)
		if err == nil {
			t.h.cfg.Throttle.Clear(key)
			return next, nil
		}
		if !errors.Is(err, errFailed) && !errors.Is(err, errReplay) {
			t.s.Log().Error("recording code use", "account", a.Name, "err", err)
			t.say(msgTrouble)
			return nil, errStop
		}
		if hint, ok := digitsHint(code); ok {
			t.say(hint)
			continue
		}
		t.say(msgCodeWrong)
	}
	t.say(msgCodeTries)
	return nil, errFailed
}

// useCode checks code as a TOTP code (digits) or a recovery code, and
// records its use, so neither can be used twice.
func (t *turn) useCode(a *account.Account, secret []byte, code string) (*account.Account, error) {
	digits := strings.ReplaceAll(code, " ", "")
	if len(digits) == 6 && strings.Trim(digits, "0123456789") == "" {
		step, ok := account.CheckTOTP(secret, digits, t.h.cfg.now(), a.TOTP.LastStep)
		if !ok {
			return nil, errFailed
		}
		return t.modify(a, func(a *account.Account) error {
			if a.TOTP == nil || step <= a.TOTP.LastStep {
				return errReplay // used by a racing login since we read it
			}
			a.TOTP.LastStep = step
			return nil
		})
	}
	if _, ok := account.UseRecoveryCode(a.Recovery, code); !ok {
		return nil, errFailed
	}
	next, err := t.modify(a, func(a *account.Account) error {
		rest, ok := account.UseRecoveryCode(a.Recovery, code)
		if !ok {
			return errReplay
		}
		a.Recovery = rest
		return nil
	})
	if err == nil {
		t.s.Log().Info("recovery code used", "account", a.Name, "left", len(next.Recovery))
		t.say(fmt.Sprintf(msgRecoveryLeft, len(next.Recovery)))
	}
	return next, err
}

// newPassword asks for a new password twice until it is acceptable. When
// cancellable, an empty first answer backs out (errCancelled).
func (t *turn) newPassword(cancellable bool) (string, error) {
	for {
		pw, err := t.ask(fmt.Sprintf(msgNewPwPrompt, account.MinPassword), true)
		if err != nil {
			return "", err
		}
		if pw == "" && cancellable {
			return "", errCancelled
		}
		if err := account.CheckNewPassword(pw); err != nil {
			t.say(userError(err) + "\n")
			continue
		}
		again, err := t.ask(msgPwAgain, true)
		if err != nil {
			return "", err
		}
		if again != pw {
			t.say(msgPwMismatch)
			continue
		}
		hash, err := t.h.cfg.Hasher.Hash(t.ctx, pw)
		if errors.Is(err, account.ErrBusy) {
			if t.ctx.Err() != nil {
				return "", t.stop()
			}
			t.say(msgBusy)
			continue
		}
		if err != nil {
			t.s.Log().Error("hashing password", "err", err)
			t.say(msgTrouble)
			return "", errStop
		}
		return hash, nil
	}
}

// userError is an account error as a sentence for the player.
func userError(err error) string {
	msg := strings.TrimPrefix(err.Error(), "account: ")
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}

func (t *turn) changePassword(a *account.Account) (*account.Account, error) {
	t.say(msgMustChange)
	hash, err := t.newPassword(false)
	if err != nil {
		return nil, err
	}
	next, err := t.modify(a, func(a *account.Account) error {
		a.Password = hash
		a.PasswordChanged = t.h.cfg.now().UTC()
		a.MustChangePassword = false
		return nil
	})
	if err != nil {
		t.s.Log().Error("changing password", "account", a.Name, "err", err)
		t.say(msgTrouble)
		return nil, errStop
	}
	t.s.Log().Info("password changed after reset", "account", a.Name)
	t.say(msgPwChanged)
	return next, nil
}

// signup creates an account, as the server's Signup mode allows. It
// returns nil, nil to go back to the name prompt.
func (t *turn) signup(plainWarned *bool) (*account.Account, error) {
	var invite string
	switch t.h.cfg.Signup {
	case SignupStaff:
		t.say(msgStaffOnly)
		return nil, nil
	case SignupInvite:
		line, err := t.ask(msgInvitePrompt, false)
		if err != nil {
			return nil, err
		}
		if invite = strings.TrimSpace(line); invite == "" {
			return nil, nil
		}
	}
	// Account creation from one address is throttled like failed logins:
	// every signup counts and none is refunded.
	signupKey := "signup:" + t.src
	wait, ok := t.h.cfg.Throttle.Begin(signupKey)
	if !ok {
		t.say(msgSignupLimit)
		return nil, nil
	}
	// Only an account actually created (or a wrong invite code: guessing)
	// uses up the allowance; changing your mind part way does not.
	keep := false
	defer func() {
		if !keep {
			t.h.cfg.Throttle.Refund(signupKey)
		}
	}()
	if err := t.wait(wait); err != nil {
		return nil, err
	}

	var name string
	for {
		line, err := t.ask(msgChoosePrompt, false)
		if err != nil {
			return nil, err
		}
		name = strings.TrimSpace(line)
		if name == "" {
			return nil, nil
		}
		if err := t.nameFree(name); err != nil {
			t.say(err.Error())
			continue
		}
		break
	}
	if !t.s.Meta().Secure && !*plainWarned {
		t.say(fmt.Sprintf(msgPlainWarn, secureHint(t.h.cfg.SecureHint)))
		*plainWarned = true
	}
	hash, err := t.newPassword(false)
	if err != nil {
		return nil, err
	}
	id, err := account.NewID()
	if err != nil {
		t.say(msgTrouble)
		return nil, errStop
	}
	now := t.h.cfg.now().UTC()
	a := &account.Account{ID: id, Name: name, Created: now, Password: hash, PasswordChanged: now}
	if invite != "" {
		err = t.h.cfg.Store.CreateWithInvite(t.ctx, a, invite)
	} else {
		err = t.h.cfg.Store.Create(t.ctx, a)
	}
	switch {
	case err == nil:
		keep = true
	case errors.Is(err, account.ErrInviteInvalid):
		keep = true
		t.say(msgInviteBad)
		return nil, nil
	case errors.Is(err, account.ErrExists):
		t.say(msgTaken) // taken while they chose a password
		return nil, nil
	case errors.Is(err, account.ErrReservedName), errors.Is(err, account.ErrBadName):
		t.say(userError(err) + "\n")
		return nil, nil
	default:
		t.s.Log().Error("creating account", "err", err)
		t.say(msgTrouble)
		return nil, errStop
	}
	t.s.Log().Info("account created", "account", a.Name, "invite", invite != "")
	t.say(fmt.Sprintf(msgCreated, a.Name))
	return a, nil
}

// nameErr is a message for the player about a name they chose.
type nameErr string

func (e nameErr) Error() string { return string(e) }

func (t *turn) nameFree(name string) error {
	switch err := t.h.cfg.Names.Check(name); {
	case errors.Is(err, account.ErrReservedName):
		return nameErr(msgReserved)
	case err != nil:
		return nameErr(userError(err) + "\n")
	}
	switch _, err := t.h.cfg.Store.Get(t.ctx, name); {
	case err == nil:
		return nameErr(msgTaken)
	case !errors.Is(err, account.ErrNotFound):
		t.s.Log().Error("reading account", "err", err)
		return nameErr(msgTrouble)
	}
	return nil
}
