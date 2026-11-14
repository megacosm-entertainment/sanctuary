package login

import (
	"errors"
	"fmt"
	"strings"

	"sanctuary/internal/account"
	"sanctuary/internal/qrtext"
)

// Account management from the lobby: changing the password, and setting
// up or removing an authenticator. Each asks for the password again first,
// so a session left logged in on a shared computer cannot be used to take
// the account over; removing the authenticator or replacing the recovery
// codes also asks for a current code.

const (
	msgReauth       = "Your current password (Enter to cancel): "
	msgCancelled    = "Cancelled.\n"
	msgTOTPHave     = "You already have an authenticator. 'totp off' removes it; 'codes' gives you new recovery codes.\n"
	msgTOTPNone     = "You have no authenticator set up. 'totp' sets one up.\n"
	msgTOTPIntroFmt = "Add this account to your authenticator app (Google Authenticator, Aegis, 1Password, ...).\n" +
		"Enter this key by hand, choosing a time-based code of 6 digits:\n  %s\n" +
		"or open this link, or make a QR code of it (in a shell, put it in single quotes):\n%s\n" +
		"Type 'qr' at the prompt below to see it as a QR code to scan.\n"
	msgTOTPConfirm      = "The 6-digit code your app shows ('qr' for a QR code, Enter to stop for now): "
	msgTruncatedFmt     = "Your app seems to have only the first %d of the %d characters of the key. Remove it from the app and enter the whole key again; it ends with the last group shown above.\n"
	msgResumeFmt        = "Continuing the set-up you began on %s, with the same key: if your app already has it, just type its code.\n"
	msgDiscarded        = "The unfinished set-up is discarded; remove its entry from your app if you added it.\n"
	msgPaused           = "Set-up paused. 'totp' continues it with the same key (for a day); 'totp off' discards it.\n"
	msgQRAfter          = "Scan it with your app, then type the code it shows.\n"
	msgQRTrySmall       = "If it does not scan, 'qr small' draws it half the size, which suits some clients better.\n"
	msgQRTryLarge       = "If it does not scan, 'qr' draws it full size, which suits most MUD clients better.\n"
	msgQRSmallNeedsUTF8 = "The small QR code needs a client that has turned on UTF-8; 'qr' draws the full-size one.\n"
	msgQRSmallerFmt     = "Your window (%d columns) is too narrow for the full-size code, so this is the half-size one.\n"
	msgQRScreenReader   = "Your client reports a screen reader, so the QR code is not drawn: the key above is the same thing. Type 'qr show' to draw it anyway.\n"
	msgQRTooNarrowFmt   = "The QR code needs %d columns and your window has %d. Widen it and type 'qr' again, type 'qr show' to draw it anyway, or use the key or link above.\n"
	msgQRNoSizeFmt      = "Your client has not reported its window size, so this may wrap if the window is narrower than %d columns. (Turning on NAWS, window size, in the client lets the server check.)\n"
	msgTOTPOn           = "Your authenticator is set up. From now on you will be asked for a code when you log in.\n"
	msgTOTPOff          = "Your authenticator is removed, with its recovery codes.\n"
	msgCodesFmt         = "Recovery codes. Each works once, in place of a code from your app, if you lose it.\n" +
		"Keep them somewhere safe: they are shown only now.\n%s"
	msgOldCodes   = "Your old recovery codes no longer work.\n"
	msgRaceTOTP   = "Your authenticator changed in another session; nothing was changed here.\n"
	msgCodeVerify = "To confirm it is you, enter a code from your authenticator (an empty line cancels).\n"
)

// manage handles an account command typed in the lobby. It reports
// whether line was one; a is updated to the stored account after a change.
func (t *turn) manage(a **account.Account, line string) (bool, error) {
	var run func(*account.Account) (*account.Account, error)
	switch strings.Join(strings.Fields(strings.ToLower(line)), " ") {
	case "password":
		run = t.lobbyPassword
	case "totp", "2fa":
		run = t.enrolTOTP
	case "totp off", "2fa off":
		run = t.removeTOTP
	case "codes":
		run = t.newCodes
	default:
		return false, nil
	}
	// Read afresh: another session, a staff command or an earlier command
	// here that stopped part way may have changed it.
	cur, err := t.h.cfg.Store.Get(t.ctx, (*a).Name)
	if err != nil {
		t.trouble("reading account", err) // said so; stay in the lobby
		return true, nil
	}
	next, err := run(cur)
	switch {
	case err == nil:
		*a = next
	case errors.Is(err, errCancelled):
		t.say(msgCancelled)
	case errors.Is(err, errFailed):
	default:
		return true, err
	}
	return true, nil
}

// reauth reads the account afresh and checks its password, through the
// same throttle as logging in.
func (t *turn) reauth(name string) (*account.Account, error) {
	pw, err := t.ask(msgReauth, true)
	if err != nil {
		return nil, err
	}
	if pw == "" {
		return nil, errCancelled
	}
	return t.check(name, pw)
}

// codeAgain asks for a current code when the account has an authenticator.
func (t *turn) codeAgain(a *account.Account) (*account.Account, error) {
	if a.TOTP == nil {
		return a, nil
	}
	t.say(msgCodeVerify)
	return t.secondFactor(a, true)
}

func (t *turn) lobbyPassword(a *account.Account) (*account.Account, error) {
	a, err := t.reauth(a.Name)
	if err != nil {
		return nil, err
	}
	if a, err = t.codeAgain(a); err != nil {
		return nil, err
	}
	hash, err := t.newPassword(true)
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
		return nil, t.trouble("changing password", err)
	}
	t.s.Log().Info("password changed", "account", a.Name)
	t.say(msgPwChanged)
	return next, nil
}

// trouble logs a storage failure and tells the player, without ending
// the session.
func (t *turn) trouble(what string, err error) error {
	t.s.Log().Error(what, "err", err)
	t.say(msgTrouble)
	return errFailed
}

func (t *turn) issuer() string {
	if t.h.cfg.Issuer != "" {
		return t.h.cfg.Issuer
	}
	return "Sanctuary"
}

func (t *turn) enrolTOTP(a *account.Account) (*account.Account, error) {
	if a.TOTP != nil {
		t.say(msgTOTPHave)
		return nil, errFailed
	}
	a, err := t.reauth(a.Name)
	if err != nil {
		return nil, err
	}
	if a.TOTP != nil {
		t.say(msgTOTPHave)
		return nil, errFailed
	}
	secret, resumed, err := t.pendingKey(a)
	if err != nil {
		return nil, err
	}
	if resumed {
		t.say(fmt.Sprintf(msgResumeFmt, a.TOTPPending.Started.UTC().Format("2006-01-02 15:04 MST")))
	}
	t.say(fmt.Sprintf(msgTOTPIntroFmt, account.TOTPDisplay(secret), account.TOTPURI(t.issuer(), a.Name, secret)))
	var step int64
	for tries := 0; ; tries++ {
		if tries == maxCodeTries {
			t.say(msgCodeTries + msgPaused)
			return nil, errFailed
		}
		line, err := t.ask(msgTOTPConfirm, false)
		if err != nil {
			return nil, err
		}
		code := strings.TrimSpace(line)
		switch strings.ToLower(code) {
		case "":
			t.say(msgPaused)
			return nil, errFailed
		case "qr", "qr show", "qr small", "qr small show", "qr show small":
			lc := strings.ToLower(code)
			t.showQR(account.TOTPURI(t.issuer(), a.Name, secret), strings.Contains(lc, "small"), strings.Contains(lc, "show"))
			tries-- // not an attempt
			continue
		}
		var ok bool
		if step, ok = account.CheckTOTP(secret, code, t.h.cfg.now(), 0); ok {
			break
		}
		if hint, ok := digitsHint(code); ok {
			t.say(hint)
			continue
		}
		if n, of, ok := account.TOTPTruncated(secret, code, t.h.cfg.now()); ok {
			t.say(fmt.Sprintf(msgTruncatedFmt, n, of))
			continue
		}
		t.say(msgCodeWrong + "Check that the app's clock is right and that you entered the whole key.\n")
	}
	sealed, err := t.h.cfg.Key.Seal(secret, a.ID)
	if err != nil {
		return nil, t.trouble("sealing a TOTP secret", err)
	}
	shown, stored, err := account.NewRecoveryCodes()
	if err != nil {
		return nil, t.trouble("making recovery codes", err)
	}
	pending := a.TOTPPending.Sealed
	next, err := t.modify(a, func(a *account.Account) error {
		// Confirm only the key that was shown: another session may have
		// replaced or confirmed it since.
		if a.TOTP != nil || a.TOTPPending == nil || a.TOTPPending.Sealed != pending {
			return errReplay
		}
		a.TOTP = &account.TOTPState{Sealed: sealed, LastStep: step, Enabled: t.h.cfg.now().UTC()}
		a.Recovery = stored
		a.TOTPPending = nil
		return nil
	})
	if errors.Is(err, errReplay) {
		t.say(msgRaceTOTP)
		return nil, errFailed
	}
	if err != nil {
		return nil, t.trouble("enrolling TOTP", err)
	}
	t.s.Log().Info("authenticator set up", "account", a.Name)
	t.say(msgTOTPOn)
	t.say(fmt.Sprintf(msgCodesFmt, codeList(shown)))
	return next, nil
}

// pendingKey returns the set-up key: the pending one when there is a live
// one (the app may already hold it), else a new one, stored as pending
// before it is shown. a is updated to what was stored.
func (t *turn) pendingKey(a *account.Account) ([]byte, bool, error) {
	now := t.h.cfg.now()
	if p := a.TOTPPending; p.Live(now) {
		secret, err := t.h.cfg.Key.Open(p.Sealed, account.PendingAD(a.ID))
		if err == nil {
			return secret, true, nil
		}
		t.s.Log().Warn("pending TOTP key does not open; starting a new set-up", "account", a.Name, "err", err)
	}
	secret, err := account.NewTOTPSecret()
	if err != nil {
		return nil, false, t.trouble("making a TOTP secret", err)
	}
	sealed, err := t.h.cfg.Key.Seal(secret, account.PendingAD(a.ID))
	if err != nil {
		return nil, false, t.trouble("sealing a TOTP secret", err)
	}
	next, err := t.modify(a, func(a *account.Account) error {
		if a.TOTP != nil {
			return errReplay
		}
		a.TOTPPending = &account.TOTPPending{Sealed: sealed, Started: now.UTC()}
		return nil
	})
	if errors.Is(err, errReplay) {
		t.say(msgTOTPHave)
		return nil, false, errFailed
	}
	if err != nil {
		return nil, false, t.trouble("starting TOTP set-up", err)
	}
	*a = *next
	return secret, false, nil
}

func codeList(codes []string) string {
	var b strings.Builder
	for i, c := range codes {
		fmt.Fprintf(&b, "  %2d. %s\n", i+1, c)
	}
	return b.String()
}

func (t *turn) removeTOTP(a *account.Account) (*account.Account, error) {
	if a.TOTP == nil && a.TOTPPending != nil {
		return t.discardPending(a)
	}
	if a.TOTP == nil {
		t.say(msgTOTPNone)
		return nil, errFailed
	}
	a, err := t.reauth(a.Name)
	if err != nil {
		return nil, err
	}
	if a, err = t.codeAgain(a); err != nil {
		return nil, err
	}
	next, err := t.modify(a, func(a *account.Account) error {
		a.TOTP, a.Recovery = nil, nil
		return nil
	})
	if err != nil {
		return nil, t.trouble("removing TOTP", err)
	}
	t.s.Log().Info("authenticator removed", "account", a.Name)
	t.say(msgTOTPOff)
	return next, nil
}

func (t *turn) newCodes(a *account.Account) (*account.Account, error) {
	if a.TOTP == nil {
		t.say(msgTOTPNone)
		return nil, errFailed
	}
	a, err := t.reauth(a.Name)
	if err != nil {
		return nil, err
	}
	if a, err = t.codeAgain(a); err != nil {
		return nil, err
	}
	shown, stored, err := account.NewRecoveryCodes()
	if err != nil {
		return nil, t.trouble("making recovery codes", err)
	}
	next, err := t.modify(a, func(a *account.Account) error {
		a.Recovery = stored
		return nil
	})
	if err != nil {
		return nil, t.trouble("replacing recovery codes", err)
	}
	t.s.Log().Info("recovery codes replaced", "account", a.Name)
	t.say(fmt.Sprintf(msgCodesFmt, codeList(shown)) + msgOldCodes)
	return next, nil
}

// digitsHint explains a code of all digits but the wrong length: usually
// an app set to 7 or 8 digits (Authy does this for keys entered by hand).
func digitsHint(code string) (string, bool) {
	c := strings.ReplaceAll(code, " ", "")
	if c == "" || strings.Trim(c, "0123456789") != "" || len(c) == account.TOTPDigits {
		return "", false
	}
	return fmt.Sprintf("Codes have %d digits; that one has %d. If your app shows %d, set the account's code length to %d in the app.\n",
		account.TOTPDigits, len(c), len(c), account.TOTPDigits), true
}

// discardPending drops a set-up that was never confirmed. Nothing about
// logging in changes, so the password is enough.
func (t *turn) discardPending(a *account.Account) (*account.Account, error) {
	a, err := t.reauth(a.Name)
	if err != nil {
		return nil, err
	}
	next, err := t.modify(a, func(a *account.Account) error {
		a.TOTPPending = nil
		return nil
	})
	if err != nil {
		return nil, t.trouble("discarding TOTP set-up", err)
	}
	t.say(msgDiscarded)
	return next, nil
}

// showQR draws uri as a QR code. The default draws each module as two
// spaces on a black or white background: MUD clients fill backgrounds
// across the whole line, line spacing included, where half-block glyphs
// leave gaps (and many MUD fonts lack them). small ('qr small') uses half
// blocks, half the size, for real terminals and narrow windows, and needs
// UTF-8. The width the client reported (NAWS) is checked each time; with
// none reported the code is drawn anyway, since the player asked. anyway
// ('qr show') skips the width check and the screen-reader explanation.
func (t *turn) showQR(uri string, small, anyway bool) {
	c := t.s.Client() // as now: a window resized since is seen
	if c.ScreenReader() && !anyway {
		t.say(msgQRScreenReader)
		return
	}
	if small && !c.UTF8() {
		t.say(msgQRSmallNeedsUTF8)
		return
	}
	code, err := qrtext.Encode(uri)
	if err != nil {
		t.s.Log().Error("encoding a QR code", "err", err)
		t.say(msgTrouble)
		return
	}
	drawing, need, other := code.Spaces(), code.SpacesWidth(), msgQRTrySmall
	if small {
		drawing, need, other = code.HalfBlocks(), code.HalfBlocksWidth(), msgQRTryLarge
	}
	note := ""
	if !small && c.Width > 0 && need > c.Width && c.UTF8() && code.HalfBlocksWidth() <= c.Width {
		// Too narrow for the large form: the small one fits.
		drawing, need, other = code.HalfBlocks(), code.HalfBlocksWidth(), msgQRTryLarge
		note = fmt.Sprintf(msgQRSmallerFmt, c.Width)
	}
	switch {
	case c.Width > 0 && need > c.Width && !anyway:
		t.say(fmt.Sprintf(msgQRTooNarrowFmt, need, c.Width))
		return
	case c.Width == 0:
		note += fmt.Sprintf(msgQRNoSizeFmt, need)
	}
	if !c.UTF8() {
		other = ""
	}
	t.say(note + drawing + msgQRAfter + other)
}
