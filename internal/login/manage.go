package login

import (
	"errors"
	"fmt"
	"strings"

	"sanctuary/internal/account"
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
		"or open this link, or make a QR code of it (in a shell, put it in single quotes):\n%s\n"
	msgTOTPConfirm = "The 6-digit code your app shows (Enter to cancel): "
	msgTOTPOn      = "Your authenticator is set up. From now on you will be asked for a code when you log in.\n"
	msgTOTPOff     = "Your authenticator is removed, with its recovery codes.\n"
	msgCodesFmt    = "Recovery codes. Each works once, in place of a code from your app, if you lose it.\n" +
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
	next, err := run(*a)
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
	secret, err := account.NewTOTPSecret()
	if err != nil {
		return nil, t.trouble("making a TOTP secret", err)
	}
	t.say(fmt.Sprintf(msgTOTPIntroFmt, account.TOTPDisplay(secret), account.TOTPURI(t.issuer(), a.Name, secret)))
	var step int64
	for tries := 0; ; tries++ {
		if tries == maxCodeTries {
			t.say(msgCodeTries + "Nothing was changed; type 'totp' to start again.\n")
			return nil, errFailed
		}
		line, err := t.ask(msgTOTPConfirm, false)
		if err != nil {
			return nil, err
		}
		code := strings.TrimSpace(line)
		if code == "" {
			return nil, errCancelled
		}
		var ok bool
		if step, ok = account.CheckTOTP(secret, code, t.h.cfg.now(), 0); ok {
			break
		}
		if hint, ok := digitsHint(code); ok {
			t.say(hint)
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
	next, err := t.modify(a, func(a *account.Account) error {
		if a.TOTP != nil {
			return errReplay
		}
		a.TOTP = &account.TOTPState{Sealed: sealed, LastStep: step, Enabled: t.h.cfg.now().UTC()}
		a.Recovery = stored
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

func codeList(codes []string) string {
	var b strings.Builder
	for i, c := range codes {
		fmt.Fprintf(&b, "  %2d. %s\n", i+1, c)
	}
	return b.String()
}

func (t *turn) removeTOTP(a *account.Account) (*account.Account, error) {
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
