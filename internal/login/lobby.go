package login

import (
	"fmt"
	"strconv"
	"strings"

	"sanctuary/internal/account"
	"sanctuary/internal/proxy"
	"sanctuary/internal/sanitize"
)

const (
	msgHelloFmt   = "Hello, %s.\n"
	msgNoRealms   = "Press Enter to wait for one, or type 'quit' to leave.\n"
	msgLobbyHelpF = "Type a realm's number or name to enter it, or press Enter for the first one.\n" +
		"  realms    list them again\n" +
		"  password  change your password\n" +
		"  totp      set up an authenticator app ('totp off' removes it)\n" +
		"  codes     new recovery codes for your authenticator\n" +
		"  quit      leave\n" +
		"In a realm, the gateway's commands start with %[1]s: '%[1]slobby' comes back here and\n" +
		"'%[1]shelp' lists the rest. They work here too, so '%[1]spassword' is the same as 'password'.\n"
	msgNoSuch      = "There is no realm called that. Type 'realms' to see the list.\n"
	msgUnknownFmt  = "There is no gateway command '%[1]s%[2]s'. 'help' lists them.\n"
	msgInLobby     = "You are in the lobby.\n"
	msgBackInLobby = "\nYou are back in the lobby.\n"
	msgLobbyPrompt = "Realm (Enter for %s): "
	msgLobbyWait   = "Lobby (Enter to wait for a realm): "
	msgLobbyHint   = "Type 'help' for what you can do here.\n"
)

// lobby lists realms and takes the player into the one they choose, and
// back here when they leave it, until they quit or disconnect. Commands
// work bare or with the gateway's prefix, as they would in a realm.
func (t *turn) lobby(a *account.Account) {
	t.say(fmt.Sprintf(msgHelloFmt, a.Name) + msgLobbyHint)
	prefix := t.h.cfg.Realms.CommandPrefix()
	list := true
	for {
		realms := t.h.cfg.Realms.Hub.Realms()
		if list {
			menu := proxy.RealmList(realms, "")
			if len(realms) == 0 {
				menu += msgNoRealms
			}
			t.say(menu)
			list = false
		}
		prompt := msgLobbyWait
		if len(realms) > 0 {
			prompt = fmt.Sprintf(msgLobbyPrompt, proxy.RealmLabel(realms[0]))
		}
		line, err := t.ask(prompt, false)
		if err != nil {
			return
		}
		choice := strings.TrimSpace(line)
		command := strings.ToLower(choice)
		name, rest, prefixed := proxy.ParseCommand(prefix, choice)
		if prefixed {
			command = strings.TrimSpace(name + " " + strings.ToLower(rest))
		}
		switch command {
		case "quit":
			t.say(msgGoodbye)
			return
		case "help", "?":
			t.say(fmt.Sprintf(msgLobbyHelpF, prefix))
			continue
		case "realms", "list", "look":
			list = true
			continue
		case "lobby":
			t.say(msgInLobby)
			continue
		}
		if handled, err := t.manage(&a, command); handled {
			if err != nil {
				return
			}
			continue
		}
		if prefixed {
			t.say(fmt.Sprintf(msgUnknownFmt, prefix, sanitize.Untrusted(name)))
			continue
		}
		id, ok := pick(realms, choice)
		if !ok {
			t.say(msgNoSuch)
			continue
		}
		p := t.h.cfg.Realms
		p.Realm = id
		if p.Play(t.ctx, t.s, t.in) == proxy.Gone {
			return
		}
		t.say(msgBackInLobby)
		list = true
	}
}

// pick resolves a choice: empty for the first realm (or any, when none is
// running yet), a number from the menu, or a realm's id or name in any
// case.
func pick(realms []proxy.RealmInfo, choice string) (string, bool) {
	if choice == "" {
		if len(realms) == 0 {
			return "", true // wait for whichever registers first
		}
		return realms[0].ID, true
	}
	if n, err := strconv.Atoi(choice); err == nil {
		if n >= 1 && n <= len(realms) {
			return realms[n-1].ID, true
		}
		return "", false
	}
	for _, r := range realms {
		if strings.EqualFold(choice, r.ID) || strings.EqualFold(choice, r.Name) {
			return r.ID, true
		}
	}
	return "", false
}
