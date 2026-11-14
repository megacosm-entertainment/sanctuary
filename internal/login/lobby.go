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
	msgHelloFmt    = "Hello, %s.\n"
	msgRealms      = "Realms:\n"
	msgNoRealms    = "No realms are running right now. Press Enter to wait for one, or type 'quit' to leave.\n"
	msgLobbyHelp   = "Type a realm's number or name to enter it, or press Enter for the first one.\n'realms' lists them again; 'quit' leaves.\nYour account: 'password' changes your password; 'totp' sets up an authenticator app,\n'totp off' removes it, 'codes' gives you new recovery codes.\n"
	msgNoSuch      = "There is no realm called that. Type 'realms' to see the list.\n"
	msgBackInLobby = "\nYou are back in the lobby.\n"
	msgLobbyPrompt = "Realm (Enter for %s): "
	msgLobbyWait   = "Lobby (Enter to wait for a realm): "
	msgLobbyHint   = "Type 'help' for what you can do here.\n"
)

// lobby lists realms and takes the player into the one they choose, and
// back here when they leave it, until they quit or disconnect.
func (t *turn) lobby(a *account.Account) {
	t.say(fmt.Sprintf(msgHelloFmt, a.Name) + msgLobbyHint)
	list := true
	for {
		realms := t.h.cfg.Realms.Hub.Realms()
		if list {
			t.say(menu(realms))
			list = false
		}
		prompt := msgLobbyWait
		if len(realms) > 0 {
			prompt = fmt.Sprintf(msgLobbyPrompt, label(realms[0]))
		}
		line, err := t.ask(prompt, false)
		if err != nil {
			return
		}
		choice := strings.TrimSpace(line)
		switch strings.ToLower(choice) {
		case "quit":
			t.say(msgGoodbye)
			return
		case "help", "?":
			t.say(msgLobbyHelp)
			continue
		case "realms", "list", "look":
			list = true
			continue
		}
		if handled, err := t.manage(&a, choice); handled {
			if err != nil {
				return
			}
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

// label is how a realm is named to players. The name comes from the
// realm's hello; it is sanitised like any text from a realm.
func label(r proxy.RealmInfo) string {
	if r.Name == "" {
		return r.ID
	}
	return sanitize.Untrusted(r.Name)
}

func menu(realms []proxy.RealmInfo) string {
	if len(realms) == 0 {
		return msgNoRealms
	}
	var b strings.Builder
	b.WriteString(msgRealms)
	for i, r := range realms {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, label(r))
	}
	return b.String()
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
