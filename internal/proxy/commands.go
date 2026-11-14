package proxy

import (
	"errors"
	"fmt"
	"strings"

	"sanctuary/internal/sanitize"
	"sanctuary/internal/session"
)

// DefaultPrefix marks a line for the gateway rather than the realm: the
// prefix directly followed by a letter, as in ">lobby" (protocol.md §5a).
// A space after it ("> quoted text") makes it an ordinary line, so pasted
// quotes reach the realm untouched. The prefix is reserved: realms never
// receive a gateway command, so a command added to the gateway later
// cannot take over one of theirs. A server may choose another prefix
// (SANCTUARY_COMMAND_PREFIX); realms learn it from the welcome message.
const DefaultPrefix = ">"

// CheckPrefix validates a command prefix: one printable ASCII character
// that is not a letter, digit or space, so it can never swallow an
// ordinary word.
func CheckPrefix(p string) error {
	if len(p) != 1 || p[0] <= ' ' || p[0] > '~' || isLetter(p[0]) || p[0] >= '0' && p[0] <= '9' {
		return errors.New("the command prefix must be one ASCII punctuation character, such as > or /")
	}
	return nil
}

// ParseCommand splits a gateway command into its name (lower case) and the
// rest of the line; ok is false for any other line.
func ParseCommand(prefix, line string) (name, rest string, ok bool) {
	l := strings.TrimLeft(line, " \t")
	if len(prefix) != 1 || len(l) < 2 || l[0] != prefix[0] || !isLetter(l[1]) {
		return "", "", false
	}
	name, rest, _ = strings.Cut(l[1:], " ")
	return strings.ToLower(name), strings.TrimSpace(rest), true
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// verdict is what a gateway command typed in a realm asks for.
type verdict int

const (
	notCommand verdict = iota // an ordinary line: send it to the realm
	stay                      // answered; carry on
	toLobby                   // leave the realm for the lobby
	quitAll                   // disconnect
)

const (
	msgRealmHelpFmt = "Gateway commands, which work in any realm:\n" +
		"  %[1]slobby   leave this realm and go back to the lobby\n" +
		"  %[1]srealms  list the realms\n" +
		"  %[1]squit    disconnect\n" +
		"  %[1]shelp    this list\n" +
		"Anything else you type goes to the realm.\n"
	msgUnknownFmt = "There is no gateway command '%[1]s%[2]s'. '%[1]shelp' lists them.\n"
	msgToLobby    = "Leaving the realm.\n"
	msgGoodbye    = "Goodbye.\n"
)

// command answers a gateway command typed while in, or waiting for, realm
// here.
func (h Handler) command(s *session.Session, line, here string) verdict {
	p := h.CommandPrefix()
	name, _, ok := ParseCommand(p, line)
	if !ok {
		return notCommand
	}
	switch name {
	case "lobby":
		s.Send(session.Text{Text: msgToLobby})
		return toLobby
	case "quit":
		s.Send(session.Text{Text: msgGoodbye})
		return quitAll
	case "help":
		s.Send(session.Text{Text: fmt.Sprintf(msgRealmHelpFmt, p)})
	case "realms":
		s.Send(session.Text{Text: RealmList(h.Hub.Realms(), here)})
	default:
		s.Send(session.Text{Text: fmt.Sprintf(msgUnknownFmt, p, sanitize.Untrusted(name))})
	}
	return stay
}

// RealmList is the realms as a numbered list for players, marking the one
// they are in (here may be empty).
func RealmList(realms []RealmInfo, here string) string {
	if len(realms) == 0 {
		return "No realms are running right now.\n"
	}
	var b strings.Builder
	b.WriteString("Realms:\n")
	for i, r := range realms {
		mark := ""
		if r.ID == here {
			mark = " (you are here)"
		}
		fmt.Fprintf(&b, "  %d. %s%s\n", i+1, RealmLabel(r), mark)
	}
	return b.String()
}

// RealmLabel is how a realm is named to players. The name comes from the
// realm's hello; it is sanitised like any text from a realm.
func RealmLabel(r RealmInfo) string {
	if r.Name == "" {
		return r.ID
	}
	return sanitize.Untrusted(r.Name)
}

// CommandPrefix is the prefix that marks gateway commands for this handler.
func (h Handler) CommandPrefix() string {
	if h.Prefix == "" {
		return DefaultPrefix
	}
	return h.Prefix
}
