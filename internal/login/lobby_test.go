package login

import (
	"strings"
	"testing"
)

func TestGatewayCommandsFromTheLobby(t *testing.T) {
	f := newFixture(t)
	f.add("Mara", goodPassword)
	h := f.start()
	login(t, h, "Mara", goodPassword)

	// Into the realm, and back out with the gateway's command, which the
	// realm never sees (the stub would echo it).
	h.Type("1")
	contains(t, prompt(t, h, ">"), "'>lobby' comes back out")
	h.Type(">lobby")
	text := prompt(t, h, "Realm")
	contains(t, text, "back in the lobby")
	if strings.Contains(text, "You said") {
		t.Fatalf("the realm received >lobby: %q", text)
	}

	// In the lobby the prefix is optional.
	h.Type(">lobby")
	contains(t, prompt(t, h, "Realm"), "You are in the lobby")
	h.Type(">PASSWORD")
	hiddenPrompt(t, h, "current password")
	h.Type("")
	contains(t, prompt(t, h, "Realm"), "Cancelled")
	h.Type(">stub")
	contains(t, prompt(t, h, "Realm"), "no gateway command '>stub'")
	h.Type(">quit")
	h.ExpectText("Goodbye")
	h.ExpectClosed()
}
