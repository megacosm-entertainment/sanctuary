package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"sanctuary/internal/telnet/telnettest"
	ws "sanctuary/internal/websocket"
	"sanctuary/internal/websocket/wstest"
)

var (
	accountName = flag.String("account", "smoketest", "account to log in as (created if it does not exist and signup is open)")
	password    = flag.String("password", "smoke test passphrase", "its password")
)

// player is what logging in needs from a client: send a line, and read
// until one of several texts has arrived.
type player interface {
	line(s string) error
	until(wants ...string) (string, error)
}

// enter logs in at the front door (signing up when the account does not
// exist yet) and enters the first realm. It returns the text up to the
// realm's first prompt.
func enter(p player) (string, error) {
	try := func(steps ...string) (string, error) {
		var out string
		for i := 0; i+1 < len(steps); i += 2 {
			if err := p.line(steps[i]); err != nil {
				return "", err
			}
			var err error
			if out, err = p.until(strings.Split(steps[i+1], "|")...); err != nil {
				return out, fmt.Errorf("after %q: %w", redact(steps[i]), err)
			}
		}
		return out, nil
	}
	out, err := try(*accountName, "Password", *password, "Realm (|wrong|Too many")
	if err != nil {
		return out, err
	}
	if !strings.Contains(out, "Realm (") {
		// Not there yet: create it. A second connection logs in instead.
		if out, err = try("new", "Choose an account name|created by staff"); err != nil {
			return out, err
		}
		if strings.Contains(out, "created by staff") {
			return out, errors.New("the account does not exist and signup is not open; use -account and -password")
		}
		if out, err = try(*accountName, "New password|taken", *password, "again", *password, "Realm ("); err != nil {
			return out, err
		}
	}
	return try("", "> ")
}

// redact keeps the password out of failure messages.
func redact(s string) string {
	if s == *password {
		return "[password]"
	}
	return s
}

// telnetPlayer waits for a prompt terminator as well as the text, so the
// next read starts clean; never for a quiet period, which would break the
// zlib reader under MCCP2 (see telnettest.Client.Pump).
type telnetPlayer struct {
	c       *telnettest.Client
	prompts int
}

func (t *telnetPlayer) line(s string) error {
	t.c.Text.Reset()
	t.prompts = len(t.c.Prompts)
	return t.c.SendLine(s)
}

func (t *telnetPlayer) until(wants ...string) (string, error) {
	err := t.c.Pump(telnettest.DefaultTimeout, func() bool {
		if len(t.c.Prompts) <= t.prompts {
			return false
		}
		for _, w := range wants {
			if strings.Contains(t.c.Text.String(), w) {
				return true
			}
		}
		return false
	})
	return t.c.Text.String(), err
}

type wsPlayer struct {
	c   *wstest.Client
	eol string
}

func (w wsPlayer) line(s string) error { return w.c.Send(ws.OpBinary, []byte(s+w.eol)) }

func (w wsPlayer) until(wants ...string) (string, error) {
	var b strings.Builder
	for {
		for _, want := range wants {
			if strings.Contains(b.String(), want) {
				return b.String(), nil
			}
		}
		op, p, err := w.c.ReadFrame()
		if err != nil {
			return b.String(), err
		}
		if op == ws.OpBinary {
			b.Write(p)
		}
	}
}
