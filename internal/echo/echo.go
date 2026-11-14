// Package echo is the stage-01 session handler: it echoes each line back.
// Stage 02 replaces it with a proxy that speaks the internal protocol to a
// realm; nothing else in the gateway changes.
//
// A few slash commands exist only to exercise negotiation against real
// clients: /info, /secret (password-style hidden input), /quit.
package echo

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"sanctuary/internal/sanitize"
	"sanctuary/internal/session"
)

const prompt = "> "

// DefaultBanner is what a session sees first when Handler.Banner is empty.
const DefaultBanner = "Sanctuary gateway, stage 01: echo mode.\nType anything and it comes back. /help lists commands.\n"

// DefaultShutdown is sent at shutdown when Handler.Shutdown is empty.
const DefaultShutdown = "\nThe gateway is shutting down. Goodbye.\n"

// Handler echoes input. It is stateless and safe to share. The stub realm
// runs the same handler behind the realm protocol, with its own messages.
type Handler struct {
	Banner   string // first output on a new session; DefaultBanner if empty
	Shutdown string // sent when ctx is cancelled; DefaultShutdown if empty
}

func (h Handler) ServeSession(ctx context.Context, s *session.Session) {
	events := make(chan session.Inbound)
	readErr := make(chan error, 1)
	go func() {
		for {
			ev, err := s.Recv()
			if err != nil {
				readErr <- err
				return
			}
			select {
			case events <- ev:
			case <-s.Done():
				return
			}
		}
	}()

	banner := h.Banner
	if banner == "" {
		banner = DefaultBanner
	}
	s.Send(session.Text{Text: banner})
	s.Send(session.Prompt{Text: prompt})

	hidden := false
	for {
		select {
		case <-ctx.Done():
			bye := h.Shutdown
			if bye == "" {
				bye = DefaultShutdown
			}
			s.Send(session.Text{Text: bye})
			return
		case <-readErr:
			return
		case <-s.Done():
			return
		case ev := <-events:
			line, ok := ev.(session.Line)
			if !ok {
				continue // GMCP is logged by the transport; ClientUpdate is tracked by the session.
			}
			if hidden {
				hidden = false
				s.Send(session.InputMode{Hidden: false})
				s.Send(session.Text{Text: fmt.Sprintf("\nReceived %d characters of hidden input (not shown).\n",
					utf8.RuneCountInString(line.Text))})
				s.Send(session.Prompt{Text: prompt})
				continue
			}
			switch strings.ToLower(strings.TrimSpace(line.Text)) {
			case "/quit":
				s.Send(session.Text{Text: "Goodbye.\n"})
				return
			case "/help":
				s.Send(session.Text{Text: "/info    show what your client negotiated\n" +
					"/secret  type a line with local echo turned off\n" +
					"/quit    disconnect\n"})
			case "/info":
				s.Send(session.Text{Text: describe(s)})
			case "/secret":
				hidden = true
				s.Send(session.InputMode{Hidden: true})
				s.Send(session.Prompt{Text: "Secret: "})
				continue
			default:
				// Input is sanitised by the transport already; sanitising
				// again here keeps this handler safe on its own.
				s.Send(session.Text{Text: "You said: " + sanitize.Untrusted(line.Text) + "\n"})
			}
			s.Send(session.Prompt{Text: prompt})
		}
	}
}

func describe(s *session.Session) string {
	m := s.Meta()
	c := s.Client()
	var b strings.Builder
	fmt.Fprintf(&b, "Transport:     %s (encrypted: %v)\n", m.Kind, m.Secure)
	fmt.Fprintf(&b, "Client:        %s\n", orUnknown(strings.TrimSpace(c.Name+" "+c.Version)))
	fmt.Fprintf(&b, "Terminal:      %s\n", orUnknown(c.Terminal))
	if c.HasMTTS {
		fmt.Fprintf(&b, "MTTS:          %d (screen reader: %v)\n", c.MTTS, c.ScreenReader())
	} else {
		b.WriteString("MTTS:          not reported\n")
	}
	fmt.Fprintf(&b, "Charset:       %s\n", c.Charset)
	if c.Width > 0 {
		fmt.Fprintf(&b, "Window:        %d x %d\n", c.Width, c.Height)
	} else {
		b.WriteString("Window:        not reported\n")
	}
	if len(c.Options) > 0 {
		fmt.Fprintf(&b, "Telnet options: %s\n", strings.Join(c.Options, ", "))
	}
	if len(c.Env) > 0 {
		keys := make([]string, 0, len(c.Env))
		for k := range c.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("MNES:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s = %s\n", k, c.Env[k])
		}
	}
	// Every value above is client-supplied: sanitise line by line.
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	for i, l := range lines {
		lines[i] = sanitize.Untrusted(l)
	}
	return strings.Join(lines, "\n") + "\n"
}

func orUnknown(s string) string {
	if s == "" {
		return "(not reported)"
	}
	return s
}
