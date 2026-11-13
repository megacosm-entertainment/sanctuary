// Package session is the transport-neutral session abstraction. Every client
// connection, whatever its wire protocol, is normalised into a Transport that
// produces Inbound events and consumes Outbound ones. A Handler drives a
// Session; in stage 01 that is the echo handler, and in stage 02 it becomes a
// proxy speaking the internal protocol to a realm.
package session

import "encoding/json"

// Inbound is an event from the client towards the server.
type Inbound interface{ isInbound() }

// Outbound is an event from the server towards the client.
type Outbound interface{ isOutbound() }

// Line is one line of player input. Transports deliver it as valid UTF-8 with
// control sequences already stripped; it is still untrusted text.
type Line struct {
	Text string
}

// GMCP is a well-formed GMCP message. Malformed messages never reach a Handler.
type GMCP struct {
	Package string
	Data    json.RawMessage // nil when the message carried no payload
}

// ClientUpdate carries a fresh snapshot of what the client has told us about
// itself (TTYPE/MTTS, MNES, NAWS, CHARSET). Sent whenever any of it changes.
type ClientUpdate struct {
	Info ClientInfo
}

func (Line) isInbound()         {}
func (GMCP) isInbound()         {}
func (ClientUpdate) isInbound() {}

// Text is server-authored output. It may contain ANSI SGR sequences; any
// untrusted text embedded in it must already have been sanitised. Use "\n"
// for line breaks: transports translate as the wire requires.
type Text struct {
	Text string
}

// Prompt is output that ends without a newline and expects input. Telnet
// transports terminate it with IAC EOR (or IAC GA) so clients and screen
// readers know where the prompt ends.
type Prompt struct {
	Text string
}

// GMCPOut sends a GMCP message if the client has GMCP enabled; otherwise it
// is silently discarded.
type GMCPOut struct {
	Package string
	Data    json.RawMessage
}

// InputMode asks the client to stop (Hidden) or resume echoing typed input
// locally, for password entry. Over telnet this is WILL/WONT ECHO.
type InputMode struct {
	Hidden bool
}

func (Text) isOutbound()      {}
func (Prompt) isOutbound()    {}
func (GMCPOut) isOutbound()   {}
func (InputMode) isOutbound() {}

// Where a client's name came from.
const (
	SourceTTYPE     = "ttype"      // MTTS convention: upper case, no version
	SourceMNES      = "mnes"       // explicit CLIENT_NAME
	SourceCoreHello = "core.hello" // GMCP Core.Hello; set by Session.Client
)

// MTTS capability bits (https://tintin.mudhalla.net/protocols/mtts/).
const (
	MTTSANSI         = 1
	MTTSVT100        = 2
	MTTSUTF8         = 4
	MTTS256Colors    = 8
	MTTSMouse        = 16
	MTTSOSCColor     = 32
	MTTSScreenReader = 64
	MTTSProxy        = 128
	MTTSTrueColor    = 256
	MTTSMNES         = 512
	MTTSMSLP         = 1024
	MTTSSSL          = 2048
)

// ClientInfo is what a client has claimed about itself. Every field is a
// presentation hint, never a credential, and never grants privileges.
type ClientInfo struct {
	Name string // TTYPE first reply or MNES CLIENT_NAME
	// NameSource says where Name came from, so Session.Client can keep a
	// name and version from the same source.
	NameSource string
	Version    string // MNES CLIENT_VERSION
	Terminal   string // TTYPE second reply or MNES TERMINAL_TYPE
	MTTS       int    // capability bitvector; valid when HasMTTS
	HasMTTS    bool
	Charset    string // negotiated charset; "UTF-8" by default
	Width      int    // NAWS; 0 when unknown
	Height     int
	// Env holds MNES variables as reported. IPADDRESS is never stored: it is
	// client-supplied and only trustworthy from proxies an admin has listed.
	Env map[string]string
	// Options lists telnet options currently enabled, for diagnostics.
	Options []string
}

// ScreenReader reports the MTTS screen-reader bit. Use it to choose defaults,
// never as the only way to reach them.
func (c ClientInfo) ScreenReader() bool {
	return c.HasMTTS && c.MTTS&MTTSScreenReader != 0
}

// Clone returns a deep copy, so snapshots can cross goroutines safely.
func (c ClientInfo) Clone() ClientInfo {
	out := c
	if c.Env != nil {
		out.Env = make(map[string]string, len(c.Env))
		for k, v := range c.Env {
			out.Env[k] = v
		}
	}
	out.Options = append([]string(nil), c.Options...)
	return out
}
