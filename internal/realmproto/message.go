package realmproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"sanctuary/internal/gmcp"
	"sanctuary/internal/session"
)

// Version is the protocol version this package speaks (protocol.md §4).
const Version = 1

// Limits from protocol.md. Every string a peer sends is capped, so a
// message's size is bounded by more than the frame limit alone.
const (
	MaxInput     = 4096           // bytes in one Input line, as transports deliver it
	MaxSessionID = 1<<53 - 1      // largest id every JSON implementation reads exactly
	maxVersions  = 16             // entries in Hello.Versions / Reject.Versions
	maxVersion   = 1000           // a version number above this is nonsense
	maxLabel     = 64             // display names, build ids, client strings
	maxID        = 128            // fingerprints, scene and actor ids
	maxDrainMS   = 10 * 60 * 1000 // a drain longer than ten minutes is a bug
)

// Sender says which side sent a message. Each message type may be sent by
// only one side, except GMCP and the keepalives (protocol.md §5, §8).
type Sender int

const (
	FromGateway Sender = iota + 1
	FromRealm
)

func (s Sender) String() string {
	switch s {
	case FromGateway:
		return "gateway"
	case FromRealm:
		return "realm"
	}
	return "unknown"
}

// Message is one protocol message.
type Message interface {
	// Type is the wire "type" value.
	Type() string
	validate() error
}

// Errors from Decode.
var (
	ErrInvalidUTF8  = errors.New("realmproto: payload is not valid UTF-8")
	ErrNotObject    = errors.New("realmproto: payload is not a JSON object")
	ErrMissingType  = errors.New("realmproto: message has no type")
	ErrWrongSender  = errors.New("realmproto: message type not allowed from this sender")
	ErrInvalidField = errors.New("realmproto: invalid field")
)

// ── Handshake (protocol.md §4) ──────────────────────────────

// Hello is the realm's first message on a link.
type Hello struct {
	Versions    []int  `json:"versions"`
	Realm       string `json:"realm"`
	Name        string `json:"name"` // untrusted display text: sanitise before showing
	Build       string `json:"build"`
	Fingerprint string `json:"fingerprint"`
}

// Welcome accepts a realm and fixes the protocol version for the link.
type Welcome struct {
	Version int    `json:"version"`
	Gateway string `json:"gateway"`
}

// Reject refuses a realm; the gateway closes the link after sending it.
type Reject struct {
	Reason   string `json:"reason"`
	Versions []int  `json:"versions,omitempty"`
}

// Reject reasons.
const (
	RejectUnsupportedVersion = "unsupported-version"
	RejectDuplicateRealm     = "duplicate-realm"
	RejectBadHello           = "bad-hello"
	RejectTooManyRealms      = "too-many-realms"
)

// ── Sessions, gateway to realm (protocol.md §5) ─────────────

// SessionOpen routes a player to the realm.
type SessionOpen struct {
	Session   uint64     `json:"session"`
	Transport string     `json:"transport"`
	Secure    bool       `json:"secure"`
	Client    ClientInfo `json:"client"`
}

// Input is one line of player input. Untrusted.
type Input struct {
	Session uint64 `json:"session"`
	Text    string `json:"text"`
}

// Client reports a change in the client's self-description.
type Client struct {
	Session uint64     `json:"session"`
	Client  ClientInfo `json:"client"`
}

// SessionClosed says a player is gone.
type SessionClosed struct {
	Session uint64 `json:"session"`
	Reason  string `json:"reason"`
}

// SessionClosed reasons.
const (
	ClosedQuit         = "quit"
	ClosedDisconnected = "disconnected"
	ClosedOverflow     = "overflow"
	ClosedShutdown     = "shutdown"
)

// ── Sessions, realm to gateway (protocol.md §5) ─────────────

// Text is output ending with a line break.
type Text struct {
	Session uint64 `json:"session"`
	Text    string `json:"text"`
	Meta    *Meta  `json:"meta,omitempty"`
}

// Prompt is output that expects input.
type Prompt struct {
	Session uint64 `json:"session"`
	Text    string `json:"text"`
}

// InputMode stops (Hidden) or resumes local echo.
type InputMode struct {
	Session uint64 `json:"session"`
	Hidden  bool   `json:"hidden"`
}

// SessionClose asks the gateway to disconnect a player once their queued
// output is sent.
type SessionClose struct {
	Session uint64 `json:"session"`
	Reason  string `json:"reason,omitempty"`
}

// ── Both directions ─────────────────────────────────────────

// GMCP carries a well-formed GMCP message for one session, in either
// direction.
type GMCP struct {
	Session uint64          `json:"session"`
	Package string          `json:"package"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Ping asks for a Pong with the same N.
type Ping struct {
	N uint64 `json:"n"`
}

// Pong answers a Ping.
type Pong struct {
	N uint64 `json:"n"`
}

// ── Link lifecycle (protocol.md §8) ─────────────────────────

// Shutdown: the gateway is going away; sessions follow as SessionClosed.
type Shutdown struct{}

// Drain: the realm is shutting down and will close its sessions within
// DeadlineMS milliseconds, then send Drained.
type Drain struct {
	DeadlineMS int64 `json:"deadline_ms"`
}

// Drained: the realm has closed every session; the gateway closes the link.
type Drained struct{}

// Unknown is a message whose type this version does not know. Peers ignore
// it (protocol.md §2); it is returned so the caller can count it.
type Unknown struct {
	Name string
}

// ── Shared parts ────────────────────────────────────────────

// Meta describes what a piece of output is (protocol.md §6). Every field is
// optional; a realm that runs no scenes simply never sets Scene.
type Meta struct {
	Kind  string `json:"kind,omitempty"`
	Voice string `json:"voice,omitempty"`
	Scene string `json:"scene,omitempty"`
	Actor string `json:"actor,omitempty"`
}

// Output kinds from protocol.md §6. Other well-formed kinds are accepted and
// passed through, so a realm can add one without a version bump; a
// receiver that does not know a kind treats it as narration.
const (
	KindNarration = "narration"
	KindPose      = "pose"
	KindSay       = "say"
	KindEmote     = "emote"
	KindOOC       = "ooc"
	KindSystem    = "system"
	KindCombat    = "combat"
	KindAlert     = "alert"
)

// Voices.
const (
	VoiceIC  = "ic"
	VoiceOOC = "ooc"
)

// ClientInfo is the wire form of session.ClientInfo (protocol.md §7): client
// claims, presentation hints only.
type ClientInfo struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Terminal     string `json:"terminal,omitempty"`
	MTTS         *int   `json:"mtts,omitempty"` // nil when the client sent no MTTS
	Charset      string `json:"charset,omitempty"`
	Width        int    `json:"width,omitempty"`
	Height       int    `json:"height,omitempty"`
	ScreenReader bool   `json:"screen_reader"`
}

// ClientFrom converts the gateway's view of a client to its wire form. Only
// the fields protocol.md §7 lists cross the link: MNES variables, telnet
// option lists and anything else the client reported stay in the gateway.
func ClientFrom(c session.ClientInfo) ClientInfo {
	w := ClientInfo{
		Name:         c.Name,
		Version:      c.Version,
		Terminal:     c.Terminal,
		Charset:      c.Charset,
		Width:        c.Width,
		Height:       c.Height,
		ScreenReader: c.ScreenReader(),
	}
	if c.HasMTTS {
		m := c.MTTS
		w.MTTS = &m
	}
	return w
}

// ToSession converts wire client info back to the session form, for a realm
// that runs session handlers. ScreenReader is not copied: session.ClientInfo
// derives it from the MTTS bit, which is the claim the client actually made.
func (c ClientInfo) ToSession() session.ClientInfo {
	s := session.ClientInfo{
		Name:     c.Name,
		Version:  c.Version,
		Terminal: c.Terminal,
		Charset:  c.Charset,
		Width:    c.Width,
		Height:   c.Height,
	}
	if c.MTTS != nil {
		s.MTTS, s.HasMTTS = *c.MTTS, true
	}
	return s
}

// ── Registry of types ───────────────────────────────────────

type entry struct {
	from []Sender
	make func() Message
}

var both = []Sender{FromGateway, FromRealm}

var types = map[string]entry{
	"hello":          {[]Sender{FromRealm}, func() Message { return &Hello{} }},
	"welcome":        {[]Sender{FromGateway}, func() Message { return &Welcome{} }},
	"reject":         {[]Sender{FromGateway}, func() Message { return &Reject{} }},
	"session.open":   {[]Sender{FromGateway}, func() Message { return &SessionOpen{} }},
	"input":          {[]Sender{FromGateway}, func() Message { return &Input{} }},
	"client":         {[]Sender{FromGateway}, func() Message { return &Client{} }},
	"session.closed": {[]Sender{FromGateway}, func() Message { return &SessionClosed{} }},
	"text":           {[]Sender{FromRealm}, func() Message { return &Text{} }},
	"prompt":         {[]Sender{FromRealm}, func() Message { return &Prompt{} }},
	"input.mode":     {[]Sender{FromRealm}, func() Message { return &InputMode{} }},
	"session.close":  {[]Sender{FromRealm}, func() Message { return &SessionClose{} }},
	"gmcp":           {both, func() Message { return &GMCP{} }},
	"ping":           {both, func() Message { return &Ping{} }},
	"pong":           {both, func() Message { return &Pong{} }},
	"shutdown":       {[]Sender{FromGateway}, func() Message { return &Shutdown{} }},
	"drain":          {[]Sender{FromRealm}, func() Message { return &Drain{} }},
	"drained":        {[]Sender{FromRealm}, func() Message { return &Drained{} }},
}

func (*Hello) Type() string         { return "hello" }
func (*Welcome) Type() string       { return "welcome" }
func (*Reject) Type() string        { return "reject" }
func (*SessionOpen) Type() string   { return "session.open" }
func (*Input) Type() string         { return "input" }
func (*Client) Type() string        { return "client" }
func (*SessionClosed) Type() string { return "session.closed" }
func (*Text) Type() string          { return "text" }
func (*Prompt) Type() string        { return "prompt" }
func (*InputMode) Type() string     { return "input.mode" }
func (*SessionClose) Type() string  { return "session.close" }
func (*GMCP) Type() string          { return "gmcp" }
func (*Ping) Type() string          { return "ping" }
func (*Pong) Type() string          { return "pong" }
func (*Shutdown) Type() string      { return "shutdown" }
func (*Drain) Type() string         { return "drain" }
func (*Drained) Type() string       { return "drained" }
func (*Unknown) Type() string       { return "" }

// SessionOf returns the session a message is about, or 0 for link-level
// messages.
func SessionOf(m Message) uint64 {
	switch v := m.(type) {
	case *SessionOpen:
		return v.Session
	case *Input:
		return v.Session
	case *Client:
		return v.Session
	case *SessionClosed:
		return v.Session
	case *Text:
		return v.Session
	case *Prompt:
		return v.Session
	case *InputMode:
		return v.Session
	case *SessionClose:
		return v.Session
	case *GMCP:
		return v.Session
	}
	return 0
}

// ── Encode and decode ───────────────────────────────────────

// Encode validates m and renders it as a frame payload.
func Encode(m Message) ([]byte, error) {
	if _, ok := m.(*Unknown); ok {
		return nil, errors.New("realmproto: cannot encode an unknown message")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	// Every message marshals to a JSON object; splice "type" in first so it
	// is the first thing a reader of a raw capture sees.
	head := fmt.Sprintf(`{"type":%q`, m.Type())
	if len(body) > 2 {
		head += ","
	}
	out := append([]byte(head), body[1:]...)
	if len(out) > MaxFrame {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, len(out), MaxFrame)
	}
	return out, nil
}

// Decode parses a frame payload sent by from. A message type from cannot
// send is ErrWrongSender; an unknown type is returned as *Unknown, not an
// error. Any other failure means the peer is broken or hostile, and the
// link should be closed.
func Decode(payload []byte, from Sender) (Message, error) {
	if len(payload) > MaxFrame {
		// ReadFrame already enforces this; Decode does not rely on its caller.
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, len(payload), MaxFrame)
	}
	if !utf8.Valid(payload) {
		// encoding/json would silently replace invalid UTF-8; refuse instead.
		return nil, ErrInvalidUTF8
	}
	trimmed := bytes.TrimLeft(payload, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, ErrNotObject
	}
	var env struct {
		Type *string `json:"type"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotObject, err)
	}
	if env.Type == nil || *env.Type == "" {
		return nil, ErrMissingType
	}
	e, ok := types[*env.Type]
	if !ok {
		name := *env.Type
		if len(name) > maxLabel {
			name = name[:maxLabel]
		}
		return &Unknown{Name: name}, nil
	}
	allowed := false
	for _, s := range e.from {
		allowed = allowed || s == from
	}
	if !allowed {
		return nil, fmt.Errorf("%w: %q from %s", ErrWrongSender, *env.Type, from)
	}
	m := e.make()
	if err := json.Unmarshal(payload, m); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidField, *env.Type, err)
	}
	if g, ok := m.(*GMCP); ok && string(g.Data) == "null" {
		g.Data = nil // "data": null means no payload, as an absent field does
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// ── Validation ──────────────────────────────────────────────

func fieldErr(msg, field, why string) error {
	return fmt.Errorf("%w: %s.%s %s", ErrInvalidField, msg, field, why)
}

// token reports whether s is 1..max bytes of [a-z0-9.-].
func token(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// opaqueID reports whether s is 1..maxID bytes of [A-Za-z0-9._:-]: ids that
// may end up in GMCP or logs, so no spaces, quotes or controls.
func opaqueID(s string) bool {
	if len(s) == 0 || len(s) > maxID {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

func realmID(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func checkSession(msg string, id uint64) error {
	if id == 0 || id > MaxSessionID {
		return fieldErr(msg, "session", "must be 1.."+fmt.Sprint(MaxSessionID))
	}
	return nil
}

func checkVersions(msg string, vs []int, required bool) error {
	if required && len(vs) == 0 {
		return fieldErr(msg, "versions", "is empty")
	}
	if len(vs) > maxVersions {
		return fieldErr(msg, "versions", "has too many entries")
	}
	for _, v := range vs {
		if v < 1 || v > maxVersion {
			return fieldErr(msg, "versions", "has an out-of-range version")
		}
	}
	return nil
}

func checkLabel(msg, field, s string) error {
	if len(s) > maxLabel {
		return fieldErr(msg, field, "is too long")
	}
	return nil
}

func (m *Hello) validate() error {
	if err := checkVersions("hello", m.Versions, true); err != nil {
		return err
	}
	if !realmID(m.Realm) {
		return fieldErr("hello", "realm", "must be 1-32 of [a-z0-9-]")
	}
	if err := checkLabel("hello", "name", m.Name); err != nil {
		return err
	}
	if err := checkLabel("hello", "build", m.Build); err != nil {
		return err
	}
	if m.Fingerprint != "" && !opaqueID(m.Fingerprint) {
		return fieldErr("hello", "fingerprint", "is not a valid id")
	}
	return nil
}

func (m *Welcome) validate() error {
	if m.Version < 1 || m.Version > maxVersion {
		return fieldErr("welcome", "version", "is out of range")
	}
	return checkLabel("welcome", "gateway", m.Gateway)
}

func (m *Reject) validate() error {
	if !token(m.Reason, 32) {
		return fieldErr("reject", "reason", "must be a short token")
	}
	return checkVersions("reject", m.Versions, false)
}

func (c *ClientInfo) validate(msg string) error {
	for field, s := range map[string]string{
		"name": c.Name, "version": c.Version, "terminal": c.Terminal, "charset": c.Charset,
	} {
		if err := checkLabel(msg, "client."+field, s); err != nil {
			return err
		}
	}
	// NAWS carries 16-bit sizes (RFC 1073).
	if c.Width < 0 || c.Width > 0xFFFF || c.Height < 0 || c.Height > 0xFFFF {
		return fieldErr(msg, "client", "window size out of range")
	}
	if c.MTTS != nil && (*c.MTTS < 0 || *c.MTTS > 1<<30) {
		return fieldErr(msg, "client.mtts", "is out of range")
	}
	return nil
}

func (m *SessionOpen) validate() error {
	if err := checkSession("session.open", m.Session); err != nil {
		return err
	}
	if !token(m.Transport, 32) && !transportKind(m.Transport) {
		return fieldErr("session.open", "transport", "must be a short token")
	}
	return m.Client.validate("session.open")
}

// transportKind accepts the session kinds that contain '/' or '+'
// ("ws/gmcp", "telnet+tls"), which token deliberately does not.
func transportKind(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '/' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

func (m *Input) validate() error {
	if err := checkSession("input", m.Session); err != nil {
		return err
	}
	if len(m.Text) > MaxInput {
		return fieldErr("input", "text", "is too long")
	}
	return nil
}

func (m *Client) validate() error {
	if err := checkSession("client", m.Session); err != nil {
		return err
	}
	return m.Client.validate("client")
}

func (m *SessionClosed) validate() error {
	if err := checkSession("session.closed", m.Session); err != nil {
		return err
	}
	if !token(m.Reason, 32) {
		return fieldErr("session.closed", "reason", "must be a short token")
	}
	return nil
}

func (m *Meta) validate() error {
	if m.Kind != "" && !token(m.Kind, 32) {
		return fieldErr("text", "meta.kind", "must be a short token")
	}
	if m.Voice != "" && m.Voice != VoiceIC && m.Voice != VoiceOOC {
		return fieldErr("text", "meta.voice", `must be "ic" or "ooc"`)
	}
	if m.Scene != "" && !opaqueID(m.Scene) {
		return fieldErr("text", "meta.scene", "is not a valid id")
	}
	if m.Actor != "" && !opaqueID(m.Actor) {
		return fieldErr("text", "meta.actor", "is not a valid id")
	}
	return nil
}

func (m *Text) validate() error {
	if err := checkSession("text", m.Session); err != nil {
		return err
	}
	if m.Meta != nil {
		return m.Meta.validate()
	}
	return nil
}

func (m *Prompt) validate() error    { return checkSession("prompt", m.Session) }
func (m *InputMode) validate() error { return checkSession("input.mode", m.Session) }

func (m *SessionClose) validate() error {
	if err := checkSession("session.close", m.Session); err != nil {
		return err
	}
	if m.Reason != "" && !token(m.Reason, 32) {
		return fieldErr("session.close", "reason", "must be a short token")
	}
	return nil
}

func (m *GMCP) validate() error {
	if err := checkSession("gmcp", m.Session); err != nil {
		return err
	}
	if !gmcp.ValidPackage(m.Package) {
		return fieldErr("gmcp", "package", "is not a valid GMCP package name")
	}
	if len(m.Data) > gmcp.MaxPayload {
		return fieldErr("gmcp", "data", "is too large")
	}
	return nil
}

func (m *Ping) validate() error     { return nil }
func (m *Pong) validate() error     { return nil }
func (m *Shutdown) validate() error { return nil }
func (m *Drained) validate() error  { return nil }
func (m *Unknown) validate() error  { return nil }

func (m *Drain) validate() error {
	if m.DeadlineMS < 1 || m.DeadlineMS > maxDrainMS {
		return fieldErr("drain", "deadline_ms", "must be 1.."+fmt.Sprint(maxDrainMS))
	}
	return nil
}
