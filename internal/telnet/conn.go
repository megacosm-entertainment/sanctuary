package telnet

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"sentience/internal/gmcp"
	"sentience/internal/sanitize"
	"sentience/internal/session"
)

// Limits on untrusted input.
const (
	MaxLine     = 4096     // bytes per input line; the rest is discarded
	MaxSubneg   = 48 << 10 // bytes per subnegotiation; GMCP is the largest
	maxTTYPE    = 4        // TTYPE requests per session (MTTS needs three)
	maxEnvValue = 256
)

// MSSPVar is one MSSP variable; a variable may carry several values.
type MSSPVar struct {
	Name   string
	Values []string
}

// Config configures a telnet Conn.
type Config struct {
	Meta session.Meta
	// MSSP supplies MSSP variables at the moment a crawler asks. Nil disables
	// MSSP.
	MSSP         func() []MSSPVar
	Log          *slog.Logger
	WriteTimeout time.Duration // per flush; default 15s
}

type deadliner interface {
	SetWriteDeadline(time.Time) error
}

type parseState uint8

const (
	stData parseState = iota
	stIAC
	stCmd // after WILL/WONT/DO/DONT, waiting for the option
	stSB  // first byte of a subnegotiation: the option
	stSBData
	stSBIAC
)

// Conn is a telnet session.Transport over any byte stream: a TCP socket, a
// TLS socket, or a telnet.mudstandards.org WebSocket.
type Conn struct {
	rw  io.ReadWriteCloser
	cfg Config
	log *slog.Logger

	// mu guards all protocol state and the output path.
	mu      sync.Mutex
	q       qmachine
	out     []byte    // pending output, flushed at the end of each operation
	w       io.Writer // rw, or z while MCCP2 is active
	z       *zlib.Writer
	werr    error
	closed  bool
	pending []session.Inbound

	// parser
	state    parseState
	cmd      byte
	sbOpt    byte
	sb       []byte
	sbOver   bool
	line     []byte
	lineOver bool
	sawCR    bool

	// client info
	info         session.ClientInfo
	dirty        bool
	ttypeCount   int
	ttypeLast    string
	ttypeDone    bool
	charsetAsked bool                          // a CHARSET REQUEST of ours awaits an answer
	fromMNES     struct{ terminal, mtts bool } // fields MNES has set

	readBuf   []byte
	rerr      error
	closeOnce sync.Once
	closing   atomic.Bool // set first thing in Close, read by flush without mu
}

// closeGrace bounds how long Close waits for a final flush to a client.
const closeGrace = 500 * time.Millisecond

// NewConn wraps rw. Call Start to send the initial negotiation.
func NewConn(rw io.ReadWriteCloser, cfg Config) *Conn {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 15 * time.Second
	}
	c := &Conn{
		rw:      rw,
		cfg:     cfg,
		log:     cfg.Log,
		w:       rw,
		readBuf: make([]byte, 4096),
		info:    session.ClientInfo{Charset: "UTF-8"},
	}
	c.q = qmachine{
		allowUs:  c.allowUs,
		allowHim: c.allowHim,
		send:     c.sendCmd,
		changed:  c.optionChanged,
		violation: func(opt byte, what string) {
			c.log.Debug("telnet negotiation violation", "option", OptionName(opt), "what", what)
		},
	}
	return c
}

// Start offers the server's options. SGA is accepted when a client asks but
// not offered: offering WILL SGA without WILL ECHO puts classic line-mode
// telnet clients into character mode, which MUD clients do not need.
func (c *Conn) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.q.askHim(OptTTYPE, true)
	c.q.askHim(OptNAWS, true)
	c.q.askHim(OptNewEnviron, true)
	c.q.askUs(OptCharset, true)
	c.q.askUs(OptEOR, true)
	c.q.askUs(OptGMCP, true)
	if c.cfg.MSSP != nil {
		c.q.askUs(OptMSSP, true)
	}
	c.q.askUs(OptMCCP2, true)
	return c.flush()
}

func (c *Conn) Meta() session.Meta { return c.cfg.Meta }

func (c *Conn) allowUs(opt byte) bool {
	switch opt {
	case OptSGA, OptEOR, OptCharset, OptGMCP, OptMCCP2:
		return true
	case OptMSSP:
		return c.cfg.MSSP != nil
	}
	// ECHO is only ever enabled at our request (InputMode); a client asking
	// us to echo everything it types is refused.
	return false
}

func (c *Conn) allowHim(opt byte) bool {
	switch opt {
	case OptSGA, OptTTYPE, OptNAWS, OptNewEnviron, OptCharset:
		return true
	}
	return false
}

// ---------------------------------------------------------------- reading

// ReadEvent returns the next inbound event.
func (c *Conn) ReadEvent() (session.Inbound, error) {
	for {
		c.mu.Lock()
		if len(c.pending) > 0 {
			ev := c.pending[0]
			c.pending[0] = nil
			c.pending = c.pending[1:]
			c.mu.Unlock()
			return ev, nil
		}
		if c.rerr != nil {
			err := c.rerr
			c.mu.Unlock()
			return nil, err
		}
		c.mu.Unlock()

		n, err := c.rw.Read(c.readBuf)
		c.mu.Lock()
		if n > 0 {
			c.process(c.readBuf[:n])
			if ferr := c.flush(); ferr != nil && err == nil {
				err = ferr
			}
		}
		if err != nil {
			c.rerr = err
		}
		c.mu.Unlock()
	}
}

// process parses client bytes. Caller holds mu.
func (c *Conn) process(data []byte) {
	for _, b := range data {
		switch c.state {
		case stData:
			if b == IAC {
				c.state = stIAC
			} else {
				c.dataByte(b)
			}
		case stIAC:
			c.iacByte(b)
		case stCmd:
			c.state = stData
			c.q.recv(c.cmd, b)
		case stSB:
			c.sbOpt = b
			c.sb = c.sb[:0]
			c.sbOver = false
			c.state = stSBData
		case stSBData:
			if b == IAC {
				c.state = stSBIAC
			} else {
				c.sbByte(b)
			}
		case stSBIAC:
			switch b {
			case SE:
				c.state = stData
				if c.sbOver {
					c.log.Warn("discarded oversized subnegotiation", "option", OptionName(c.sbOpt))
				} else {
					c.subneg(c.sbOpt, c.sb)
				}
			case IAC:
				c.state = stSBData
				c.sbByte(IAC)
			default:
				// IAC <cmd> inside SB is a protocol error: abandon the
				// subnegotiation and treat it as an ordinary command.
				c.iacByte(b)
			}
		}
	}
	if c.dirty {
		c.dirty = false
		c.pending = append(c.pending, session.ClientUpdate{Info: c.snapshot()})
	}
}

// iacByte handles the byte after IAC.
func (c *Conn) iacByte(b byte) {
	c.state = stData
	switch b {
	case IAC:
		c.dataByte(IAC)
	case WILL, WONT, DO, DONT:
		c.cmd = b
		c.state = stCmd
	case SB:
		c.state = stSB
	case EC:
		c.eraseChar()
	case EL:
		c.line = c.line[:0]
		c.lineOver = false
	case AYT:
		c.out = append(c.out, "\r\n[Yes]\r\n"...)
	default:
		// NOP, GA, DM, BRK, IP, AO, EOR from the client: ignored.
	}
}

func (c *Conn) sbByte(b byte) {
	if len(c.sb) >= MaxSubneg {
		c.sbOver = true
		return
	}
	c.sb = append(c.sb, b)
}

func (c *Conn) dataByte(b byte) {
	switch b {
	case '\r':
		c.emitLine()
		c.sawCR = true
		return
	case '\n':
		if c.sawCR {
			c.sawCR = false
			return
		}
		c.emitLine()
		return
	case 0:
		c.sawCR = false
		return
	case 0x08, 0x7f: // BS, DEL: clients in character mode send these
		c.sawCR = false
		c.eraseChar()
		return
	}
	c.sawCR = false
	if len(c.line) >= MaxLine {
		c.lineOver = true
		return
	}
	c.line = append(c.line, b)
}

func (c *Conn) eraseChar() {
	if len(c.line) == 0 {
		return
	}
	_, size := utf8.DecodeLastRune(c.line)
	c.line = c.line[:len(c.line)-size]
}

func (c *Conn) emitLine() {
	if c.lineOver {
		c.log.Warn("input line truncated", "limit", MaxLine)
	}
	text := sanitize.Untrusted(string(c.line))
	c.line = c.line[:0]
	c.lineOver = false
	c.pending = append(c.pending, session.Line{Text: text})
}

// ---------------------------------------------------------------- options

func (c *Conn) sendCmd(cmd, opt byte) {
	c.out = append(c.out, IAC, cmd, opt)
}

func (c *Conn) sendSB(opt byte, payload []byte) {
	c.out = append(c.out, IAC, SB, opt)
	c.out = appendEscaped(c.out, payload)
	c.out = append(c.out, IAC, SE)
}

// optionChanged runs when a side of an option enters or leaves the enabled
// state. Caller holds mu.
func (c *Conn) optionChanged(opt byte, us, enabled bool) {
	c.dirty = true
	c.log.Debug("telnet option", "option", OptionName(opt), "side", side(us), "enabled", enabled)
	if us {
		switch opt {
		case OptCharset:
			if enabled {
				c.sendSB(OptCharset, []byte{CharsetRequest, ';', 'U', 'T', 'F', '-', '8'})
				c.charsetAsked = true
			}
		case OptMSSP:
			if enabled {
				c.sendMSSP()
			}
		case OptMCCP2:
			if enabled {
				c.startCompression()
			} else {
				c.stopCompression()
			}
		}
		return
	}
	switch opt {
	case OptTTYPE:
		if enabled && !c.ttypeDone {
			c.requestTTYPE()
		}
	case OptNewEnviron:
		if enabled {
			req := []byte{EnvSend}
			for _, v := range []string{"CLIENT_NAME", "CLIENT_VERSION", "CHARSET", "MTTS", "TERMINAL_TYPE"} {
				req = append(req, EnvVar)
				req = append(req, v...)
			}
			c.sendSB(OptNewEnviron, req)
		}
	}
}

func side(us bool) string {
	if us {
		return "server"
	}
	return "client"
}

func (c *Conn) subneg(opt byte, data []byte) {
	switch opt {
	case OptTTYPE:
		if c.q.himEnabled(OptTTYPE) && len(data) > 0 && data[0] == TTypeIs {
			c.handleTTYPE(string(data[1:]))
		}
	case OptNAWS:
		if c.q.himEnabled(OptNAWS) && len(data) == 4 {
			c.info.Width = int(data[0])<<8 | int(data[1])
			c.info.Height = int(data[2])<<8 | int(data[3])
			c.dirty = true
		}
	case OptNewEnviron:
		if c.q.himEnabled(OptNewEnviron) && len(data) > 0 && (data[0] == EnvIs || data[0] == EnvInfo) {
			c.handleEnviron(data[1:])
		}
	case OptCharset:
		c.handleCharset(data)
	case OptGMCP:
		if !c.q.usEnabled(OptGMCP) {
			c.log.Debug("GMCP received before negotiation; ignored")
			return
		}
		pkg, payload, err := gmcp.Parse(data)
		if err != nil {
			c.log.Warn("rejected malformed GMCP", "err", err, "bytes", len(data))
			return
		}
		// Payloads are never logged: Char.Login will carry credentials.
		c.log.Info("GMCP received", "package", pkg, "bytes", len(payload))
		c.pending = append(c.pending, session.GMCP{Package: pkg, Data: payload})
	default:
		c.log.Debug("ignored subnegotiation", "option", OptionName(opt), "bytes", len(data))
	}
}

func (c *Conn) requestTTYPE() {
	c.ttypeCount++
	c.sendSB(OptTTYPE, []byte{TTypeSend})
}

// handleTTYPE implements the MTTS cycle: the first reply is the client name,
// the second the terminal type, the third "MTTS <bitvector>". A client that
// repeats itself does not support MTTS and the cycle stops.
func (c *Conn) handleTTYPE(raw string) {
	v := cleanIdent(raw, 64)
	if c.ttypeDone {
		return
	}
	c.log.Debug("TTYPE reply", "n", c.ttypeCount, "value", v)
	switch {
	case strings.HasPrefix(strings.ToUpper(v), "MTTS "):
		n, err := strconv.Atoi(strings.TrimSpace(v[5:]))
		if err == nil && n >= 0 && !c.fromMNES.mtts {
			c.info.MTTS = n
			c.info.HasMTTS = true
			c.dirty = true
		}
		c.ttypeDone = true
	case v == c.ttypeLast:
		c.ttypeDone = true
	case v == "":
		// Nothing to record; keep cycling.
	default:
		// MNES values, when a client sends them, are explicit and can be
		// updated mid-session, so they win over TTYPE.
		switch c.ttypeCount {
		case 1:
			if c.info.Name == "" { // an MNES name, if any, is already here
				c.info.Name = v
				c.info.NameSource = session.SourceTTYPE
			}
		default:
			if !c.fromMNES.terminal && (c.info.Terminal == "" || c.ttypeCount == 2) {
				c.info.Terminal = v
			}
		}
		c.dirty = true
	}
	c.ttypeLast = v
	if c.ttypeDone || c.ttypeCount >= maxTTYPE {
		c.ttypeDone = true
		c.log.Info("client identified", "client", c.info.Name, "terminal", c.info.Terminal,
			"mtts", c.info.MTTS, "screen_reader", c.info.ScreenReader())
		return
	}
	c.requestTTYPE()
}

// handleEnviron parses MNES variables from NEW-ENVIRON IS or INFO.
//
// RFC 1572 distinguishes "VAR name" (no VAL: the client does not have this
// variable) from "VAR name VAL" with an empty value (defined, but empty).
// Undefined variables are not recorded; Mudlet, for one, lists every
// requested variable as undefined before sending the ones it supports.
func (c *Conn) handleEnviron(data []byte) {
	var name, val []byte
	var cur *[]byte
	haveVar, haveVal := false, false
	commit := func() {
		if !haveVar {
			return
		}
		if haveVal {
			c.setEnv(string(name), string(val))
		} else {
			c.unsetEnv(string(name))
		}
		name, val, haveVar, haveVal = name[:0], val[:0], false, false
	}
	for i := 0; i < len(data); i++ {
		switch b := data[i]; b {
		case EnvVar, EnvUserVar:
			commit()
			haveVar = true
			cur = &name
		case EnvVal:
			if haveVar {
				haveVal = true
				cur = &val
			}
		case EnvEsc:
			if i+1 < len(data) && cur != nil {
				i++
				*cur = append(*cur, data[i])
			}
		default:
			if cur != nil && len(*cur) < maxEnvValue {
				*cur = append(*cur, b)
			}
		}
	}
	commit()
}

// mnesVariables are the variables MNES defines that the engine keeps.
// IPADDRESS is also defined but handled separately: see setEnv.
var mnesVariables = map[string]bool{
	"CHARSET": true, "CLIENT_NAME": true, "CLIENT_VERSION": true, "MTTS": true, "TERMINAL_TYPE": true,
}

// unsetEnv records that the client reports a variable as undefined. In an
// INFO update that removes a value reported earlier.
func (c *Conn) unsetEnv(name string) {
	name = cleanIdent(name, 64)
	if name == "" {
		return
	}
	c.log.Debug("MNES variable undefined", "name", name)
	if _, ok := c.info.Env[name]; ok {
		delete(c.info.Env, name)
		c.dirty = true
	}
}

func (c *Conn) setEnv(name, val string) {
	name = cleanIdent(name, 64)
	val = cleanIdent(val, maxEnvValue)
	if name == "" {
		return
	}
	if name == "IPADDRESS" {
		// Client-supplied; trustworthy only from an admin-listed proxy,
		// and no proxies are configured yet.
		c.log.Debug("ignored client-supplied IPADDRESS")
		return
	}
	if !mnesVariables[name] {
		// Not an MNES variable. Plain NEW-ENVIRON clients send things like
		// USER (the local account name), which the engine has no use for
		// and should not hold. Log the name only.
		c.log.Debug("ignored non-MNES variable", "name", name)
		return
	}
	c.log.Debug("MNES variable", "name", name, "value", val)
	if c.info.Env == nil {
		c.info.Env = map[string]string{}
	}
	c.info.Env[name] = val
	c.dirty = true
	// An empty value is recorded in Env but never erases something the
	// client reported another way: some clients send blank identity fields
	// for privacy while TTYPE or GMCP still name them.
	if val == "" {
		return
	}
	switch name {
	case "CLIENT_NAME":
		c.info.Name = val
		c.info.NameSource = session.SourceMNES
	case "CLIENT_VERSION":
		c.info.Version = val
	case "TERMINAL_TYPE":
		c.info.Terminal = val
		c.fromMNES.terminal = true
	case "MTTS":
		// MNES is how clients update MTTS mid-session (e.g. turning a
		// screen reader on), so once it reports MTTS, TTYPE no longer
		// overrides it.
		if n, err := strconv.Atoi(val); err == nil && n >= 0 {
			c.info.MTTS = n
			c.info.HasMTTS = true
			c.fromMNES.mtts = true
		}
	}
}

func (c *Conn) handleCharset(data []byte) {
	if len(data) == 0 {
		return
	}
	switch data[0] {
	case CharsetAccepted, CharsetRejected:
		if !c.charsetAsked {
			c.log.Debug("ignored CHARSET answer to a request we did not send")
			return
		}
		c.charsetAsked = false
	}
	switch data[0] {
	case CharsetAccepted:
		cs := cleanIdent(string(data[1:]), 32)
		c.info.Charset = cs
		c.dirty = true
		c.log.Debug("charset accepted", "charset", cs)
	case CharsetRejected:
		// UTF-8 stays the default; a client that cannot take it will show
		// replacement characters rather than lose text.
		c.log.Info("client rejected UTF-8 charset")
	case CharsetRequest:
		if !c.q.usEnabled(OptCharset) && !c.q.himEnabled(OptCharset) {
			return
		}
		body := data[1:]
		if len(body) >= 9 && bytes.HasPrefix(body, []byte("[TTABLE]")) {
			body = body[9:]
		}
		if len(body) < 2 {
			c.sendSB(OptCharset, []byte{CharsetRejected})
			return
		}
		sep := body[0]
		for _, cs := range bytes.Split(body[1:], []byte{sep}) {
			if strings.EqualFold(string(cs), "UTF-8") || strings.EqualFold(string(cs), "UTF8") {
				c.sendSB(OptCharset, append([]byte{CharsetAccepted}, cs...))
				c.info.Charset = "UTF-8"
				c.dirty = true
				return
			}
		}
		c.sendSB(OptCharset, []byte{CharsetRejected})
	}
}

func (c *Conn) sendMSSP() {
	var p []byte
	for _, v := range c.cfg.MSSP() {
		p = append(p, MSSPVarCode)
		p = append(p, msspClean(v.Name)...)
		for _, val := range v.Values {
			p = append(p, MSSPValCode)
			p = append(p, msspClean(val)...)
		}
	}
	c.sendSB(OptMSSP, p)
}

func msspClean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// cleanIdent sanitises a client-reported identity string.
func cleanIdent(s string, max int) string {
	s = strings.TrimSpace(sanitize.Untrusted(s))
	if len(s) > max {
		s = s[:max]
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

func (c *Conn) snapshot() session.ClientInfo {
	info := c.info.Clone()
	info.Options = info.Options[:0]
	for i := 0; i < 256; i++ {
		if c.q.usEnabled(byte(i)) {
			info.Options = append(info.Options, OptionName(byte(i)))
		}
		if c.q.himEnabled(byte(i)) {
			info.Options = append(info.Options, "client:"+OptionName(byte(i)))
		}
	}
	sort.Strings(info.Options)
	return info
}

// ---------------------------------------------------------------- MCCP2

func (c *Conn) startCompression() {
	if c.z != nil {
		return
	}
	// The SB that announces compression is the last uncompressed output.
	c.out = append(c.out, IAC, SB, OptMCCP2, IAC, SE)
	if err := c.flush(); err != nil {
		return
	}
	c.z = zlib.NewWriter(c.rw)
	c.w = c.z
	// Send the zlib header now, so clients can set up decompression
	// straight after the announcement instead of on the next output.
	if err := c.z.Flush(); err != nil && c.werr == nil {
		c.werr = err
	}
	c.log.Debug("MCCP2 compression started")
}

func (c *Conn) stopCompression() {
	if c.z == nil {
		return
	}
	c.flush()
	err := c.z.Close() // ends the zlib stream
	c.z = nil
	c.w = c.rw
	if err != nil && c.werr == nil {
		c.werr = err
	}
	c.log.Debug("MCCP2 compression stopped")
}

// ---------------------------------------------------------------- writing

// WriteEvent renders one outbound event.
func (c *Conn) WriteEvent(o session.Outbound) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return session.ErrClosed
	}
	switch v := o.(type) {
	case session.Text:
		c.out = appendText(c.out, v.Text)
	case session.Prompt:
		c.out = appendText(c.out, v.Text)
		switch {
		case c.q.usEnabled(OptEOR):
			c.out = append(c.out, IAC, EOR)
		case !c.q.usEnabled(OptSGA):
			c.out = append(c.out, IAC, GA)
		}
	case session.GMCPOut:
		if !c.q.usEnabled(OptGMCP) {
			return nil
		}
		msg, err := gmcp.Format(v.Package, v.Data)
		if err != nil {
			c.log.Warn("dropped invalid outbound GMCP", "err", err)
			return nil
		}
		c.sendSB(OptGMCP, msg)
	case session.InputMode:
		c.q.askUs(OptEcho, v.Hidden)
	}
	return c.flush()
}

// appendText converts newlines to CRLF and escapes IAC.
func appendText(dst []byte, s string) []byte {
	s = strings.ToValidUTF8(s, "�")
	for i := 0; i < len(s); i++ {
		switch b := s[i]; b {
		case '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				continue // the '\n' writes CRLF
			}
			dst = append(dst, '\r', 0) // bare CR is CR NUL on the wire
		case '\n':
			dst = append(dst, '\r', '\n')
		case IAC:
			dst = append(dst, IAC, IAC)
		default:
			dst = append(dst, b)
		}
	}
	return dst
}

func appendEscaped(dst, p []byte) []byte {
	for _, b := range p {
		if b == IAC {
			dst = append(dst, IAC, IAC)
		} else {
			dst = append(dst, b)
		}
	}
	return dst
}

// flush writes pending output. Caller holds mu.
func (c *Conn) flush() error {
	if c.werr != nil {
		c.out = c.out[:0]
		return c.werr
	}
	if len(c.out) == 0 {
		return nil
	}
	if d, ok := c.rw.(deadliner); ok {
		timeout := c.cfg.WriteTimeout
		if c.closing.Load() {
			// Close has begun: never extend its short deadline, or a stalled
			// client could hold Close for the full write timeout.
			timeout = closeGrace
		}
		d.SetWriteDeadline(time.Now().Add(timeout))
	}
	_, err := c.w.Write(c.out)
	if err == nil && c.z != nil {
		err = c.z.Flush()
	}
	c.out = c.out[:0]
	if err != nil {
		c.werr = err
	}
	return err
}

// Close ends any compressed stream and closes the connection. A write
// blocked on a stalled client is cut short first.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		if d, ok := c.rw.(deadliner); ok {
			d.SetWriteDeadline(time.Now().Add(closeGrace))
		}
		c.mu.Lock()
		c.closed = true
		if c.z != nil && c.werr == nil {
			c.flush()
			c.z.Close()
		}
		c.mu.Unlock()
		err = c.rw.Close()
	})
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return err
}
