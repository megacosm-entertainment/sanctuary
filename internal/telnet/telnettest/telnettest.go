// Package telnettest is a scripted MUD client for tests and the smoke
// client. It answers the server's option negotiation according to a
// Profile, the way a real client would, and records everything the server
// sent so tests can assert on it.
//
// The telnet package's own unit tests cannot import this package (it
// imports telnet); they use the in-package fixture in conn_test.go.
package telnettest

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	tn "sentience/internal/telnet"
)

// DefaultTimeout bounds every wait.
const DefaultTimeout = 3 * time.Second

// MTTS bit values used by profiles; see session.MTTS* for the full list.
const (
	mttsANSI         = 1
	mttsUTF8         = 4
	mtts256Colors    = 8
	mttsScreenReader = 64
)

// Profile describes how the client answers negotiation.
type Profile struct {
	// TTYPE replies in order; the last is repeated if asked again. The
	// MTTS convention is name, terminal type, then "MTTS <bits>".
	TTYPE []string
	// NAWS window size; zero width means refuse NAWS.
	Width, Height uint16
	// MNES variables sent in reply to NEW-ENVIRON SEND; nil refuses
	// NEW-ENVIRON.
	MNES [][2]string
	// Options the client agrees to when the server offers WILL.
	Accept map[byte]bool
}

// ScreenReaderProfile is a Mudlet-like client with the MTTS screen-reader
// bit set (77 = ANSI 1 + UTF-8 4 + 256 colours 8 + screen reader 64). It
// accepts every option the gateway offers except MCCP2.
func ScreenReaderProfile() Profile {
	return Profile{
		TTYPE:  []string{"SMOKETEST", "XTERM-256COLOR", fmt.Sprintf("MTTS %d", mttsANSI+mttsUTF8+mtts256Colors+mttsScreenReader)},
		Width:  120,
		Height: 40,
		MNES: [][2]string{
			{"CLIENT_NAME", "SmokeTest"},
			{"CLIENT_VERSION", "1.0"},
			// Client-supplied and untrusted: the gateway must not store it.
			{"IPADDRESS", "198.51.100.7"},
		},
		Accept: map[byte]bool{tn.OptCharset: true, tn.OptEOR: true, tn.OptGMCP: true, tn.OptMSSP: true, tn.OptEcho: true},
	}
}

// Client is a scripted telnet client.
type Client struct {
	Conn    net.Conn
	Profile Profile

	raw *bufio.Reader // the uncompressed stream
	src *bufio.Reader // raw, or decompressed while MCCP2 is on

	// Recorded server output.
	Text    bytes.Buffer      // data bytes with telnet commands removed
	Cmds    [][2]byte         // (command, option) pairs received
	SBs     map[byte][][]byte // subnegotiation payloads by option
	Prompts []byte            // EOR or GA, one per prompt received
	// WriteErr is the first error writing a negotiation reply. Reading
	// continues regardless, as a real client's would: the server may have
	// closed after sending text the test still needs to read.
	WriteErr error

	ttype     []string // TTYPE replies not yet sent
	ttypeSent int      // TTYPE replies sent
	mnesSent  bool     // MNES reply sent
	zlibOn    bool
}

// New wraps an established connection.
func New(conn net.Conn, p Profile) *Client {
	raw := bufio.NewReader(conn)
	return &Client{
		Conn: conn, Profile: p, raw: raw, src: raw,
		SBs:   map[byte][][]byte{},
		ttype: append([]string(nil), p.TTYPE...),
	}
}

// Dial connects over TCP, or TLS without certificate verification (dev
// certificates are self-signed).
func Dial(addr string, useTLS bool, p Profile) (*Client, error) {
	d := &net.Dialer{Timeout: DefaultTimeout}
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	return New(conn, p), nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.Conn.Close() }

// Compressed reports whether the client is currently decompressing MCCP2.
func (c *Client) Compressed() bool { return c.zlibOn }

// Got reports whether the server has sent IAC cmd opt.
func (c *Client) Got(cmd, opt byte) bool {
	for _, x := range c.Cmds {
		if x == [2]byte{cmd, opt} {
			return true
		}
	}
	return false
}

// Send writes raw bytes.
func (c *Client) Send(b ...byte) error {
	_, err := c.Conn.Write(b)
	return err
}

// SendSB writes IAC SB opt payload IAC SE, doubling IAC in the payload.
func (c *Client) SendSB(opt byte, payload ...byte) error {
	out := []byte{tn.IAC, tn.SB, opt}
	for _, b := range payload {
		out = append(out, b)
		if b == tn.IAC {
			out = append(out, tn.IAC)
		}
	}
	return c.Send(append(out, tn.IAC, tn.SE)...)
}

// SendLine writes s followed by CRLF.
func (c *Client) SendLine(s string) error { return c.Send([]byte(s + "\r\n")...) }

// Pump reads and handles server output until cond is true or the timeout
// passes. It answers negotiation as the Profile says.
//
// Do not rely on a timeout to mean "nothing more is coming" while MCCP2 is
// on: Go's zlib reader keeps a read error permanently, so a timeout ends
// decompression for the rest of the connection.
func (c *Client) Pump(timeout time.Duration, cond func() bool) error {
	c.Conn.SetReadDeadline(time.Now().Add(timeout))
	for !cond() {
		b, err := c.src.ReadByte()
		if errors.Is(err, io.EOF) && c.zlibOn {
			// The server ended the compressed stream; continue raw.
			c.zlibOn = false
			c.src = c.raw
			continue
		}
		if err != nil {
			return err
		}
		if b != tn.IAC {
			c.Text.WriteByte(b)
			continue
		}
		if err := c.command(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) command() error {
	cmd, err := c.src.ReadByte()
	if err != nil {
		return err
	}
	switch cmd {
	case tn.IAC:
		c.Text.WriteByte(tn.IAC)
	case tn.WILL, tn.WONT, tn.DO, tn.DONT:
		opt, err := c.src.ReadByte()
		if err != nil {
			return err
		}
		c.Cmds = append(c.Cmds, [2]byte{cmd, opt})
		c.noteWrite(c.negotiate(cmd, opt))
	case tn.SB:
		opt, err := c.src.ReadByte()
		if err != nil {
			return err
		}
		var p []byte
		for {
			x, err := c.src.ReadByte()
			if err != nil {
				return err
			}
			if x == tn.IAC {
				y, err := c.src.ReadByte()
				if err != nil {
					return err
				}
				if y == tn.SE {
					break
				}
				x = y // IAC IAC is a literal 255
			}
			p = append(p, x)
		}
		c.SBs[opt] = append(c.SBs[opt], p)
		return c.subneg(opt, p)
	case tn.EOR, tn.GA:
		c.Prompts = append(c.Prompts, cmd)
	}
	return nil
}

func (c *Client) noteWrite(err error) {
	if err != nil && c.WriteErr == nil {
		c.WriteErr = err
	}
}

func (c *Client) negotiate(cmd, opt byte) error {
	switch cmd {
	case tn.DO:
		switch {
		case opt == tn.OptTTYPE && len(c.Profile.TTYPE) > 0,
			opt == tn.OptNewEnviron && c.Profile.MNES != nil:
			return c.Send(tn.IAC, tn.WILL, opt)
		case opt == tn.OptNAWS && c.Profile.Width > 0:
			if err := c.Send(tn.IAC, tn.WILL, opt); err != nil {
				return err
			}
			w, h := c.Profile.Width, c.Profile.Height
			return c.SendSB(tn.OptNAWS, byte(w>>8), byte(w), byte(h>>8), byte(h))
		default:
			return c.Send(tn.IAC, tn.WONT, opt)
		}
	case tn.WILL:
		if c.Profile.Accept[opt] {
			return c.Send(tn.IAC, tn.DO, opt)
		}
		return c.Send(tn.IAC, tn.DONT, opt)
	case tn.WONT:
		if c.Profile.Accept[opt] {
			return c.Send(tn.IAC, tn.DONT, opt)
		}
	}
	return nil
}

func (c *Client) subneg(opt byte, p []byte) error {
	switch opt {
	case tn.OptTTYPE:
		if len(p) > 0 && p[0] == tn.TTypeSend && len(c.ttype) > 0 {
			reply := c.ttype[0]
			if len(c.ttype) > 1 {
				c.ttype = c.ttype[1:]
			}
			c.ttypeSent++
			c.noteWrite(c.SendSB(tn.OptTTYPE, append([]byte{tn.TTypeIs}, reply...)...))
		}
	case tn.OptNewEnviron:
		if len(p) > 0 && p[0] == tn.EnvSend {
			reply := []byte{tn.EnvIs}
			for _, kv := range c.Profile.MNES {
				reply = append(reply, tn.EnvVar)
				reply = append(reply, kv[0]...)
				reply = append(reply, tn.EnvVal)
				reply = append(reply, kv[1]...)
			}
			c.mnesSent = true
			c.noteWrite(c.SendSB(tn.OptNewEnviron, reply...))
		}
	case tn.OptCharset:
		if len(p) > 0 && p[0] == tn.CharsetRequest {
			c.noteWrite(c.SendSB(tn.OptCharset, append([]byte{tn.CharsetAccepted}, "UTF-8"...)...))
		}
	case tn.OptMCCP2:
		// Everything after IAC SB MCCP2 IAC SE is a zlib stream.
		zr, err := zlib.NewReader(c.raw)
		if err != nil {
			return fmt.Errorf("starting MCCP2 decompression: %w", err)
		}
		c.src = bufio.NewReader(zr)
		c.zlibOn = true
	}
	return nil
}

// WaitText pumps until the received text contains s.
func (c *Client) WaitText(s string) error {
	if err := c.Pump(DefaultTimeout, func() bool { return strings.Contains(c.Text.String(), s) }); err != nil {
		return fmt.Errorf("waiting for %q: %w (received %q)", s, err, c.Text.String())
	}
	return nil
}

// WaitPrompt pumps until another prompt terminator (EOR or GA) arrives.
func (c *Client) WaitPrompt() error {
	n := len(c.Prompts)
	if err := c.Pump(DefaultTimeout, func() bool { return len(c.Prompts) > n }); err != nil {
		return fmt.Errorf("waiting for a prompt: %w (received %q)", err, c.Text.String())
	}
	return nil
}

// Round sends a line and returns the text received up to the next prompt
// terminator.
func (c *Client) Round(line string) (string, error) {
	c.Text.Reset()
	if err := c.SendLine(line); err != nil {
		return "", err
	}
	err := c.WaitPrompt()
	return c.Text.String(), err
}

// WaitIdentified pumps until the client has sent every TTYPE reply in its
// profile and, if it has MNES variables, its MNES reply. The server reads
// the connection in order, so anything the test sends afterwards is
// processed after the client's identity is complete. This is the sync
// point to use before asserting on what the server knows about the client.
func (c *Client) WaitIdentified() error {
	done := func() bool {
		return c.ttypeSent >= len(c.Profile.TTYPE) && (c.Profile.MNES == nil || c.mnesSent)
	}
	if err := c.Pump(DefaultTimeout, done); err != nil {
		return fmt.Errorf("waiting for TTYPE/MNES exchange (sent %d of %d TTYPE replies, MNES sent %v): %w",
			c.ttypeSent, len(c.Profile.TTYPE), c.mnesSent, err)
	}
	return nil
}

// Settle reads for a short quiet period so negotiation can finish. It is
// for setup only, never for asserting that something did not arrive; use a
// Round afterwards as the sync point. Not for use while MCCP2 is on (see
// Pump).
func (c *Client) Settle() {
	c.Pump(400*time.Millisecond, func() bool { return false })
}

// LastPrompt returns the terminator of the most recent prompt, or 0.
func (c *Client) LastPrompt() byte {
	if len(c.Prompts) == 0 {
		return 0
	}
	return c.Prompts[len(c.Prompts)-1]
}
