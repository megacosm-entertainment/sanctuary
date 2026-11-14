// Command gateway-smoke drives a running gateway the way MUD clients do and
// reports PASS/FAIL per check. It uses the same scripted clients as the
// end-to-end tests (telnettest, wstest) and needs nothing but Go.
//
//	go run ./cmd/gateway-smoke -host localhost -telnet 9000 -telnets 9010 -ws 9020
package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	tn "sanctuary/internal/telnet"
	"sanctuary/internal/telnet/telnettest"
	ws "sanctuary/internal/websocket"
	"sanctuary/internal/websocket/wstest"
)

var (
	host    = flag.String("host", "localhost", "gateway host")
	tport   = flag.String("telnet", "9000", "plain telnet port (empty skips)")
	tlsport = flag.String("telnets", "9010", "telnet+TLS port (empty skips)")
	wsport  = flag.String("ws", "9020", "WebSocket port (empty skips)")
	wsPlain = flag.Bool("ws-plain", false, "gateway serves ws:// rather than wss://")
	verbose = flag.Bool("v", false, "print received text on failure")
)

var failures int

func check(name string, err error) {
	if err != nil {
		failures++
		fmt.Printf("FAIL  %s: %v\n", name, err)
		return
	}
	fmt.Printf("PASS  %s\n", name)
}

func main() {
	flag.Parse()
	if *tport != "" {
		telnetChecks()
		mccpChecks()
	}
	if *tlsport != "" {
		tlsChecks()
	}
	if *wsport != "" {
		wsChecks()
	}
	if failures > 0 {
		fmt.Printf("\n%d check(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nall checks passed")
}

// contains reports a missing substring as an error, with the received text
// when -v is set.
func contains(out string, err error, wants ...string) error {
	if err != nil {
		return err
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			if *verbose {
				fmt.Printf("      received: %q\n", out)
			}
			return fmt.Errorf("missing %q", w)
		}
	}
	return nil
}

// connect dials, waits for the first prompt and for the client to finish
// identifying itself, so later checks see complete negotiation.
func connect(name, port string, useTLS bool, p telnettest.Profile) *telnettest.Client {
	addr := net.JoinHostPort(*host, port)
	c, err := telnettest.Dial(addr, useTLS, p)
	if err == nil {
		err = c.WaitPrompt()
	}
	if err == nil {
		err = c.WaitIdentified()
	}
	check(name+": connect to "+addr+" and negotiate", err)
	if err != nil {
		if c != nil {
			c.Close()
		}
		return nil
	}
	return c
}

// ---------------------------------------------------------------- telnet

func telnetChecks() {
	c := connect("telnet", *tport, false, telnettest.ScreenReaderProfile())
	if c == nil {
		return
	}
	defer c.Close()

	// Stage 02: the session is served by a realm through the realm
	// protocol, not by the gateway itself. The stub realm's banner says so.
	check("telnet: served by the stub realm through the realm protocol", contains(c.Text.String(), nil, "stub realm"))

	check("telnet: server offers TTYPE, NAWS, NEW-ENVIRON, CHARSET, EOR, GMCP, MSSP, MCCP2", func() error {
		var missing []string
		for _, w := range [][2]byte{{tn.DO, tn.OptTTYPE}, {tn.DO, tn.OptNAWS}, {tn.DO, tn.OptNewEnviron},
			{tn.WILL, tn.OptCharset}, {tn.WILL, tn.OptEOR}, {tn.WILL, tn.OptGMCP}, {tn.WILL, tn.OptMSSP}, {tn.WILL, tn.OptMCCP2}} {
			if !c.Got(w[0], w[1]) {
				missing = append(missing, tn.Describe([]byte{tn.IAC, w[0], w[1]}))
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("missing %s", strings.Join(missing, ", "))
		}
		return nil
	}())
	check("telnet: MTTS cycle asks TTYPE three times", func() error {
		if n := len(c.SBs[tn.OptTTYPE]); n != 3 {
			return fmt.Errorf("asked %d times, want 3", n)
		}
		return nil
	}())
	check("telnet: MSSP reports NAME, PLAYERS, UPTIME and FAMILY Custom", func() error {
		if len(c.SBs[tn.OptMSSP]) == 0 {
			return errors.New("no MSSP subnegotiation received")
		}
		m := c.SBs[tn.OptMSSP][0]
		variable := func(name string) []byte { return append(append([]byte{tn.MSSPVarCode}, name...), tn.MSSPValCode) }
		for _, v := range [][]byte{variable("NAME"), variable("PLAYERS"), variable("UPTIME"), append(variable("FAMILY"), "Custom"...)} {
			if !bytes.Contains(m, v) {
				return fmt.Errorf("missing %q in %q", v, m)
			}
		}
		return nil
	}())

	out, err := c.Round("hello from the smoke test")
	check("telnet: echo", contains(out, err, "You said: hello from the smoke test"))
	check("telnet: prompt ends with IAC EOR", func() error {
		if p := c.LastPrompt(); p != tn.EOR {
			return fmt.Errorf("ended with %s", tn.Describe([]byte{tn.IAC, p}))
		}
		return nil
	}())

	out, err = c.Round("red \x1b[31mtext\x1b[0m \x1b]0;retitled\x07end")
	check("telnet: control sequences stripped from echo", func() error {
		if err == nil && strings.ContainsAny(out, "\x1b\x07") {
			return fmt.Errorf("escape survived: %q", out)
		}
		return contains(out, err, "You said: red text end")
	}())

	out, err = c.Round("/info")
	check("telnet: /info shows MNES name, screen reader, NAWS and UTF-8",
		contains(out, err, "SmokeTest 1.0", "XTERM-256COLOR", "screen reader: true", "120 x 40", "UTF-8"))
	check("telnet: client-supplied IPADDRESS is not stored", func() error {
		if strings.Contains(out, "198.51.100.7") {
			return errors.New("IPADDRESS shown in /info")
		}
		return nil
	}())

	var gmcpErr error
	for _, msg := range []string{`Core.Hello {"client":"SmokeTest","version":"1.0"}`, `Core.Hello {"client":`} {
		if err := c.SendSB(tn.OptGMCP, []byte(msg)...); err != nil && gmcpErr == nil {
			gmcpErr = err
		}
	}
	out, err = c.Round("after gmcp")
	if gmcpErr != nil {
		err = gmcpErr
	}
	check("telnet: valid and malformed GMCP accepted without disconnect", contains(out, err, "You said: after gmcp"))

	c.Text.Reset()
	n := len(c.Prompts)
	err = c.SendLine("/secret")
	if err == nil {
		// Wait for the prompt's terminator too, so the next round starts clean.
		err = c.Pump(telnettest.DefaultTimeout, func() bool { return c.Got(tn.WILL, tn.OptEcho) && len(c.Prompts) > n })
	}
	check("telnet: /secret sends WILL ECHO (input masking)", err)
	out, err = c.Round("hunter2")
	check("telnet: hidden input not echoed, ECHO released", func() error {
		if err != nil {
			return err
		}
		if strings.Contains(out, "hunter2") {
			return errors.New("secret echoed")
		}
		if !c.Got(tn.WONT, tn.OptEcho) {
			return errors.New("no WONT ECHO")
		}
		return contains(out, nil, "7 characters")
	}())

	// RFC 1143: repeating a request for an already-enabled option must not
	// be answered. The echo round afterwards is the sync point: the server
	// handles input in order, so any reply to the spam arrives before it.
	before := len(c.Cmds)
	var spam []byte
	for i := 0; i < 200; i++ {
		spam = append(spam, tn.IAC, tn.DO, tn.OptEOR, tn.IAC, tn.WILL, tn.OptNAWS)
	}
	err = c.Send(spam...)
	if err == nil {
		out, err = c.Round("still alive")
		err = contains(out, err, "You said: still alive")
	}
	check("telnet: repeated DO/WILL for enabled options not answered (Q method)", func() error {
		if err != nil {
			return err
		}
		if d := len(c.Cmds) - before; d != 0 {
			return fmt.Errorf("server answered %d times", d)
		}
		return nil
	}())

	err = c.SendLine("/quit")
	if err == nil {
		err = c.Pump(telnettest.DefaultTimeout, func() bool { return false })
	}
	check("telnet: /quit closes the connection", func() error {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("expected EOF, got %v", err)
	}())
}

func mccpChecks() {
	p := telnettest.ScreenReaderProfile()
	p.Accept[tn.OptMCCP2] = true
	c := connect("mccp2", *tport, false, p)
	if c == nil {
		return
	}
	defer c.Close()
	check("mccp2: compression started", func() error {
		if !c.Compressed() {
			return errors.New("no IAC SB MCCP2 IAC SE received")
		}
		return nil
	}())
	out, err := c.Round("compressed hello")
	check("mccp2: echo through the compressed stream", contains(out, err, "You said: compressed hello"))

	err = c.Send(tn.IAC, tn.DONT, tn.OptMCCP2)
	if err == nil {
		err = c.Pump(telnettest.DefaultTimeout, func() bool { return c.Got(tn.WONT, tn.OptMCCP2) })
	}
	check("mccp2: DONT ends the stream and the server sends WONT uncompressed", func() error {
		if err != nil {
			return err
		}
		if c.Compressed() {
			return errors.New("still reading compressed data")
		}
		return nil
	}())
	out, err = c.Round("plain again")
	check("mccp2: echo after compression stopped", contains(out, err, "You said: plain again"))
}

func tlsChecks() {
	c := connect("tls", *tlsport, true, telnettest.ScreenReaderProfile())
	if c == nil {
		return
	}
	defer c.Close()
	check("tls: protocol is TLS 1.2 or later", func() error {
		tc, ok := c.Conn.(*tls.Conn)
		if !ok {
			return errors.New("not a TLS connection")
		}
		if v := tc.ConnectionState().Version; v < tls.VersionTLS12 {
			return fmt.Errorf("version %#x", v)
		}
		return nil
	}())
	out, err := c.Round("over tls")
	check("tls: echo", contains(out, err, "You said: over tls"))
	out, err = c.Round("/info")
	check("tls: session reports encrypted transport", contains(out, err, "telnet+tls (encrypted: true)"))
}

// ---------------------------------------------------------------- WebSocket

// upgraded checks a handshake result and returns a usable client or nil.
func upgraded(name, wantProto string, c *wstest.Client, resp *http.Response, err error) *wstest.Client {
	check(name, func() error {
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Protocol") != wantProto {
			return fmt.Errorf("status %d protocol %q, want 101 %q", resp.StatusCode, resp.Header.Get("Sec-WebSocket-Protocol"), wantProto)
		}
		return nil
	}())
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}
	return c
}

func refused(name string, opts wstest.DialOptions, want int) {
	c, resp, err := wstest.Dial(net.JoinHostPort(*host, *wsport), opts)
	check(name, func() error {
		if err != nil {
			return err
		}
		c.Close()
		if resp.StatusCode != want {
			return fmt.Errorf("status %d, want %d", resp.StatusCode, want)
		}
		return nil
	}())
}

func wsChecks() {
	addr := net.JoinHostPort(*host, *wsport)
	scheme := "https"
	if *wsPlain {
		scheme = "http"
	}
	sameOrigin := scheme + "://" + addr
	secure := !*wsPlain

	c, resp, err := wstest.Dial(addr, wstest.DialOptions{TLS: secure, Protocols: []string{ws.ProtoGMCP}, Origin: sameOrigin})
	if c = upgraded("ws/gmcp: upgrade with a same-origin browser Origin", ws.ProtoGMCP, c, resp, err); c != nil {
		_, err = c.ReadUntil(ws.OpBinary, "> ")
		check("ws/gmcp: banner in binary frames", err)
		for _, m := range []struct {
			op byte
			s  string
		}{
			{ws.OpText, `Core.Hello {"client":"SmokeTest"}`},
			{ws.OpText, `Core.Hello {broken`},
			{ws.OpBinary, "hello websocket\n"},
		} {
			if err == nil {
				err = c.Send(m.op, []byte(m.s))
			}
		}
		if err == nil {
			_, err = c.ReadUntil(ws.OpBinary, "You said: hello websocket")
		}
		check("ws/gmcp: echo after valid and malformed GMCP text frames", err)
		out := ""
		if err == nil {
			err = c.Send(ws.OpBinary, []byte("/info\n"))
		}
		if err == nil {
			out, err = c.ReadUntil(ws.OpBinary, "Terminal:")
		}
		check("ws/gmcp: /info names the client from GMCP Core.Hello", contains(out, err, "SmokeTest"))
		check("ws/gmcp: ping answered with pong", func() error {
			if err := c.Send(ws.OpPing, []byte("ping")); err != nil {
				return err
			}
			for {
				op, p, err := c.ReadFrame()
				if err != nil {
					return err
				}
				if op == ws.OpPong {
					if string(p) != "ping" {
						return fmt.Errorf("pong payload %q, want \"ping\"", p)
					}
					return nil
				}
			}
		}())
		c.Close()
	}

	c, resp, err = wstest.Dial(addr, wstest.DialOptions{TLS: secure, Protocols: []string{ws.ProtoTelnet}})
	if c = upgraded("ws/telnet: upgrade without Origin (a non-browser client)", ws.ProtoTelnet, c, resp, err); c != nil {
		out, err := c.ReadUntil(ws.OpBinary, "> ")
		check("ws/telnet: telnet negotiation carried in binary frames", func() error {
			if err != nil {
				return err
			}
			if !strings.Contains(out, string([]byte{tn.IAC, tn.WILL, tn.OptGMCP})) {
				return fmt.Errorf("no IAC WILL GMCP in %s", tn.Describe([]byte(out)))
			}
			return nil
		}())
		err = c.Send(ws.OpBinary, []byte("hello telnet over ws\r\n"))
		if err == nil {
			_, err = c.ReadUntil(ws.OpBinary, "You said: hello telnet over ws")
		}
		check("ws/telnet: echo", err)
		c.Close()
	}

	refused("ws: cross-origin browser connection refused (403)",
		wstest.DialOptions{TLS: secure, Protocols: []string{ws.ProtoGMCP}, Origin: "https://evil.example"}, http.StatusForbidden)
	refused("ws: connection offering no subprotocol refused (400)",
		wstest.DialOptions{TLS: secure}, http.StatusBadRequest)
	refused("ws: unsupported subprotocol refused (400)",
		wstest.DialOptions{TLS: secure, Protocols: []string{"chat"}}, http.StatusBadRequest)

	check("ws: test page served at /", func() error {
		cl := &http.Client{Timeout: wstest.DefaultTimeout, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // dev certificate is self-signed
		r, err := cl.Get(sameOrigin + "/")
		if err != nil {
			return err
		}
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		if r.StatusCode != http.StatusOK || !bytes.Contains(b, []byte("WebSocket test client")) {
			return fmt.Errorf("status %d, want 200 with the test page", r.StatusCode)
		}
		return nil
	}())
}
