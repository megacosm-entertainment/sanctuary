package websocket

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MudStandards subprotocols (https://mudstandards.org/websocket/).
const (
	// ProtoGMCP: ANSI text in binary frames, GMCP in text frames.
	ProtoGMCP = "gmcp.mudstandards.org"
	// ProtoTelnet: the full telnet stream, options included, in binary frames.
	ProtoTelnet = "telnet.mudstandards.org"
	// protoTelnetAlias is the short alias the spec allows for ProtoTelnet.
	protoTelnetAlias = "telnet"
)

// Supported lists the subprotocols in server preference order.
var Supported = []string{ProtoGMCP, ProtoTelnet}

const acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// HandshakeError is an upgrade refusal with the HTTP status to send.
type HandshakeError struct {
	Status int
	Msg    string
}

func (e *HandshakeError) Error() string { return e.Msg }

// OriginPolicy decides whether a browser origin may connect.
//
// Requests with no Origin header come from non-browser clients, which cannot
// be used for cross-site WebSocket hijacking, and are allowed. A request
// with an Origin must match Allowed exactly (scheme://host[:port]), or, when
// Allowed is empty, must be same-origin with the request: the same host and
// port, and https exactly when the request arrived over TLS.
type OriginPolicy struct {
	Allowed []string
}

func (p OriginPolicy) Check(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return errors.New("unparseable origin")
	}
	norm := strings.ToLower(u.Scheme + "://" + u.Host)
	if len(p.Allowed) > 0 {
		for _, a := range p.Allowed {
			if strings.EqualFold(strings.TrimRight(a, "/"), norm) {
				return nil
			}
		}
		return errors.New("origin not allowed: " + origin)
	}
	// Same origin means same scheme as well as host and port (RFC 6454).
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if strings.EqualFold(u.Scheme, scheme) && strings.EqualFold(u.Host, r.Host) {
		return nil
	}
	return errors.New("cross-origin request: " + origin)
}

// Negotiate validates an upgrade request and chooses a subprotocol. It
// returns the canonical subprotocol name and the value to echo in the
// Sec-WebSocket-Protocol response header (the client's own spelling).
//
// Negotiation is explicit: a client that offers none of the supported
// subprotocols is refused rather than defaulted, because telnet-over-
// WebSocket and the GMCP subprotocol are not interchangeable.
func Negotiate(r *http.Request, origins OriginPolicy) (proto, echo string, err error) {
	if r.Method != http.MethodGet {
		return "", "", &HandshakeError{http.StatusMethodNotAllowed, "websocket upgrade requires GET"}
	}
	if !headerHasToken(r.Header, "Connection", "upgrade") || !headerHasToken(r.Header, "Upgrade", "websocket") {
		return "", "", &HandshakeError{http.StatusBadRequest, "not a websocket upgrade"}
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return "", "", &HandshakeError{http.StatusUpgradeRequired, "unsupported websocket version"}
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if k, err := base64.StdEncoding.DecodeString(key); err != nil || len(k) != 16 {
		return "", "", &HandshakeError{http.StatusBadRequest, "bad Sec-WebSocket-Key"}
	}
	if err := origins.Check(r); err != nil {
		return "", "", &HandshakeError{http.StatusForbidden, err.Error()}
	}
	offered := map[string]string{}
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			canon := strings.ToLower(p)
			if canon == protoTelnetAlias {
				canon = ProtoTelnet
			}
			if _, seen := offered[canon]; !seen && p != "" {
				offered[canon] = p
			}
		}
	}
	for _, s := range Supported {
		if spelled, ok := offered[s]; ok {
			return s, spelled, nil
		}
	}
	return "", "", &HandshakeError{http.StatusBadRequest,
		"no supported subprotocol offered; use one of: " + strings.Join(Supported, ", ")}
}

// AcceptKey computes Sec-WebSocket-Accept.
func AcceptKey(key string) string {
	h := sha1.Sum([]byte(key + acceptGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// Upgrade negotiates, hijacks the HTTP connection and completes the
// handshake. On failure it has already written the HTTP error response.
func Upgrade(w http.ResponseWriter, r *http.Request, origins OriginPolicy) (*Conn, string, error) {
	proto, echo, err := Negotiate(r, origins)
	if err != nil {
		var he *HandshakeError
		if errors.As(err, &he) {
			if he.Status == http.StatusUpgradeRequired {
				w.Header().Set("Sec-WebSocket-Version", "13")
			}
			http.Error(w, he.Msg, he.Status)
		}
		return nil, "", err
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unsupported", http.StatusInternalServerError)
		return nil, "", errors.New("response writer cannot hijack")
	}
	nc, brw, err := hj.Hijack()
	if err != nil {
		return nil, "", err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + AcceptKey(r.Header.Get("Sec-WebSocket-Key")) + "\r\n" +
		"Sec-WebSocket-Protocol: " + echo + "\r\n\r\n"
	// Clear the HTTP server's deadlines; the session sets its own.
	nc.SetDeadline(time.Time{})
	if _, err := brw.WriteString(resp); err != nil {
		nc.Close()
		return nil, "", err
	}
	if err := brw.Flush(); err != nil {
		nc.Close()
		return nil, "", err
	}
	return newConn(nc, brw.Reader), proto, nil
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}
