# Coding guidelines

How code in Sanctuary is written, by people or with AI assistance. The architecture and its reasoning live in the design document; this file covers day-to-day practice. Testing has its own guidelines in [testing.md](testing.md).

## 1. Reuse first, then extend, then build

Before writing anything new, look for something that already does it, or nearly does.

1. **Search first.** Check the inventory below and grep `internal/` for the concept, not just the name you'd give it. Most "new" needs here are a variant of something that exists: another protocol to frame, another untrusted string to clean, another client to script in a test.
2. **Extend what's close.** If something does 80% of the job, add the missing 20% to it, with its own test, rather than writing a parallel version. Two implementations of one idea drift apart, and the bugs get fixed in only one of them.
3. **Build it reusable.** When nothing fits, write the new piece so the next caller can use it: in its own package or file, with a small exported API, documented, and tested on its own rather than only through its first caller.
4. **Add it to the inventory** in the same change, so the next person finds it.

The test for "reusable" is the second caller. When you notice you're about to write the same logic a second time, stop and extract it. Don't guess at a general version before there are two real uses: a guessed-at abstraction usually fits neither.

### Where this rule stops

Reuse is about not duplicating work, not about abstracting everything. The design document (§03, "Where not to abstract") draws the line: **interfaces belong at infrastructure boundaries** (session state, persistence, secrets, logs, mail, auth). Game systems such as combat, skills, the world model and the script engine are the engine's opinion and get no plug-in layer. Share code inside them freely. Don't make them swappable.

## 2. Inventory of reusable pieces

Keep this current. A reusable piece that isn't listed here is hard to find.

| Need | Use | Where |
| --- | --- | --- |
| Clean untrusted text before output (escapes, C1, bidi, bad UTF-8) | `sanitize.Untrusted` | `internal/sanitize` |
| Clean server output, keeping line breaks and SGR colour | `sanitize.Server` | `internal/sanitize` |
| Fold text to plain ASCII for a client without UTF-8; decide whether it has UTF-8 | `charset.ASCII`, `session.ClientInfo.UTF8` | `internal/charset`, `internal/session/events.go` |
| Parse or format a GMCP message, rejecting malformed JSON | `gmcp.Parse`, `gmcp.Format` | `internal/gmcp` |
| Normalise a client connection into events | `session.Transport` (telnet, WebSocket, in-memory) | `internal/session`, `internal/telnet`, `internal/websocket` |
| Bounded outbound queue with a drop/disconnect policy | `session.Session`, `session.QueuePolicy` | `internal/session/session.go` |
| Connection limits and session tracking | `session.Registry` | `internal/session/registry.go` |
| In-process link with no sockets | `session.NewMemPipe` | `internal/session/mem.go` |
| Telnet option negotiation (RFC 1143) | `qmachine` | `internal/telnet/qmethod.go` |
| Run telnet over any byte stream | `telnet.NewConn` | `internal/telnet/conn.go` |
| Readable rendering of telnet bytes | `telnet.Describe` | `internal/telnet/describe.go` |
| WebSocket upgrade, origin check, framing | `websocket.Upgrade`, `websocket.Conn` | `internal/websocket` |
| Development TLS certificate | `gateway.SelfSigned` | `internal/gateway/tls.go` |
| Declare a program setting once: flag, `SANCTUARY_` env var, env-file key, secret handling | `config.Set` (`String`, `Int`, `Bool`, `Duration`, `Blob`) | `internal/config` |
| Command startup: parse settings, logger, report sources, key pairs, trust | `cli.Parse`, `cli.Logger`, `cli.Report`, `cli.KeyPair`, `cli.Trust` | `internal/cli` |
| Validate a GMCP package name | `gmcp.ValidPackage` | `internal/gmcp` |
| Realm protocol: frames, messages, validation, in-memory link | `realmproto.Conn`, `realmproto.Pipe`, `Encode`/`Decode` | `internal/realmproto` (spec: [protocol.md](protocol.md)) |
| Client info as it crosses to a realm (drops MNES variables), and back | `realmproto.ClientFrom`, `ClientInfo.ToSession` | `internal/realmproto/message.go` |
| Non-blocking, bounded writer for a link (per-session and per-link limits) | `realmproto.Writer` | `internal/realmproto/writer.go` |
| Realm side of a link: handshake, players as `session.Transport`s | `realm.Serve` | `internal/realm` |
| Keep a realm connected: dial over mTLS, reconnect with jittered backoff | `realm.Run`, `realm.TLSDialer`, `realm.Backoff` | `internal/realm/dial.go` |
| Realm-link TLS: pinned keys and/or CA, identities, pin files | `realmproto.ServerTLS`, `ClientTLS`, `Trust`, `WriteIdentity`, `ReadPins` | `internal/realmproto/tls.go` |
| Ping a quiet link, end a silent one | `realmproto.Keepalive`, `Conn.RecvIdle` | `internal/realmproto/keepalive.go` |
| Gateway side of realm links; route a player to a realm | `proxy.Hub`, `proxy.Handler` | `internal/proxy` |
| Realm port: handshake limits, per-source rate limiting | `proxy.Hub.ServeListener` | `internal/proxy/listener.go` |
| The stub realm (echo behind the protocol) | `realm.StubHandler` | `internal/realm/stub.go` |
| Test clients and harnesses | see [testing.md §1](testing.md#1-use-the-shared-scaffolding-extend-it-dont-hand-roll) | |

## 3. Dependencies

The standard library is the default. A third-party module has to justify itself against the design doc's priorities: a small dependency surface is a security property (§02), and `./sanctuary` with no configuration must just work (§03). Note the reason for any dependency in the change that adds it. Every dependency is attack surface: the red team checks each one against known vulnerabilities, and so does an upgrade of Go itself.

**The Go toolchain is a dependency too.** The `go` line in `go.mod` is the security floor: the oldest toolchain allowed to build the gateway. Keep it on a supported release (Go supports its two newest major versions) and raise it to the newest patch release whenever `scripts/vulncheck.sh` reports a fix. Keep the devcontainer's Go version at or above it.

## 4. Untrusted input

- Everything from a client is untrusted: input lines, GMCP payloads, TTYPE/MNES/`Core.Hello` claims, WebSocket headers. Client claims are presentation hints; they never grant anything.
- Clean untrusted text with `sanitize.Untrusted` before it reaches any output, even if a lower layer already did.
- Cap every buffer that a client can grow: lines, subnegotiations, frames, messages, variable counts. A message over a cap is discarded whole, never truncated and then acted on.
- Act only on replies to requests the server actually sent; an unsolicited reply (a TTYPE IS, a CHARSET ACCEPTED) is ignored.
- Every wait on a client is bounded: write timeouts, handshake timeouts, drain timeouts. Make the bound configurable so a test can exercise it in milliseconds.

## 5. Logging

- Structured `log/slog`, with fields rather than interpolated strings.
- **Player text and GMCP payloads are never logged.** Log sizes, package names and counts instead (design doc §02).
- Every line about a connection carries its `session` ID, through the logger the gateway builds for that connection.
- Client *software* identity (client name and version, terminal type, MTTS) may be logged at info level: it describes the program, not the person.
- Anything else a client reports about its environment is not kept or logged. MNES is limited to the variables it defines; plain NEW-ENVIRON variables such as `USER` (the local account name) are dropped with only their name logged at debug level.

## 6. Comments and names

- Package and exported-identifier comments say what something is for, not how it works.
- Where code encodes an external rule, cite it: the RFC section, the MudStandards spec, the client and version whose behaviour it handles, or the design-doc section.
- Name or explain every magic number.

## 7. Finishing a change

- `scripts/test.sh` passes (vet, tests, race detector); `scripts/smoke.sh` passes for anything touching the gateway; `scripts/vulncheck.sh` reports nothing.
- New behaviour has tests that follow [testing.md](testing.md).
- Anything reusable you added is in the inventory above.
- For significant changes, and after any Go or dependency upgrade, run `/red-team`, resolve what it confirms, and record each confirmed finding in [security/redteam-log.md](security/redteam-log.md).
