# Realm protocol, version 1 (draft)

The internal protocol between the gateway and a realm (design §04, "The
internal protocol"). The gateway owns every client socket; a realm sees only
the messages below. This document is the contract: the Go package
`internal/realmproto` implements it, and a realm written in another
language implements it from this text.

Status: **draft for stage 02**, decisions agreed 2026-11-14; it becomes
version 1 when stage 02 ships.

## 1. Principles

- **Realms dial the gateway.** A realm connects outbound, proves who it is,
  and is added to the realm list. The gateway needs no list of realm
  addresses (design §04, "Realms dial the gateway").
- **One link per realm.** Every player session for a realm is multiplexed
  over that realm's single link, so connection count scales with realms, not
  players.
- **Asynchronous.** Messages are one-way; nothing waits for a reply except
  the handshake and the drain. A realm's tick never blocks on the gateway,
  and the gateway never blocks on a realm.
- **Events, not finished text, where it matters.** Output carries
  presentation metadata (§6) so the gateway, GMCP clients, screen readers
  and scene logs can tell a pose from a system message without parsing it.
- **Encrypted, always.** No plaintext form of the protocol exists (design
  §01, "Transport security"). See §3.

## 2. Framing

A link is a byte stream carrying frames. Each frame is:

```
uint32  length    big-endian, bytes of payload that follow
bytes   payload   one JSON object, UTF-8
```

- `length` is at most **262 144** (256 KiB), the gateway's per-session
  outbound budget: no single message may exceed what a session can queue.
  A larger length is a protocol error; the receiver closes the link without
  reading the payload.
- A payload that is not one JSON object, or is not valid UTF-8, is a
  protocol error.
- Every object has a string field `type`. Messages about a session also
  have `session`, an integer from 1 to 2^53-1 chosen by the gateway (§5);
  the upper bound is the largest integer every JSON implementation reads
  exactly.
- Unknown fields are ignored. An unknown `type` is ignored and counted, so a
  newer peer can add optional messages without a version bump. Anything a
  peer must understand needs a new protocol version.

## 3. Transport and authentication

- **TCP with mutual TLS** (TLS 1.3 only). The gateway listens on its own
  port, separate from player ports and not meant to be internet-facing
  (default `127.0.0.1:9030`).
- **Allowlist by certificate.** The gateway accepts a realm only if the
  SHA-256 of its certificate's public key (SPKI) is on the configured
  allowlist. No CA trust, so issuing a certificate grants nothing by itself.
  The realm pins the gateway's key the same way.
- **Authenticate before allocating.** Until the TLS handshake completes, a
  connection gets a short handshake timeout and no buffers beyond TLS's own.
  Registration attempts are rate-limited per source address, and the number
  of registered realms is capped.
- **In-memory transport** for tests and same-process use: the same frames
  over an in-process pipe, with no TLS because nothing leaves the process.

**The one-command launcher** (design §04, "Deployment modes") runs gateway
and realm as two processes on one host. They use the same mTLS over
loopback, with keys the launcher generates on first run, so even the local
case has no plaintext link. There is no Unix-socket or plaintext exemption.

## 4. Handshake and versions

After TLS, the realm speaks first:

```json
{"type": "hello", "versions": [1], "realm": "live",
 "name": "Sanctuary", "build": "1c3784d", "fingerprint": "sha256:…"}
```

- `versions`: protocol versions the realm supports.
- `realm`: a short id, `[a-z0-9-]{1,32}`, unique among connected realms.
- `name`: shown in the realm list; untrusted text, sanitised before display.
- `build`: the realm's build identity.
- `fingerprint`: the ruleset fingerprint (design §06). Carried from version
  1 so peering can be added without a protocol change; unused in stage 02.

The gateway answers with one of:

```json
{"type": "welcome", "version": 1, "gateway": "…build…"}
{"type": "reject", "reason": "unsupported-version", "versions": [1]}
```

and closes the link after a `reject`. Reasons: `unsupported-version`,
`duplicate-realm`, `bad-hello`, `too-many-realms`. A realm that receives a
`reject` backs off (§8) rather than reconnecting at once.

The hello must arrive within 5 seconds of TLS completing and be at most
4 KiB.

## 5. Sessions

The gateway assigns session ids; they are unique for the gateway's
lifetime and never reused while a link is up.

### Gateway to realm

| `type` | Fields | Meaning |
| --- | --- | --- |
| `session.open` | `session`, `transport`, `secure`, `client` | A player was routed to this realm. `transport` is the session kind (`telnet`, `ws/gmcp`, …); `secure` says whether the client's link is encrypted; `client` is the client-info object (§7). |
| `input` | `session`, `text` | One line of input. Valid UTF-8 with control sequences stripped, at most 4096 bytes. Still untrusted. |
| `gmcp` | `session`, `package`, `data` | A well-formed GMCP message from the client. `data` is any JSON value, or absent. |
| `client` | `session`, `client` | The client's self-description changed (window resized, MNES update). |
| `session.closed` | `session`, `reason` | The player is gone. Reasons: `quit`, `disconnected`, `overflow`, `shutdown`. No more messages for this session will be accepted. |

### Realm to gateway

| `type` | Fields | Meaning |
| --- | --- | --- |
| `text` | `session`, `text`, `meta` | Output ending with a line break. `meta` is optional (§6). |
| `prompt` | `session`, `text` | Output that expects input; telnet ends it with EOR. |
| `gmcp` | `session`, `package`, `data` | GMCP to the client, discarded if the client has no GMCP. |
| `input.mode` | `session`, `hidden` | Stop or resume local echo (password entry). |
| `session.close` | `session`, `reason` | Disconnect the player after their queued output is sent. |

Rules:

- `text` and `prompt` use `\n` for line breaks and may contain ANSI SGR
  colour sequences. Any player-supplied text embedded in them must already be
  sanitised by the realm. The gateway sanitises again before output
  (coding.md §4), keeping only line breaks, tabs and 7-bit SGR
  (`sanitize.Server`), and will transliterate to ASCII for clients that
  have not claimed UTF-8.
- Output for a session the gateway does not know (already closed) is
  dropped silently; it is a normal race, not an error.
- Output is applied to the session's bounded queue without blocking
  (`session.QueuePolicy`). If that disconnects the player, the realm gets
  `session.closed` with reason `overflow`.

## 6. Output metadata

Output can say what it is, so roleplay scenes, scene logs, GMCP clients and
screen readers can tell a pose from a system message without parsing text
(design §02, "What the engine is for"). `meta` is an object; every field is
optional, and `meta` itself may be absent.

Scenes are supported, not assumed. Much output belongs to no scene: a realm
run mostly for combat and exploration may never set `scene` at all, and
that is a normal configuration, not a degraded one. `kind` and `voice` are
useful either way.

| Field | Values | Meaning |
| --- | --- | --- |
| `kind` | `narration`, `pose`, `say`, `emote`, `ooc`, `system`, `combat`, `alert` | What the text is. `alert` always breaks through filtered views (design §09). Other lowercase tokens are accepted and passed through, so a realm can add a kind without a version bump; a receiver that does not know a kind treats it as `narration`. |
| `voice` | `ic`, `ooc` | In character or out of character. Absent means not applicable (system text). |
| `scene` | string id | The scene this belongs to, for scene logs. Absent when the output is not part of a scene. |
| `actor` | string id | Who produced it, when that is a character. Opaque to the gateway. |

The gateway does not interpret these in stage 02 beyond passing them on to
GMCP clients later; they exist in version 1 so that every realm emits them
from the start.

**Scene start and end** will be their own messages (`scene.start`,
`scene.end`, carrying participants and title), added when scene logs are
built. Because unknown types are ignored, that needs no version bump; until
then `meta.scene` is the only scene information on the wire.

## 7. Client info

The `client` object mirrors `session.ClientInfo`: everything is a client
claim, a presentation hint, never a credential.

```json
{"name": "mushclient", "version": "", "terminal": "ANSI",
 "mtts": 13, "charset": "UTF-8", "width": 80, "height": 26,
 "screen_reader": false}
```

`mtts` is absent when the client sent none. MNES variables beyond these are
not forwarded, and `IPADDRESS` never is.

## 8. Link lifecycle

- **Keepalive.** Either side may send `{"type": "ping", "n": …}`; the other
  answers `{"type": "pong", "n": …}`. A link with no traffic for 30 seconds
  sends a ping; no pong within 10 seconds closes it.
- **Reconnect.** A realm whose link drops reconnects with exponential
  backoff from 1 second up to 60, with full jitter, so realms restarting
  together do not reconnect in step.
- **Gateway shutdown.** The gateway sends `{"type": "shutdown"}`, then
  `session.closed` (reason `shutdown`) for each session after its output is
  flushed, then closes the link.
- **Realm drain** (design §04, "Graceful shutdown"). On SIGTERM the realm
  sends `{"type": "drain", "deadline_ms": N}`: it accepts no new sessions,
  tells its players, saves, then sends `session.close` for each and finally
  `{"type": "drained"}`. The gateway then closes the link.

- **Realm lost** (crash or network, no drain). Players stay connected to
  the gateway and are told the realm is unavailable. When the realm
  reconnects, each waiting player is offered to it again with a fresh
  `session.open`. Players still waiting after a configurable time (default 2
  minutes) are told and disconnected. Design §04 calls this worth building
  deliberately; the stub realm makes it testable.

## 8a. Backpressure

Neither side ever blocks on the other. Each side writes a link from one
writer with a bounded queue (`realmproto.Writer`); everything else, the
link reader answering a ping included, only queues.

- **Per session.** Each session may have at most 1 MiB queued on a link. A
  session over its share is ended alone (reason `overflow`): one player
  flooding input, or one player a realm floods with output, cannot hold up
  anyone else on the link. Ending a session is always allowed, even when its
  share is full.
- **Per link.** At most 16 MiB queued in all. Past that, or when one frame
  takes longer than 10 seconds to write, the peer has stopped reading: the
  link is closed, the realm is treated as lost (§8), and its players are
  told.
- **Across realms.** Each realm has its own link, reader, writer and
  session table. A stuck realm affects only its own players.

## 9. Logging

Neither side logs `text`, `input` or GMCP `data`. Log message types, sizes,
session ids and counts.
