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
- Field names are lowercase and appear once, in the message object and in
  `meta` and `client`. A repeated or non-lowercase name is a protocol
  error: parsers disagree about `{"type":"text","TYPE":"hello"}` and about
  duplicates, so no frame may depend on which way they go. GMCP `data` is
  the player's own JSON and is relayed as it is.
- Unknown fields are ignored. An unknown `type` is ignored and counted, so a
  newer peer can add optional messages without a version bump. Anything a
  peer must understand needs a new protocol version.

## 3. Transport and authentication

- **TCP with mutual TLS** (TLS 1.3 only). The gateway listens on its own
  port, separate from player ports and not meant to be internet-facing. It
  is off unless configured (`-realm-listen`, conventionally
  `127.0.0.1:9030`, or a private address when realms run on other hosts).
- **Trust by pinned key, by CA, or both.** Each side accepts the other's
  certificate if either:
  - **its public key is pinned.** A pin is `sha256/` followed by the base64
    SHA-256 of the certificate's SubjectPublicKeyInfo. Pinning the key, not
    the certificate, means a renewed certificate for the same key keeps
    working. This is the default and needs no infrastructure; or
  - **it chains to a configured CA,** with the right extended key usage
    (client authentication for a realm, server authentication for the
    gateway), and for the gateway the expected name. This is for
    certificate managers that rotate keys, such as cert-manager.

  With neither configured, the side refuses to start: an empty trust is
  never "accept everyone". Identities for pinning are made with
  `-gen-identity PREFIX` (writes `PREFIX.crt`, `.key` with mode 0600, and
  `.pin`, and never overwrites). Pins are compared in canonical base64.
- **A key may register only as its own realm.** Trust in a key is not trust
  in whatever realm id it claims: otherwise one trusted realm could register
  as another while that one is down, and be handed its held players and
  what they type next (red team RT-3-1). So on the gateway:
  - every pin names the realm its key is for: `id=sha256/...`
    (`SANCTUARY_REALM_PINS=live=sha256/...,stub=sha256/...`; a pin with no
    id is refused at startup);
  - a CA-issued realm certificate may register as its Common Name or one of
    its DNS names (a realm id is a valid DNS label), and as nothing else.
    This applies only to certificates that chain to the configured CA; a
    pinned self-signed key gains nothing from its own subject.

  A hello for any other id is answered `reject` with `not-allowed`. The
  realm side pins one gateway, so its pins carry no id.
- **Authenticate before allocating.** Until the TLS handshake completes, a
  connection holds only a pending slot: no protocol buffers, no writer.
  The handshake has 5 seconds; at most 16 may be in progress at once;
  each source (an IPv4 address, or an IPv6 /64) may make 30 attempts a
  minute, and at most 4096 sources are tracked, new ones being refused
  while the table is full of recent ones. The number of registered realms
  is capped (32).
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
{"type": "welcome", "version": 1, "gateway": "…build…", "command_prefix": ">"}
{"type": "reject", "reason": "unsupported-version", "versions": [1]}
```

`command_prefix` is the gateway's command prefix (§5a); absent means `>`.

and closes the link after a `reject`. Reasons: `unsupported-version`,
`duplicate-realm`, `bad-hello`, `too-many-realms`, `not-allowed` (§3). A realm that receives a
`reject` backs off (§8) rather than reconnecting at once.

The hello must arrive within 5 seconds of TLS completing and be at most
4 KiB.

## 5. Sessions

The gateway assigns session ids; they are unique for the gateway's
lifetime and never reused while a link is up.

### Gateway to realm

| `type` | Fields | Meaning |
| --- | --- | --- |
| `session.open` | `session`, `transport`, `secure`, `client`, `account` | A player was routed to this realm. `transport` is the session kind (`telnet`, `ws/gmcp`, …); `secure` says whether the client's link is encrypted; `client` is the client-info object (§7); `account` is who logged in (§7a), absent when the gateway has no accounts. |
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
| `session.close` | `session`, `reason` | Disconnect the player after their queued output is sent. With reason `drain`, the player is handed back instead: the gateway holds them for this realm's return (§8). |

Rules:

- `text` and `prompt` use `\n` for line breaks and may contain ANSI SGR
  colour sequences. Any player-supplied text embedded in them must already be
  sanitised by the realm. The gateway sanitises again before output
  (coding.md §4), keeping only line breaks, tabs and 7-bit SGR
  (`sanitize.Server`), and transliterates to ASCII for clients that
  have not claimed UTF-8.
- Output for a session the gateway does not know (already closed) is
  dropped silently; it is a normal race, not an error.
- Output is applied to the session's bounded queue without blocking
  (`session.QueuePolicy`). If that disconnects the player, the realm gets
  `session.closed` with reason `overflow`.

## 5a. Gateway commands

A line that starts with the gateway's command prefix directly followed by a
letter is a command for the gateway, not the realm: `>lobby`, `>help`,
`>realms`, `>quit` with the default prefix `>`. The gateway answers it and
never forwards it, so **realms must not define commands that start with
the prefix**, and a command the gateway adds later cannot take over one
of theirs. The prefix followed by a space or a non-letter (`> quoted
text`) is an ordinary line and is forwarded.

The prefix is one ASCII punctuation character, set by the gateway's
`SANCTUARY_GATEWAY_CMD_PREFIX` and sent in `welcome` (§4), so a realm can
name it in its own help. Two exceptions keep players' input intact:

- While a realm has asked for hidden input (`input.mode`, a password
  prompt), every line goes to the realm, whatever it starts with.
- GMCP is never inspected for commands.

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

`mtts` is absent when the client sent none. `charset` is what the gateway
will deliver: `"UTF-8"` once the client has claimed UTF-8 (CHARSET, MNES
`CHARSET`, the MTTS UTF-8 bit, or a UTF-8-only transport such as
`gmcp.mudstandards.org`), and absent when it has not, in which case the
gateway folds all text to plain ASCII. MNES variables beyond these are
not forwarded, and `IPADDRESS` never is.

## 7a. Account

The `account` object in `session.open` says who the player logged in as:

```json
{"id": "0123456789abcdef0123456789abcdef", "name": "Mara"}
```

Unlike `client`, it is not a claim: the gateway authenticated the player
(password, and TOTP when enrolled) before routing them, and a realm may
rely on it to find the player's characters. `id` is opaque and stable for
the account's life; key records by it, not by `name`. `name` is 1-32 ASCII
letters and digits, unique ignoring case, for display. The realm never
sees a password or a second factor, and the link carries no way to send
one.

A realm that receives no `account` (a gateway from before stage 03, or a
test harness) must treat the player as anonymous.

## 8. Link lifecycle

- **Keepalive.** Either side may send `{"type": "ping", "n": …}`; the other
  answers `{"type": "pong", "n": …}`. A link with no traffic for 30 seconds
  sends a ping; no pong within 10 seconds closes it.
- **Reconnect.** A realm whose link drops reconnects with exponential
  backoff from 1 second up to 60, with full jitter, so realms restarting
  together do not reconnect in step.
- **Gateway shutdown.** The gateway sends `{"type": "shutdown"}`, then
  `session.closed` (reason `shutdown`) for each session after its output is
  flushed, then closes the link. The final flush has at most 5 seconds in
  all, so a realm that reads slowly cannot hold the gateway open; the
  realm's own drain flush is likewise bounded by what is left of its drain
  deadline.
- **Realm drain** (design §04, "Graceful shutdown"). On SIGTERM the realm
  sends `{"type": "drain", "deadline_ms": N}`, routes no new players (one
  that arrives anyway is handed straight back), tells its players, saves,
  and hands each back with `session.close` reason `drain`. Then it sends
  `{"type": "drained"}` and closes the link. All of this happens within the
  deadline (default 20 s, inside a typical 30 s SIGTERM grace); players
  still attached at the deadline are handed back regardless. The gateway
  holds handed-back players as for a lost realm, below.

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
