# Status

Where the project stands and what comes next. Update it when a stage
finishes or a decision is made; history belongs in git, not here.

Last updated: 2026-11-14.

## Design

The architecture, its reasoning and the build order are in the design
document, [Sanctuary Engine Architecture](https://claude.ai/artifact/HR5zEGTd1DLFAvm821NzNV).
Read §01 (decisions), §02 (priorities) and §13 (build order) before
starting a stage.

The engine is built for roleplay and worldbuilding, not hack and slash. It
acts as a background game master: it resolves the mechanics and keeps the
world consistent, and leaves the story to the players. Priorities when they
conflict: security, then accessibility, then admin and authoring.

## Stage 01: gateway, echo only (done)

- Listeners: telnet `:9000`, telnet over TLS `:9010`, WebSocket `:9020`
  (WSS; `-ws-plain` for local testing).
- One session abstraction (`internal/session`) over socket and in-memory
  transports, served by an echo handler (`internal/echo`).
- Telnet: RFC 1143 Q method; NAWS, SGA, ECHO, EOR, CHARSET, TTYPE/MTTS,
  MNES, MSSP, MCCP2. GMCP is parsed and logged; malformed GMCP is rejected.
- WebSocket: `gmcp.mudstandards.org` and `telnet.mudstandards.org`
  subprotocols, with an origin check.
- Output sanitised; per-session outbound queues (text overflow disconnects,
  GMCP is dropped above a soft limit).
- Tested live in Mudlet, TinTin++ and a browser. **MUSHclient is not yet
  tested.**
- Red-team rounds 1 and 2 are in [security/redteam-log.md](security/redteam-log.md).

## Stage 02: internal session protocol and a stub world server (next)

From design §13: a versioned message schema against a transport interface
(socket and in-memory), a world server that accepts sessions and reflects
text, realm-initiated registration over mTLS, and the drain sequence. The
gateway proxies instead of echoing.

Decided for this stage, beyond the design document:

- The event schema carries **scene, in-character/out-of-character and pose
  metadata from its first version**, because scenes are first-class (design
  §02, "What the engine is for"). Adding them later would mean versioning
  every consumer.
- Build on what stage 01 already has: `session.Transport`, `MemPipe` and
  the shared test clients. See the inventory in [coding.md](coding.md).

## Open items

| Item | When |
| --- | --- |
| Test against MUSHclient | Any time; before stage 02 is closed |
| Idle timeout (RT-1-A1, accepted for now) | Stage 03, with the lobby and accounts |
| Small runtime image for servers. `docker/dev` is for development only: passwordless sudo, Claude Code, compilers | Before anything is reachable from the internet |
| Remove the deploy-key line from the legacy image | When that image is next rebuilt |
| Decisions still open in design §14: scene presentation, combat timing, remote replay, script migration | Before the stages they block |

## Environment

- Develop in the devcontainer (`ghcr.io/megacosm-entertainment/sanctuary:dev_01`,
  built from `docker/dev/Dockerfile`). It runs as `sanctuary` in
  `/sanctuary/src`, with `../old_game` beside it as read-only reference (the
  rules are in `CLAUDE.md`).
- Commits are signed. Each machine has its own signing and SSH keys; the
  devcontainer uses the host's gpg and SSH agents, and keys are never copied
  into the image or the repo.
- Go 1.27.4 is the floor in `go.mod`. When `scripts/vulncheck.sh` reports a
  reachable vulnerability, raise `go.mod` and `GO_VERSION` in the Dockerfile
  together.
