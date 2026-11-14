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
- Tested live in Mudlet, TinTin++, MUSHclient 5.06 and a browser. MUSHclient
  with default settings accepts only TTYPE (MTTS 9: ANSI, 256 colours) and
  MCCP2; echo, compression and `/secret` masking all work with that subset.
  With its NAWS, EOR and UTF-8 settings turned on it also negotiates NAWS
  and EOR (MTTS 13, adding UTF-8). It still refuses CHARSET, NEW-ENVIRON
  and GMCP (GMCP needs a plugin), so features must not depend on them.
- Red-team rounds 1 and 2 are in [security/redteam-log.md](security/redteam-log.md).

## Stage 02: internal session protocol and a stub world server (done)

Done:

- Protocol spec and `internal/realmproto` (frames, messages, validation,
  in-memory link, bounded non-blocking `Writer`).
- Realm side, `internal/realm`: handshake, and players as
  `session.Transport`s so session handlers run unchanged behind the
  protocol.
- Gateway side, `internal/proxy`: realm registration (version, duplicate
  and cap checks), routing players to a realm, relaying both ways, realm
  output cleaned with `sanitize.Server`.
- Isolation, tested: a stalled realm does not delay another realm's
  players; one player flooding input is disconnected alone; a link whose
  peer stops reading is dropped rather than hanging either side
  (protocol.md §8a).
- The gateway binary runs the stub realm in-process over the in-memory
  link (`-stub-realm`, default on; `-echo` restores stage-01 behaviour).
- Realms as separate processes: the gateway's realm port (`-realm-listen`,
  mTLS only, off by default) with pinned-key and CA trust, handshake
  limits and per-source rate limiting; `sanctuary-realm`, which dials in
  and reconnects with jittered backoff; keepalive on both sides
  (protocol.md §3, §8).

Try it: `scripts/run.sh -log-level debug` (realm in-process) or
`scripts/run.sh -split -log-level debug` (realm as its own process over
mTLS), then connect any client to 9000/9010/9020 as before. The banner says
"stub realm"; `/info` shows the client as the realm sees it (MNES variables
and telnet option lists stay in the gateway, so they no longer appear).

Remaining:

1. Done: drain on SIGTERM, and holding players when a realm drains or is
   lost, re-attaching them when it returns (protocol.md §8); the smoke test
   restarts the realm under a connected player.
2. Done: ASCII fallback. Clients that have not claimed UTF-8 get text folded
   to plain ASCII by the telnet transport (`charset.ASCII`); `/info` now
   says which a client gets.
3. Done: settings from flags, environment and env files (`internal/config`),
   secrets kept out of files; the runtime image (`docker/runtime`) and
   `compose.yaml` (see `deploy/README.md`). Verified on Fedora with Podman and
   Compose v2: `scripts/compose.sh -doppler stg` builds the image, runs both
   containers from Doppler, and serves MUSHclient through the realm.

From design §13: a versioned message schema against a transport interface
(socket and in-memory), a world server that accepts sessions and reflects
text, realm-initiated registration over mTLS, and the drain sequence. The
gateway proxies instead of echoing.

Decided for this stage, beyond the design document:

- The protocol is specified in [protocol.md](protocol.md): JSON messages in
  length-prefixed frames, standard library only, mTLS with key pinning.
- The event schema carries **scene, in-character/out-of-character and pose
  metadata from its first version**, all optional: scenes are supported,
  not assumed, since some realms will be run mainly hack and slash (design
  §02, "What the engine is for"). Adding them later would mean versioning
  every consumer.
- Charset fallback: a client that claims neither UTF-8 (MTTS bit 4,
  CHARSET or MNES) gets plain ASCII text, not UTF-8. It lives in the telnet
  transport for now; revisit when output rendering moves into the realm.
- Build on what stage 01 already has: `session.Transport`, `MemPipe` and
  the shared test clients. See the inventory in [coding.md](coding.md).

## Open items

| Item | When |
| --- | --- |
| Idle timeout (RT-1-A1, accepted for now) | Stage 03, with the lobby and accounts |
| Stage 03: accounts, auth (Argon2id, TOTP, OAuth) and the lobby, with the account store and auth provider as interfaces from the start (design §03, §13) | Next stage |
| Rootless Podman's default port forwarding (rootlessport) hides players' addresses: every connection appears to come from the Podman network, so `MAX_PER_HOST` would cap the whole server and logs cannot tell players apart. Use pasta networking or a proxy that preserves the client address | Before real players connect |
| Remove the deploy-key line from the legacy image | When that image is next rebuilt |
| Decisions still open in design §14: scene presentation, combat timing, remote replay, script migration | Before the stages they block |

## Environment

- Develop in the devcontainer (`ghcr.io/megacosm-entertainment/sanctuary:dev_02`,
  built from `docker/dev/Dockerfile`). It runs as `sanctuary` in
  `/sanctuary/src`, with `../old_game` beside it as read-only reference (the
  rules are in `CLAUDE.md`).
- Commits are signed. Each machine has its own signing and SSH keys; the
  devcontainer uses the host's gpg and SSH agents, and keys are never copied
  into the image or the repo.
- Machines:
  - **Mac (work laptop):** Docker Desktop and VS Code with Microsoft's Dev
    Containers extension. Don't install software on the host; use the
    container.
  - **Fedora desktop:** rootless Podman, VSCodium and DevPod. Start with
    `devpod up ~/devel/new_game/src --ide codium --gpg-agent-forwarding`
    (provider `docker` with `DOCKER_PATH=podman`). DevPod maps `sanctuary`
    to the host uid, so file ownership needs nothing extra. SELinux is
    enforcing, so `~/devel/new_game` (both `src` and `old_game`) is labelled
    `container_file_t` (`chcon -R -t container_file_t ~/devel/new_game`);
    redo that on a fresh checkout if the container gets "Permission denied"
    on `/sanctuary`. `devcontainer.json` does not disable SELinux labelling.
  - The Open Remote - Devcontainer extension for VSCodium does not work with
    this image: its build step runs `apt-get` as the image's user, and the
    image deliberately runs as `sanctuary`, not root.
- Go 1.27.4 is the floor in `go.mod`. When `scripts/vulncheck.sh` reports a
  reachable vulnerability, raise `go.mod` and `GO_VERSION` in the Dockerfile
  together.
