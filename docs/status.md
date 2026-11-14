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

## Stage 03: accounts, auth and the lobby (in progress)

Decided (2026-11-14): Argon2id passwords via `golang.org/x/crypto`; plain-telnet logins allowed with a warning, `SANCTUARY_REFUSE_PLAINTEXT_LOGIN` to refuse them; sign-up mode a gateway setting, `SANCTUARY_SIGNUP=open|invite|staff` (default open); OAuth after password and TOTP work end to end; our own RFC 6238 TOTP rather than a library.

Done:

- `internal/account`: Argon2id hashing (bounded concurrency, no timing enumeration), TOTP (RFC 6238 vectors, replay protection), secrets sealed at rest (AES-GCM, bound to the account), recovery codes, and the file store (revision checks, cross-process lock, atomic private files, invites).
- Reserved names are a policy: a server's own names merge with the built-in list, or replace it; the words the login prompt uses stay reserved either way.
- Login and lobby (`internal/login`), in front of the realm proxy: log in, or sign up as `SANCTUARY_SIGNUP` allows (open, invite code, or staff only). A wrong name and a wrong password get the same message. Passwords are typed with echo off. Plain telnet gets a warning (`SANCTUARY_REFUSE_PLAINTEXT_LOGIN` refuses it, pointing at TLS). TOTP or a recovery code is asked for when enrolled, a staff-reset password must be changed, disabled accounts are refused (only after a correct password), and old hashes are upgraded. Failed logins are throttled per account and per address, across connections (`login.Throttle`); so are sign-ups per address. A connection that has not logged in within `SANCTUARY_LOGIN_TIMEOUT` (2 minutes) is closed, which settles the unauthenticated half of RT-1-A1.
- The lobby lists realms; Enter picks the first. Leaving a realm (`quit` in the stub, or `>lobby` anywhere) comes back to the lobby; `quit` there disconnects. The account travels to the realm in `session.open` (protocol.md §7a), and the stub's `info` shows it.
- `PUBLIC_TELNET_PORT`, `PUBLIC_TELNETS_PORT`, `PUBLIC_WS_PORT`: the ports players connect to when they differ from the listen ports. MSSP and the plain-telnet warning name these; compose sets them from the published `PUBLISH_*` ports.
- Settings: `DATA_DIR` (default `data`), `SIGNUP`, `REFUSE_PLAINTEXT_LOGIN`, `RESERVED_NAMES`, `RESERVED_NAMES_REPLACE`, `ACCOUNT_KEY`, `LOGIN_TIMEOUT`. Without `ACCOUNT_KEY` the gateway generates `DATA_DIR/account.key` and warns. `scripts/doppler-seed.sh` sets the key, and the other account settings at their defaults, in Doppler only when they are missing, so a reseed keeps what has been changed there (a new key would also orphan TOTP enrolments); dev uploads the same `data/account.key` local runs use. Compose keeps accounts on the `gateway-data` volume.
- Staff commands, `sanctuary-gateway account list|show|create|reset|invite|role|disable|enable`: the same settings as the gateway, safe while it runs (the store's lock and revision checks). `create` and `reset` print a temporary password that must be changed at the next login; `reset -totp` removes a lost authenticator; reserved names need `-allow-reserved`. Changes apply at the next login: a player already connected stays connected (see open items). Under compose, `scripts/account.sh` runs them (deploy/README.md).
- Account commands in the lobby (`help` lists them): `password` changes it; `totp` sets up an authenticator (key in groups of four and an `otpauth://` link; turned on only after a code from the app checks out; ten recovery codes shown once); `totp off` removes it and `codes` replaces the recovery codes. Each asks for the password again, and with an authenticator a current code too, so a session left logged in cannot be used to take the account over. Failures go back to the lobby, through the same throttle as logins. The issuer shown in the app is `SANCTUARY_NAME`.
- Gateway commands: a line starting with the command prefix and a letter (`>lobby`, `>help`, `>realms`, `>quit`) is the gateway's and never reaches a realm, so the prefix is reserved (protocol.md §5a). `>lobby` leaves a realm, also while held for one that went away. `> text` with a space is ordinary input, and so is everything typed while a realm hides input. In the lobby the same commands work bare or prefixed. The prefix is `SANCTUARY_GATEWAY_CMD_PREFIX` (default `>`, one ASCII punctuation character) and reaches realms in `welcome`. The stub's own commands lost their slash: `info`, `secret`, `quit`, `help`.

Try it: `scripts/run.sh`, connect, type `new`, and choose a name and password. Accounts are kept in `data/` (git-ignored); delete it to start over.

Next:

1. A live test of TOTP set-up and login with a real authenticator app.
2. `Char.Login` over GMCP, then OAuth.

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
"stub realm"; `info` (formerly `/info`) shows the client as the realm sees it (MNES variables
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
| Idle timeout for logged-in players, in the lobby or a realm (the rest of RT-1-A1; the login timeout covers connections that never log in) | With realm idle handling, after stage 03 |
| Rootless Podman's default port forwarding (rootlessport) hides players' addresses: every connection appears to come from the Podman network, so `MAX_PER_HOST` would cap the whole server and logs cannot tell players apart. Use pasta networking or a proxy that preserves the client address | Before real players connect |
| Remove the deploy-key line from the legacy image | When that image is next rebuilt |
| Disabling an account or resetting its password does not reach a player already connected: the staff command is a separate process. The gateway needs to notice (watch the store, or a local control socket) and end or re-check those sessions | Before staff rely on disable for moderation
| Command editor: commands and their permissions edited in-game, not compiled in. Two scopes, since the gateway (lobby, account and staff commands) and each realm have their own command sets, and realms may differ from each other. Arguments are in scope too, not just base commands: permissions on particular arguments (old_game hard-codes checks such as `restore all` in each `do_` function) and aliases that run another command with transformed arguments. Learn from old_game's CMDEdit (`do_cmdedit`, `src/olc.c`), which was bolted onto OLC, and its unbuilt plan, `src/docs/PLAN_command_enhancements.md`; do better on scoping and permissions | With the building tools (design §13), after roles and staff permissions exist |
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
