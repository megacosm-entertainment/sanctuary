# Red-team findings log

Every confirmed finding from a red-team run, kept so later runs can re-attack each one. A finding that reproduces again is a **regression** and is reported as critical, whatever its original severity (see the `red-team` skill, class F).

Each entry names its reproduction: a test in the suite where one exists (re-run it with `scripts/test.sh -run <name>`), otherwise the exact steps. A fix is not done until its reproduction is a test that failed before the fix.

## Format

| Field | Meaning |
| --- | --- |
| ID | `RT-<round>-<n>` |
| Severity | critical / high / medium / low, as first reported |
| Class | the skill's attack class, A-F |
| Finding | what broke, in one line |
| Reproduction | test name, or steps |
| Status | fixed (with commit), accepted (with reason), or open |

## Round 1: 2026-11-13, whole module

Confirmed breaks, and suspected issues that were confirmed on review.

| ID | Severity | Class | Finding | Reproduction | Status |
| --- | --- | --- | --- | --- | --- |
| RT-1-1 | low | C | Malformed WebSocket close frames (one-byte payload, code 0, reserved 1005, non-UTF-8 reason) were acknowledged with 1000 instead of failing the connection (RFC 6455 §5.5.1, §7.4). | `TestProtocolViolationsClose` (close cases) | fixed, dc99fab |
| RT-1-2 | low | C | Every clean shutdown logged an ERROR, because the WebSocket listener was closed before `http.Server.Shutdown`. | `TestShutdownSaysGoodbyeAndDrains` | fixed, dc99fab |
| RT-1-3 | high | A | No test enforced the privacy rule: logging player text or GMCP payloads went unnoticed. | `TestLogsNeverContainPlayerText` | fixed, dc99fab |
| RT-1-4 | high | A | No test covered releasing queued bytes after a write; losing it would disconnect every session after 256 KB of lifetime output. | `TestQueueBytesReleasedAfterWrite` | fixed, dc99fab |
| RT-1-5 | low | D | Same-origin check compared host only, ignoring the scheme. | `TestOriginPolicy` ("same host, other scheme") | fixed, dc99fab |
| RT-1-6 | medium | D | Non-MNES NEW-ENVIRON variables (e.g. `USER`, the local account name) were stored and logged. | `TestClientIdentityIsSanitisedAndCapped/non-MNES_variables_not_kept`, `TestLogsNeverContainPlayerText` | fixed, dc99fab |
| RT-1-7 | low | C | An unsolicited CHARSET ACCEPTED changed the session's charset. | `TestUnsolicitedRepliesIgnored` | fixed, dc99fab |
| RT-1-8 | low | C | `Close` could block for the full 15 s write timeout if a concurrent flush reset its short deadline. | `TestFlushDuringCloseKeepsShortDeadline` | fixed, dc99fab |
| RT-1-9 | low | C | The TLS handshake timeout was hard-coded, so a stalled handshake's slot release was untestable. | `TestStalledTLSHandshakeTimesOut` | fixed, dc99fab |

Surviving mutants from round 1 that now have tests are covered by the tests named above and by those added alongside them (WebSocket framing limits, telnet limits and unsolicited replies, sanitiser 8-bit sequences, GMCP payload aliasing, gateway wiring). Re-running the whole suite re-attacks them.

### Accepted, not fixed

| ID | Finding | Reason |
| --- | --- | --- |
| RT-1-A1 | No idle timeout on telnet or upgraded WebSocket connections; a silent connection or an unfinished WebSocket fragment holds a per-host slot indefinitely. | Idle players are normal in MUDs; the policy belongs with the lobby and accounts in stage 03. Revisit then. |

## Round 2: 2026-11-13, known vulnerabilities (class F)

No production code had changed since round 1. All nine round-1 findings were re-attacked and none regressed; parsers fuzzed clean; twelve hostile `Origin` values were all rejected.

| ID | Severity | Class | Finding | Reproduction | Status |
| --- | --- | --- | --- | --- | --- |
| RT-2-1 | high | F | End-of-life toolchain. `go.mod` said `go 1.23` with no floor; the code was built with go1.23.4 (host) and go1.23.12 (devcontainer). govulncheck found 38 standard-library vulnerabilities reachable from our code, none fixed in the 1.23 line. Reachable from untrusted input: net/http and net/url DoS on the WebSocket upgrade (GO-2025-4012, GO-2026-6218, GO-2026-6603, GO-2026-6617, GO-2026-6859), net/url on the `Origin` header (GO-2025-4010), crypto/tls and crypto/x509 in the TLS handshake (GO-2025-4008, GO-2025-4007). | `scripts/vulncheck.sh` (non-zero exit while any reachable vulnerability remains) | fixed: `go 1.27.4` floor in `go.mod`, devcontainer Go 1.27; govulncheck v1.9.0 reports none |

Notes from verifying this round:

- The run recommended `go1.25.13`. That was wrong: the current release was go1.27.4, Go supports only its two newest major versions (so 1.25 was also end-of-life), and several `net/http` fixes exist only from go1.26.9. Always check the current release list before choosing a target version.
- The run pinned govulncheck v1.1.4, an old release that crashes on Go 1.27 code. `scripts/vulncheck.sh` now pins v1.9.0 and builds it with the module's own toolchain.

Suspected, not demonstrated (now moot at the new floor, kept for the next round to re-check after future upgrades): resource exhaustion on the WebSocket upgrade path via the net/http issues above, and a GO-2025-4010 origin bypass (none found across twelve crafted origins).

## Round 3: 2026-11-14, stage 02 (realm protocol, realm port, settings, deployment)

Scope: everything since round 2 (1c3784d), attacked on the 466af6e tree in a copy. Every past finding re-run first: no regressions; `scripts/vulncheck.sh` clean (go1.27.4, govulncheck v1.9.0). Findings 1-3 and 5 re-verified against edd3771 before recording.

| ID | Severity | Class | Finding | Reproduction | Status |
| --- | --- | --- | --- | --- | --- |
| RT-3-1 | medium | D | A realm id is a claim, not bound to the key that presents it: any trusted realm key can register as another realm's id while that realm is down, and is handed its held players and the input they type next (a password typed at a hidden prompt included). With `Handler.Realm` empty, a trusted key claiming an id that sorts first also gets every new player. | Red-team test `TestRT3OtherIdentityInheritsHeldPlayers`: two pinned keys over real mTLS; the second registers as "live" while live is down and receives a held player's input | fixed: pins name their realm (`id=sha256/...`), CA certificates register only as their CN or DNS names, other ids are rejected `not-allowed`; `TestRealmCannotRegisterAsAnotherRealm`, `TestRealmIDsFromCA` |
| RT-3-2 | low | C | Transports cap a line at 4096 bytes and then sanitise it; invalid bytes become U+FFFD (3 bytes), so the line can exceed `realmproto.MaxInput` and the proxy drops it with no message and no log. | `TestRT3SanitisedLineOverMaxInputIsDropped`; live: 3000 bytes of 0x80 then CRLF to telnet, no echo | fixed: `sanitize.UntrustedLine` caps after cleaning, in both transports; a line still refused by the protocol is logged; `TestUntrustedLineCapsAfterCleaning` |
| RT-3-3 | low | D | Secret blob content given where a path is expected (flag or `_FILE`) is logged twice: in the settings report and in the file-open error. | `-realm-key '<fake PEM>'`, then grep the log for the fake content (2 lines: INFO setting, ERROR realm port) | fixed: a secret "path" that looks like content is refused without echoing it; secret paths show as `[file]`; open errors omit the path; `TestSecretPastedAsPathNeverShown`, `TestSecretFileErrorOmitsPath` |
| RT-3-4 | low | C | The realm port's rate limiter scans its whole map on every accept once more than 1024 sources are recent: cost grows with the square of distinct sources (261 µs per accept at 40,000). Needs many source addresses (an IPv6 /64); the realm port is not meant to be internet-facing. | In-package loop of `allow()` over n distinct IPv6 keys | fixed: table capped at 4096 sources, pruning amortised to 16 times a window, IPv6 counted by /64; `TestRateLimiterBoundedUnderManySources`, `TestSourceKeyGroupsIPv6By64` |
| RT-3-5 | low | A | `ParsePin` accepts non-canonical base64 (non-zero padding bits) and returns it unchanged, so a pin for the right key never matches and the realm is refused with no hint why. | `TestRT3NonCanonicalPinAcceptedButNeverMatches` | fixed: pins re-encoded canonically; `TestParsePinCanonicalises` |
| RT-3-6 | low | B | Tests ignore errors (testing.md §6): `internal/proxy/listener_test.go:31` and `:246`, `internal/config/config_test.go:163`. | Read the lines | fixed |
| RT-3-7 | medium | A | Surviving mutants for load-bearing behaviour: Encode's frame limit (oversize realm output would close the link for everyone instead of dropping one message), the `session.closed` overflow exemption, sanitising of prompts, the 4 KiB hello cap, sanitising of realm name and build, waiting Grace (not Idle) after a ping, realm id length, and the close reasons sent to the realm (§5). Many smaller boundary and default mutants also survive. | Mutation lists in the round-3 report | fixed for the load-bearing mutants (tests for the frame limit, close exemptions, prompt and name sanitising, the hello cap, keepalive grace, realm id length, close reasons); boundary and default mutants remain |

### Suspected, not demonstrated

- Gateway shutdown has no overall deadline: a realm that reads slowly but steadily could stretch `Writer.Close`'s flush of up to 16 MiB (each frame bounded at 10 s).
- In the window between a realm's writer failing and the hub removing the realm, a held player could loop attach, fail, hold, sending a hold message each time.
- Hidden input is not undone when a realm is lost or drains while `input.mode` hidden is on.
- `encoding/json` matches keys case-insensitively and takes the last duplicate (`{"type":"text","TYPE":"hello"}` decodes as hello). Sender rules still apply, so no exploit, but a realm in another language could read the same frame differently.

Round 3 fixes were checked by mutation: 20 of 21 mutants of the fixed code and of the previously surviving load-bearing behaviour are caught. The survivor turns the dropped-input warning into a debug line; after RT-3-2 no transport can produce such input, so the warning is defence in depth only. The red team's own RT-3-1 exploit test now fails at its first step (the impostor's hello is rejected `not-allowed`), and its live RT-3-2 reproduction echoes the long line.
