# Testing guidelines

These apply to every test in the engine, whoever or whatever writes it. They exist so that a test can be read by someone who did not write it, fails only when behaviour breaks, and says why when it does.

## 1. Use the shared scaffolding; extend it, don't hand-roll

This is the testing form of the project-wide rule in [coding.md §1](coding.md#1-reuse-first-then-extend-then-build): reuse first, then extend, then build something reusable.

Each wire protocol and each layer has one test client or harness. Use it. If it can't do what you need, add the capability there so the next test gets it too.

| Need | Use | Location |
| --- | --- | --- |
| Drive a session handler with no sockets (`Options.Meta` for an unencrypted connection or a source address) | `sessiontest.Harness` | `internal/session/sessiontest` |
| Act as a telnet MUD client (negotiation, MTTS, MNES, MCCP2) | `telnettest.Client` with a `Profile` | `internal/telnet/telnettest` |
| Act as a WebSocket client (handshake, masked frames, close codes) | `wstest.Client` | `internal/websocket/wstest` |
| Print telnet bytes readably in a failure message | `telnet.Describe` | `internal/telnet/describe.go` |
| Play the gateway or a realm on a realm link | `realmprototest.Peer` (`NewGateway`, `NewRealm`, `Start` for a real mTLS link, `Expect`, `Until`, `TextFor`) | `internal/realmproto/realmprototest` |
| Run a whole gateway on loopback ports | `startGateway(t, mods...)` | `internal/gateway/gateway_test.go` |

The telnet package's own unit tests can't import `telnettest` (it imports `telnet`), so they use the in-package fixture at the top of `conn_test.go`. Keep that fixture and `telnettest` consistent.

When a new protocol or layer arrives (the stage 02 internal protocol, for example), its test client arrives with it, in a `<package>test` subpackage, before the second test that needs it is written.

## 2. One behaviour per test, named for the behaviour

- A test or subtest checks one behaviour, and its name says which: `TestMNESUndefinedVariables/not_recorded`, not `TestMNES2`.
- Use a table with `t.Run` when the same behaviour is checked over several inputs.
- A genuinely sequential scenario (MCCP2 on, then off) may stay one test, but each failure message says which step failed.

## 3. Say why the case exists

Every test or table case that encodes a rule says where the rule comes from: an RFC section, a named client and version ("Mudlet 5.1 sends…"), the design doc, or the bug it guards against. Every magic number is a named constant or carries a comment that decodes it (`2349 // SSL 2048 + truecolor 256 + …`).

## 4. Failure messages show got and want

- Format: `Func(input) = got, want want`. A failure must be diagnosable without rerunning.
- Print protocol bytes symbolically (`telnet.Describe`, `%q`), never as bare `[255 253 24]`.
- When parsing structured output such as `info`, compare fields, not exact column alignment, unless the layout is itself the contract.

## 5. Every assertion must be able to fail

- Before you finish a test, break the behaviour it covers (comment out the line, flip the condition) and watch it go red. If it stays green, the test is wrong.
- Choose inputs that only the behaviour under test can reject. A test that an oversize message is discarded proves nothing if a later check (a GMCP size limit, a parser) would reject the truncated message anyway.
- Make sure the test reaches the code it targets. A path that only runs when output is pending, or under a race, needs the test to set up that state directly.
- A negative assertion ("the server did not reply") is only meaningful after a positive sync point that proves the reply would have arrived by now. For a stream, send something that gets an answer and wait for that answer; for the in-memory fixtures, check after the call returns.
- Assert on content, not just type: a GMCP event is checked for its package *and* its payload.

## 6. No errors dropped, no panics instead of failures

- Never `_ =` or ignore an error in test code. Helpers either return the error or take `t`, call `t.Helper()` first, and fail.
- Use the comma-ok form for type assertions and fail with what was actually received; never let a test panic on `evs[0].(session.Line)`.

## 7. Concurrency

- Never call `t.Fatal`, `t.Error` or `t.FailNow` from a goroutine other than the test's. Background goroutines send results over a channel; the test goroutine asserts.
- Over `net.Pipe`, writes block until the other side reads: run the server side in a goroutine and drive the client from the test goroutine, in order.
- No `time.Sleep` to order events. Wait on a condition, bounded by the package's one timeout constant. A sleep that only polls a condition with a deadline is acceptable when there is nothing to block on.
- Run with `-race`. `scripts/test.sh` does this whenever cgo is available.

## 8. Synchronise on protocol facts, not on time

Real clients answer negotiation asynchronously, so "the first prompt arrived" doesn't mean "the server knows who the client is". Use the explicit sync points:

- `telnettest.Client.WaitIdentified` before asserting on client identity.
- `Round` (send a line, wait for its prompt) before asserting that something did *not* happen.
- `Settle` (a timed quiet period) is for setup only, never for assertions, and never while MCCP2 is active: Go's zlib reader keeps a timeout error permanently.

## 9. Black-box by default

Tests live in a `_test` package and use exported API unless they need to control internals for setup, as the telnet parser tests do by feeding `process` directly. Even then, assert on what the code emits (bytes written, events produced), not on private fields.

## 10. Clean up everything

Connections, goroutines and gateways are released with `t.Cleanup` or `defer`. A test must not leave a listener, session or goroutine running after it returns.

## 11. Fuzz the parsers

Anything that parses untrusted input has a fuzz target with seeds drawn from real traffic: currently the telnet parser (`FuzzProcess`), the sanitiser (`FuzzUntrusted`), the GMCP parser (`FuzzParse`), the WebSocket frame reader (`FuzzReadMessage`) and the realm protocol decoder (`FuzzDecode`). Run `scripts/test.sh -fuzz 30` before merging parser changes. A fuzz target asserts properties (no panic, bounded output, idempotence), with each bound explained in a comment.

## 12. Red-team significant changes

After a significant change, after a Go or dependency upgrade, and before going public, run the `red-team` skill (`/red-team`). It works on a copy of the module, mutates the code to find tests that don't notice, abuses the protocols, exploits known vulnerabilities in the toolchain and dependencies, and re-attacks every past finding. Its findings are leads: verify each one before acting on it, and turn each confirmed break into a test that fails first.

Record every confirmed finding in [security/redteam-log.md](security/redteam-log.md), with the test that reproduces it. The log is how later runs know what to re-attack.

## Running

| Command | What |
| --- | --- |
| `scripts/test.sh` | vet plus all tests, race detector when available |
| `scripts/test.sh -count 20 -run TestQMethod` | repeat a test to shake out flakes |
| `scripts/test.sh -fuzz 30` | plus 30 s of fuzzing per target |
| `scripts/smoke.sh` | the real binary against the scripted clients |
