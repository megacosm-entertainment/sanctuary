---
name: red-team
description: Adversarial review of Sanctuary's tests and code. Tries to break things - mutates the code to find tests that don't notice, abuses the telnet/WebSocket/GMCP protocols against a running gateway, exploits known vulnerabilities (CVEs, Go security advisories, documented attack classes) in the toolchain, standard library and any dependencies, re-attacks every past finding, and hunts for flaky, vacuous or racy tests and privacy leaks. Use after a significant change, before merging protocol or parser work, after a Go or dependency upgrade, or when asked to red team, attack, stress, exploit or break the tests or code. Works on a copy of the module and never edits the working tree.
---

# Red team

You are the adversary. Your job is to **break things**: find the tests that would stay green while the code is broken, and find the inputs that make the code misbehave. Assume every test is wrong until you have watched it fail. A run that finds nothing is acceptable only if the report shows what you tried.

## Run it independently

Do the attack in a **fresh subagent** that is given the target paths and this file, and **not** the author's reasoning, summaries or conclusions about the change. An attacker who has been told why the code is correct tends to agree. Brief it with the scope and the rules below; it reports back; you relay.

## Scope

The argument names what to attack: package paths (`internal/telnet`), files, or a description of a change. With no argument, attack the whole module in `src/`. Read `docs/testing.md` first: findings are judged against it. Read `docs/security/redteam-log.md` too: every past finding is re-attacked (class F).

## Rules

1. **Never modify the working tree.** Copy the module first, and do everything in the copy:
   ```bash
   RT=$(mktemp -d) && cp -R . "$RT/src" && cd "$RT/src"
   ```
   Do not commit, push, install software (except as rule 2 allows), or touch anything outside the copy and the system temp dir.
2. **Attacks stay on loopback.** Run gateways on `127.0.0.1` with spare ports (e.g. 29000-29099) and send every exploit there, never anywhere else. The one outbound exception is **read-only research** for class F: public vulnerability databases and advisories (the Go vulnerability database, OSV, the NVD, Go release notes, client projects' security advisories). Queries name only public things (Go version, module paths and versions, client names); never send project code, logs or anything from this machine.
   - **Installing tools:** never on the host machine. Inside the devcontainer, pinned Go tools run with `go run module@vX.Y.Z` (for example `golang.org/x/vuln/cmd/govulncheck`) are acceptable. If neither applies, work from the databases by hand and say so in the report.
3. **Reproduce before reporting.** A finding is *confirmed* only with an exact command or test that demonstrates it. Anything else goes under *suspected*, with what would confirm it.
4. **Don't fix production code.** You may write failing tests in the copy to demonstrate a break, and include them in the report so they can be adopted.
5. **Time-box.** Spend roughly equal effort on each attack class below, and stop at about 30 minutes of work unless asked for more. Class F's regression re-runs come first: they are cheap and catch the most embarrassing failures.
6. `GOFLAGS=-buildvcs=false` avoids VCS-stamping errors in the copy.

## Attack classes

### A. Mutation testing (first, right after re-running past findings in F.5)

For each function in scope, apply one mutation at a time in the copy, run that package's tests (`go test ./internal/<pkg>/`), record whether any test failed, then restore the file. Mutations worth trying here:

- flip a comparison or boolean (`==` to `!=`, `<` to `<=`, `!ok` to `ok`)
- delete a statement: a `sanitize.Untrusted` call, a `c.dirty = true`, a `flush`, a size-limit check, an IAC-doubling branch
- return early or return the zero value
- swap constants: EOR for GA, WILL for DO, a close code, a limit (`MaxLine`, `MaxSubneg`, `MaxMessage`)
- in `qmethod.go`, change one state transition or drop one `send`
- in precedence logic (MNES / TTYPE / Core.Hello), swap which source wins

A mutant that **survives** (all tests still pass) is a finding: name the mutation, the file:line, and the behaviour no test covers. Script the loop rather than hand-editing, and restore each file from the pristine copy between mutants.

### B. Test-quality audit

Look for, and reproduce where possible:

- assertions that cannot fail, or that check type but not content
- ignored errors, `_ =` in tests, type assertions that would panic
- `t.Fatal`/`t.Error` called from a non-test goroutine
- negative assertions ("nothing was sent") with no sync point before them
- `time.Sleep` used for ordering
- leaked connections, goroutines or gateways
- flakiness: `go test -race -count=50 -shuffle=on ./...`, and again with `GOMAXPROCS=1`

### C. Protocol abuse against a live gateway

Build and run the gateway from the copy on loopback (`go run ./cmd/sanctuary-gateway -telnet 127.0.0.1:29000 -telnets 127.0.0.1:29010 -ws 127.0.0.1:29020 -log-level debug`), and write small Go programs in the copy (using `telnettest` and `wstest` where they help) to attack it. Watch for panics, hangs, unbounded memory or goroutines, a session that never closes, or another session being affected. Ideas:

- **Telnet:** negotiation storms; a subnegotiation that never ends; IAC split across reads; endless distinct TTYPE replies; MNES variable floods and huge values; NAWS of 0x0 and 65535x65535; MCCP2 toggled rapidly; DO ECHO / WILL ECHO races with `/secret`.
- **GMCP:** maximum-size payloads, deeply nested JSON, invalid UTF-8, package names at the length limit, `Core.Hello` with hostile values.
- **WebSocket:** fragments that never finish; ping floods; frames that claim large lengths; control frames over 125 bytes; Origin variants (case, trailing dot, default port, `null`); subprotocol case and whitespace tricks; text frames on the telnet subprotocol.
- **Resources:** a client that connects and never reads (does the queue policy disconnect it?); many connections from one host versus `-max-per-host`; a TLS client that stalls mid-handshake; slowloris on the WebSocket HTTP upgrade.

### D. Security and privacy

- **Logs:** send a unique canary string as input, in GMCP payloads and in MNES values, then grep the gateway log. Player text and GMCP payloads must never appear (design doc §02). Client identity strings are allowed at debug level.
- **Output:** try to get escape sequences, OSC 8 links, bidi overrides or raw IAC bytes back out through echo or `/info`.
- **Trust:** check that client claims (TTYPE, MNES, `Core.Hello`, IPADDRESS) never change anything but presentation.

### E. Fuzzing

Run the existing fuzz targets longer than CI does (`go test -run=NONE -fuzz=FuzzProcess -fuzztime=2m ./internal/telnet/`), and write new fuzz targets in the copy for any parser that lacks one (WebSocket frame reader, GMCP `Parse`, MNES parsing). Report any crasher, with its corpus entry.

### F. Known vulnerabilities and past findings

The adversary uses what is publicly known, not only what it can invent.

1. **Inventory the attack surface.**
   - Toolchain: `go version`, and the `go` / `toolchain` lines in `go.mod`.
   - Third-party modules: `go list -m all` (none today; every one added is attack surface).
   - Standard-library packages the gateway reaches: `go list -deps ./cmd/sanctuary-gateway`, especially `net/http`, `crypto/tls`, `crypto/x509`, `compress/*`, `encoding/json`, `net/url`.
   - Anything the gateway serves to or passes through to clients: the web test client's scripts, and the MUD clients that render our output (Mudlet, MUSHclient, TinTin++).
2. **Find what is known.**
   - Run `scripts/vulncheck.sh` in the devcontainer copy (see rule 2). It runs a pinned govulncheck, built with the module's own toolchain, and reports whether a vulnerable symbol is actually reachable from our code; prefer that to version matching. If a newer govulncheck release exists than the script pins, say so in the report.
   - Otherwise, look up the Go version and each module in the Go vulnerability database (vuln.go.dev, pkg.go.dev/vuln) and OSV, and read the Go release notes for every security release after our toolchain version.
   - Report a toolchain that predates published security fixes even when nothing is shown to be exploitable: it is the cheapest finding to fix.
   - **Before recommending a target version, check the current release list** (`https://go.dev/dl/?mode=json`, or `go list -m -versions` for modules). Recommend the newest patch of a *supported* release: Go supports only its two newest major versions. A fix that moves to another end-of-life version is not a fix (round 2 made exactly this mistake).
3. **Exploit what is reachable.** For each known vulnerability whose vulnerable code the gateway can reach, write a proof of concept in the copy and run it against the loopback gateway. It is **confirmed** only if the proof of concept works against our build. Reachable but not demonstrated goes under *suspected*, with the reasoning; not reachable goes under *what held*, with the reason.
4. **Documented attack classes.** Attempt the well-known attacks that apply to this kind of server even without a CVE number:
   - **HTTP and WebSocket:** cross-site WebSocket hijacking (origin bypasses), request smuggling or desync on the upgrade path, header and method confusion, slowloris and slow-read.
   - **TLS:** protocol and cipher downgrade (check the minimum version and suites actually negotiated), renegotiation, handshake stalls.
   - **Compression:** a CRIME/BREACH-style oracle, where MCCP2 inside TLS compresses attacker-influenced text alongside something secret in the same stream; decompression bombs if the gateway ever decompresses client data.
   - **Parsers:** deeply nested or huge JSON, overlong or invalid UTF-8, Unicode tricks (bidi, homoglyphs, normalisation), integer edge cases in lengths.
   - **Client exploitation through the gateway:** published crash or injection bugs in Mudlet, MUSHclient, TinTin++ and browsers (ANSI/OSC/MXP sequences, malformed telnet). Check that one player's input cannot deliver those payloads to another player's client.
5. **Re-attack past findings.** Every entry in `docs/security/redteam-log.md` has a reproduction. Run each one again; a finding that reproduces is a **regression** and is reported as critical whatever its original severity.

## Report

Return a report in this shape:

1. **Confirmed breaks**, most severe first. Each one: severity (critical / high / medium / low), class (A-F), file:line, what broke, the exact reproduction (command or test code), why it matters, and a suggested fix.
   - For a known vulnerability, also: its identifier (CVE, GO-YYYY-NNNN), the affected component and version, how our code reaches it, and the fixed version to move to.
2. **Surviving mutants**: mutation, file:line, and the behaviour that is untested.
3. **Suspected issues**: what you saw, and what would confirm it.
4. **What held**: the attacks you ran that found nothing, so the coverage of this run is visible. Include each past finding re-attacked and each known vulnerability ruled out, with the reason.
5. **Log entries**: one row per confirmed finding, in the format of `docs/security/redteam-log.md`, ready to append.

Keep it factual. The reader will verify each finding before acting on it.
