# Sanctuary

Go module `sanctuary` (Go 1.27.4 floor, see `go.mod`): a MUD engine built for roleplay and worldbuilding. Stage 01 is a gateway (telnet, telnet+TLS, WebSocket) normalised into sessions, currently served by an echo handler. The architecture and its reasoning are in the [design document](https://claude.ai/artifact/HR5zEGTd1DLFAvm821NzNV); the build order is its §13. **Start with [docs/status.md](docs/status.md)**: what is done, what is next, and open items.

## Before writing code

Read and follow:

- [docs/coding.md](docs/coding.md): especially **reuse first**. Search the inventory and `internal/` for something to reuse or extend before writing anything new; build new pieces to be reusable; add them to the inventory.
- [docs/testing.md](docs/testing.md): use the shared test clients (`sessiontest`, `telnettest`, `wstest`); every assertion must be able to fail.

## Commands

| | |
| --- | --- |
| `scripts/test.sh` | vet plus all tests, with the race detector |
| `scripts/smoke.sh` | real binary against scripted clients |
| `scripts/run.sh -log-level debug` | run the gateway on 9000/9010/9020, stub realm in-process |
| `scripts/run.sh -split` | the same with the stub realm as a separate process over mTLS |
| `scripts/vulncheck.sh` | known vulnerabilities reachable from our code (govulncheck) |
| `/red-team` | adversarial review on a copy of the module, including known vulnerabilities; findings go in `docs/security/redteam-log.md` |

Build and test in the devcontainer (image: `docker/dev/Dockerfile`). `go.mod` requires a newer Go than the host Mac has, so running `go` there would download a toolchain.

## Non-negotiables

- Standard library first; justify any dependency.
- Client input and client claims are untrusted: sanitise before output, cap buffers, never grant anything on a claim.
- Never log player text or GMCP payloads.
- AI tools help with the engine; world content is written by people.

## The old engine (`../old_game`, `/sanctuary/old_game` in the devcontainer)

Sentience, the ROM-derived engine this project replaces. It is **read-only reference**, and all of it may be read, including player and account files: seeing how real records were structured is part of its value.

- **Read anything; modify nothing.** New work goes in `src/`. Content carried forward is rewritten or ported by people, not copied in bulk.
- **Personal data stays where it is.** Player records (`accounts/`, `acct.tar.gz`, the `characters*` directories, `player_bad/`, `backup/`, loose character files such as `Nibelung` and `Xevira`), logs and crash dumps hold real people's data: names, email addresses, IP addresses, password hashes. Use them to learn formats and structure, but:
  - never copy a real record into `src/`, its tests, fixtures or docs. Write a synthetic example with the same structure instead;
  - when describing a format, use field names and invented values, not real ones;
  - never reproduce email addresses, IP addresses or password hashes in replies, logs, commits or reports.
- **`imc/` may hold intermud credentials.** Reading is fine; never reproduce a credential.
