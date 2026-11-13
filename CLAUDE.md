# Sentience Engine

Go 1.23 module `sentience`: a MUD engine. Stage 01 is a gateway (telnet, telnet+TLS, WebSocket) normalised into sessions, currently served by an echo handler. The architecture and its reasoning are in the design document; the build order is its §13.

## Before writing code

Read and follow:

- [docs/coding.md](docs/coding.md): especially **reuse first**. Search the inventory and `internal/` for something to reuse or extend before writing anything new; build new pieces to be reusable; add them to the inventory.
- [docs/testing.md](docs/testing.md): use the shared test clients (`sessiontest`, `telnettest`, `wstest`); every assertion must be able to fail.

## Commands

| | |
| --- | --- |
| `scripts/test.sh` | vet plus all tests, with the race detector |
| `scripts/smoke.sh` | real binary against scripted clients |
| `scripts/run.sh -log-level debug` | run the gateway on 9000/9010/9020 |
| `/red-team` | adversarial review on a copy of the module |

`GOFLAGS=-buildvcs=false` avoids version-stamping errors when the folder isn't a git checkout.

## Non-negotiables

- Standard library first; justify any dependency.
- Client input and client claims are untrusted: sanitise before output, cap buffers, never grant anything on a claim.
- Never log player text or GMCP payloads.
- AI tools help with the engine; world content is written by people.
