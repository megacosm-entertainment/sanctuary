# Gateway scripts

Run from anywhere; each script changes to `src/` itself. Go is the only requirement (the devcontainer installs it). How tests should be written is in [docs/testing.md](../docs/testing.md).

| Script | What it does |
| --- | --- |
| `scripts/test.sh` | `go vet` plus every test, with the race detector when cgo/gcc is available. `-fuzz 30` also fuzzes every parser of untrusted input (telnet, sanitiser, GMCP, WebSocket frames, realm protocol) for 30 s each. Other args go to `go test` (e.g. `-run MTTS -v`). |
| `scripts/smoke.sh` | Builds the gateway and the realm, starts the gateway on 19000/19010/19020 with its realm port on 19030, starts a separate stub realm that dials in over mTLS (fresh identities each run), and drives the gateway like a MUD client over telnet, MCCP2, TLS and both WebSocket subprotocols. Then checks both logs and shuts both down gracefully. Prints PASS/FAIL per check; `-v` shows received text on failure. |
| `scripts/smoke.sh -external` | The same client checks against a gateway you already started on 9000/9010/9020. |
| `scripts/devkeys.sh` | Creates the development realm-link identities in `.dev/keys` (git-ignored, never overwritten), for `run.sh -split` and `compose.yaml`. |
| `scripts/vulncheck.sh` | Checks the code against the Go vulnerability database with a pinned `govulncheck`, which reports only vulnerabilities our code can reach. Exits non-zero if any are found. Downloads the tool on first use, so run it in the devcontainer. |
| `scripts/run.sh` | Builds and runs the gateway in the foreground on 9000 (telnet), 9010 (telnet+TLS) and 9020 (WSS), using a generated dev certificate. Extra args go to the gateway, e.g. `-log-level debug` or `-ws-plain`. |
| `scripts/run.sh -split` | As above, but the stub realm runs as its own process and dials the gateway's realm port (`127.0.0.1:9030`) over mTLS, as in production. Identities are created on first use in `.dev/keys` (git-ignored). `-log-level` applies to both processes; `REALM_ADDR=host:port` moves the realm port. Ctrl-C stops both, and if either exits the other is stopped too. |

Manual checks against real clients (with `scripts/run.sh` running; ports are forwarded to the host):

- Mudlet, MUSHclient or TinTin++: connect to `localhost:9000`, or `localhost:9010` with TLS. Type `/info` to see what the client negotiated, and `/secret` to test hidden input.
- Browser: open `https://localhost:9020/`, accept the certificate warning, then use the test page.
