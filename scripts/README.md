# Gateway scripts

Run from anywhere; each script changes to `src/` itself. Go is the only requirement (the devcontainer installs it). How tests should be written is in [docs/testing.md](../docs/testing.md).

| Script | What it does |
| --- | --- |
| `scripts/test.sh` | `go vet` plus every test, with the race detector when cgo/gcc is available. `-fuzz 30` also fuzzes the telnet parser, sanitiser, GMCP parser and WebSocket frame reader for 30 s each. Other args go to `go test` (e.g. `-run MTTS -v`). |
| `scripts/smoke.sh` | Builds the gateway, starts it on 19000/19010/19020, and drives it like a MUD client over telnet, MCCP2, TLS and both WebSocket subprotocols. Then checks the gateway's log and shuts it down gracefully. Prints PASS/FAIL per check; `-v` shows received text on failure. |
| `scripts/smoke.sh -external` | The same client checks against a gateway you already started on 9000/9010/9020. |
| `scripts/vulncheck.sh` | Checks the code against the Go vulnerability database with a pinned `govulncheck`, which reports only vulnerabilities our code can reach. Exits non-zero if any are found. Downloads the tool on first use, so run it in the devcontainer. |
| `scripts/run.sh` | Builds and runs the gateway in the foreground on 9000 (telnet), 9010 (telnet+TLS) and 9020 (WSS), using a generated dev certificate. Extra args go to the gateway, e.g. `-log-level debug` or `-ws-plain`. |

Manual checks against real clients (with `scripts/run.sh` running; ports are forwarded to the host):

- Mudlet, MUSHclient or TinTin++: connect to `localhost:9000`, or `localhost:9010` with TLS. Type `/info` to see what the client negotiated, and `/secret` to test hidden input.
- Browser: open `https://localhost:9020/`, accept the certificate warning, then use the test page.
