#!/usr/bin/env bash
# End-to-end smoke test: starts a gateway on spare ports, drives it like a
# MUD client over telnet, telnet+TLS and both WebSocket subprotocols, checks
# its log, and stops it.
#
#   scripts/smoke.sh               self-contained run on ports 19000-19020
#   scripts/smoke.sh -external     test a gateway you already started
#                                  (scripts/run.sh) on 9000/9010/9020
#   scripts/smoke.sh -v            print received text when a check fails
source "$(dirname "$0")/lib.sh"

external=0
pass=()
for a in "$@"; do
    case "$a" in
        -external) external=1 ;;
        *) pass+=("$a") ;;
    esac
done

if [ "$external" = 1 ]; then
    echo "==> testing the gateway already running on localhost:9000/9010/9020"
    exec go run ./cmd/gateway-smoke -host localhost -telnet 9000 -telnets 9010 -ws 9020 "${pass[@]+"${pass[@]}"}"
fi

build_gateway
log="$(mktemp "${TMPDIR:-/tmp}/gateway-smoke.XXXXXX")"
./bin/sentience-gateway -log-level debug \
    -telnet 127.0.0.1:19000 -telnets 127.0.0.1:19010 -ws 127.0.0.1:19020 \
    >"$log" 2>&1 &
gw=$!
trap 'kill "$gw" 2>/dev/null || true; wait "$gw" 2>/dev/null || true' EXIT

# Wait for all three listeners.
for _ in $(seq 50); do
    [ "$(grep -c '"msg":"listening"' "$log" || true)" -ge 3 ] && break
    if ! kill -0 "$gw" 2>/dev/null; then echo "gateway exited:"; cat "$log"; exit 1; fi
    sleep 0.1
done

echo "==> running client checks (gateway log: $log)"
status=0
go run ./cmd/gateway-smoke -host 127.0.0.1 -telnet 19000 -telnets 19010 -ws 19020 "${pass[@]+"${pass[@]}"}" || status=$?

echo "==> checking gateway log"
logcheck() {
    if grep -q "$2" "$log"; then echo "PASS  log: $1"; else echo "FAIL  log: $1"; status=1; fi
}
logcheck "client identified via TTYPE/MTTS"         '"msg":"client identified".*"screen_reader":true'
logcheck "valid GMCP received and logged"            '"msg":"GMCP received".*"package":"Core.Hello"'
logcheck "malformed GMCP rejected"                   '"msg":"rejected malformed GMCP"'
logcheck "cross-origin WebSocket refused"            'cross-origin request: https://evil.example'
if grep -q '"level":"ERROR"' "$log"; then echo "FAIL  log: errors logged"; grep '"level":"ERROR"' "$log"; status=1; else echo "PASS  log: no errors"; fi

echo "==> stopping gateway (graceful shutdown)"
kill -TERM "$gw"
wait "$gw" || true
trap - EXIT
logcheck "graceful shutdown logged" '"msg":"shutting down"'

if [ "$status" -ne 0 ]; then echo "smoke test FAILED (log kept at $log)"; exit "$status"; fi
rm -f "$log"
echo "==> smoke test passed"
