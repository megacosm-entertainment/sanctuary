#!/usr/bin/env bash
# End-to-end smoke test: starts a gateway and a separate stub realm on spare
# ports (the realm dials the gateway's realm port over mTLS, as in
# production), drives the gateway like a MUD client over telnet,
# telnet+TLS and both WebSocket subprotocols, checks both logs, and stops
# them.
#
#   scripts/smoke.sh               self-contained run on ports 19000-19030
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
build_realm
work="$(mktemp -d "${TMPDIR:-/tmp}/gateway-smoke.XXXXXX")"
log="$work/gateway.log"
rlog="$work/realm.log"
# Fresh identities every run: nothing persists between smoke tests.
dev_keys "$work/keys"

./bin/sanctuary-gateway -log-level debug -stub-realm=false \
    -telnet 127.0.0.1:19000 -telnets 127.0.0.1:19010 -ws 127.0.0.1:19020 \
    -realm-listen 127.0.0.1:19030 \
    -realm-cert "$work/keys/gateway.crt" -realm-key "$work/keys/gateway.key" \
    -realm-pins "$work/keys/realm-stub.pin" \
    >"$log" 2>&1 &
gw=$!
realm=
cleanup() {
    kill "$gw" 2>/dev/null || true
    [ -n "$realm" ] && kill "$realm" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# Wait for all four listeners (three player ports and the realm port).
for _ in $(seq 50); do
    [ "$(grep -c '"msg":"listening"' "$log" || true)" -ge 4 ] && break
    if ! kill -0 "$gw" 2>/dev/null; then echo "gateway exited:"; cat "$log"; exit 1; fi
    sleep 0.1
done

# The realm is configured the way a secrets manager would do it: settings
# in an env file, and its private key as environment content (as `doppler
# run` injects it), not as a file path.
cat >"$work/realm.env" <<ENV
SANCTUARY_GATEWAY=127.0.0.1:19030
SANCTUARY_GATEWAY_PINS=$work/keys/gateway.pin
SANCTUARY_CERT_FILE=$work/keys/realm-stub.crt
SANCTUARY_LOG_LEVEL=debug
ENV
start_realm() { # log file
    SANCTUARY_KEY="$(cat "$work/keys/realm-stub.key")" \
        ./bin/sanctuary-realm -config "$work/realm.env" >>"$1" 2>&1 &
    realm=$!
}
start_realm "$rlog"
for _ in $(seq 50); do
    grep -q '"msg":"realm registered"' "$log" && break
    if ! kill -0 "$realm" 2>/dev/null; then echo "realm exited:"; cat "$rlog"; exit 1; fi
    sleep 0.1
done

echo "==> running client checks (logs in $work)"
status=0
go run ./cmd/gateway-smoke -host 127.0.0.1 -telnet 19000 -telnets 19010 -ws 19020 "${pass[@]+"${pass[@]}"}" || status=$?

echo "==> checking logs"
logcheck() { # description pattern [file]
    if grep -q "$2" "${3:-$log}"; then echo "PASS  log: $1"; else echo "FAIL  log: $1"; status=1; fi
}
noerrors() { # name file
    if grep -q '"level":"ERROR"' "$2"; then echo "FAIL  log: $1 logged errors"; grep '"level":"ERROR"' "$2"; status=1; else echo "PASS  log: no errors from $1"; fi
}
logcheck "client identified via TTYPE/MTTS"            '"msg":"client identified".*"screen_reader":true'
logcheck "valid GMCP received and logged"               '"msg":"GMCP received".*"package":"Core.Hello"'
logcheck "malformed GMCP rejected"                      '"msg":"rejected malformed GMCP"'
logcheck "cross-origin WebSocket refused"               'cross-origin request: https://evil.example'
logcheck "realm port listening, mTLS only"              '"transport":"realm (mTLS)"'
logcheck "stub realm registered over mTLS"              '"msg":"realm registered".*"realm":"stub"'
logcheck "players routed to the realm"                  '"msg":"routed to realm".*"realm":"stub"'
logcheck "realm process registered with the gateway"    '"msg":"registered with gateway"' "$rlog"
logcheck "realm served the players"                     '"msg":"session opened".*"remote":"gateway"' "$rlog"
logcheck "realm read its settings from the env file"     '"msg":"setting","name":"GATEWAY","value":"127.0.0.1:19030","from":"file"' "$rlog"
logcheck "realm key came from the environment"         '"msg":"setting","name":"KEY","value":"\[secret\]","from":"env"' "$rlog"
if grep -q "PRIVATE KEY" "$rlog"; then echo "FAIL  log: realm logged its private key"; status=1; else echo "PASS  log: private key never logged"; fi
noerrors gateway "$log"

echo "==> restarting the realm with a player connected (drain, hold, re-attach)"
# A raw TCP player: it never answers telnet negotiation, so nothing is
# compressed and its received text can be searched as is.
held="$work/held.txt"
exec 3<>/dev/tcp/127.0.0.1/19000
cat <&3 >"$held" &
reader=$!
waitfor() { # file pattern
    for _ in $(seq 50); do grep -q "$2" "$1" && return 0; sleep 0.1; done
    return 1
}
waitfor "$held" "stub realm" || { echo "FAIL  player never reached the realm"; status=1; }
kill -TERM "$realm"
wait "$realm" || true
realm=
logcheck "realm drained on SIGTERM"                     '"msg":"drained"' "$rlog"
logcheck "gateway saw the drain"                        '"msg":"realm drained"'
if waitfor "$held" "unavailable for the moment"; then echo "PASS  player held while the realm was down"; else echo "FAIL  player held while the realm was down"; status=1; fi
rlog2="$work/realm2.log"
start_realm "$rlog2"
if waitfor "$held" "Reconnected"; then echo "PASS  held player re-attached to the restarted realm"; else echo "FAIL  held player re-attached to the restarted realm"; status=1; fi
exec 3>&-
kill "$reader" 2>/dev/null || true
wait "$reader" 2>/dev/null || true
rlog="$rlog2"

echo "==> stopping the gateway (graceful shutdown)"
kill -TERM "$gw"
wait "$gw" || true
logcheck "graceful shutdown logged"                     '"msg":"shutting down"'
for _ in $(seq 30); do
    grep -q '"msg":"gateway is shutting down"' "$rlog" && break
    sleep 0.1
done
logcheck "realm told about the shutdown"                '"msg":"gateway is shutting down"' "$rlog"
logcheck "realm will reconnect rather than exit"        '"msg":"gateway closed the link; reconnecting"' "$rlog"

echo "==> stopping the realm"
kill -TERM "$realm"
wait "$realm" || true
realm=
logcheck "realm stopped cleanly"                        '"msg":"realm stopped"' "$rlog"
noerrors realm "$rlog"
trap - EXIT

if [ "$status" -ne 0 ]; then echo "smoke test FAILED (logs kept in $work)"; exit "$status"; fi
rm -rf "$work"
echo "==> smoke test passed"
