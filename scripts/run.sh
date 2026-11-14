#!/usr/bin/env bash
# Build and run the gateway in the foreground on 9000 (telnet), 9010
# (telnet+TLS) and 9020 (WSS), with a generated dev certificate. Extra
# arguments go to the gateway, e.g. scripts/run.sh -ws-plain -log-level debug
# Ctrl-C shuts it down gracefully. -log-level also applies to the realm in
# -split mode.
#
#   scripts/run.sh          the stub realm runs inside the gateway process
#   scripts/run.sh -split   the stub realm runs as its own process and dials
#                           the gateway's realm port (127.0.0.1:9030) over
#                           mTLS, as in production. Identities live in
#                           .dev/keys and are created on first use.
source "$(dirname "$0")/lib.sh"

split=0
args=()
realm_args=()
while [ $# -gt 0 ]; do
    case "$1" in
        -split) split=1; shift ;;
        # Logging applies to both processes; everything else is a gateway flag.
        -log-level) args+=("$1" "${2:?level}"); realm_args+=("$1" "$2"); shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done

build_gateway
if [ "$split" = 0 ]; then
    exec ./bin/sanctuary-gateway "${args[@]+"${args[@]}"}"
fi

build_realm
# REALM_ADDR moves the realm port, e.g. to run a second copy alongside.
realm_addr="${REALM_ADDR:-127.0.0.1:9030}"
keys=.dev/keys
dev_keys "$keys"
./bin/sanctuary-gateway -stub-realm=false \
    -realm-listen "$realm_addr" \
    -realm-cert "$keys/gateway.crt" -realm-key "$keys/gateway.key" \
    -realm-pins "$keys/realm-stub.pin" \
    "${args[@]+"${args[@]}"}" &
gw=$!
./bin/sanctuary-realm -gateway "$realm_addr" \
    -cert "$keys/realm-stub.crt" -key "$keys/realm-stub.key" \
    -gateway-pins "$keys/gateway.pin" \
    "${realm_args[@]+"${realm_args[@]}"}" &
realm=$!
stop_all() {
    # Each step may fail (the process may already be gone); set -e must not
    # cut the cleanup short and leave the other process running.
    kill -TERM "$gw" 2>/dev/null || true
    wait "$gw" 2>/dev/null || true
    kill -TERM "$realm" 2>/dev/null || true
    wait "$realm" 2>/dev/null || true
}
trap stop_all EXIT INT TERM
# Ctrl-C stops both; either exiting on its own stops the other, and the
# script exits with that process's status.
status=0
wait -n "$gw" "$realm" || status=$?
exit "$status"
