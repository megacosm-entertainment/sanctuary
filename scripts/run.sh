#!/usr/bin/env bash
# Build and run the gateway in the foreground on 9000 (telnet), 9010
# (telnet+TLS) and 9020 (WSS), with a generated dev certificate. Extra
# arguments go to the gateway, e.g. scripts/run.sh -ws-plain -log-level debug
# Ctrl-C shuts it down gracefully.
#
#   scripts/run.sh          the stub realm runs inside the gateway process
#   scripts/run.sh -split   the stub realm runs as its own process and dials
#                           the gateway's realm port (127.0.0.1:9030) over
#                           mTLS, as in production. Identities live in
#                           .dev/keys and are created on first use.
source "$(dirname "$0")/lib.sh"

split=0
args=()
for a in "$@"; do
    case "$a" in
        -split) split=1 ;;
        *) args+=("$a") ;;
    esac
done

build_gateway
if [ "$split" = 0 ]; then
    exec ./bin/sanctuary-gateway "${args[@]+"${args[@]}"}"
fi

build_realm
keys=.dev/keys
dev_keys "$keys"
./bin/sanctuary-gateway -stub-realm=false \
    -realm-listen 127.0.0.1:9030 \
    -realm-cert "$keys/gateway.crt" -realm-key "$keys/gateway.key" \
    -realm-pins "$keys/realm-stub.pin" \
    "${args[@]+"${args[@]}"}" &
gw=$!
./bin/sanctuary-realm -gateway 127.0.0.1:9030 \
    -cert "$keys/realm-stub.crt" -key "$keys/realm-stub.key" \
    -gateway-pins "$keys/gateway.pin" &
realm=$!
trap 'kill -TERM "$gw" 2>/dev/null; wait "$gw" 2>/dev/null; kill -TERM "$realm" 2>/dev/null; wait "$realm" 2>/dev/null' EXIT INT TERM
# Ctrl-C stops both; either exiting on its own stops the other.
wait -n "$gw" "$realm" || true
