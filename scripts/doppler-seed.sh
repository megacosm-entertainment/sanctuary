#!/usr/bin/env bash
# Fill a Doppler config of both projects (sanctuary-gateway and
# sanctuary-stub-realm) with working defaults: addresses, pins, and the
# realm-link certificates and keys as content.
#
#   scripts/doppler-seed.sh dev    uses the identities in .dev/keys (made on
#                                  first use), so run.sh -split works the
#                                  same with or without Doppler
#   scripts/doppler-seed.sh stg    generates fresh identities, uploads them,
#                                  and deletes the local copies: Doppler is
#                                  the only place they exist
#
# Rerunning replaces the values, which is how to rotate keys. Production is
# refused: its identities should be made and pinned deliberately.
#
# Key content is sent on standard input and the CLI's output is discarded,
# so no key appears in a command line, the process list or a terminal.
source "$(dirname "$0")/lib.sh"

config="${1:?usage: scripts/doppler-seed.sh dev|stg}"
case "$config" in
    dev|stg) ;;
    prd|prod|production) echo "refusing to seed production" >&2; exit 1 ;;
    *) echo "unknown config $config (want dev or stg)" >&2; exit 1 ;;
esac
command -v doppler >/dev/null || { echo "the Doppler CLI is not installed" >&2; exit 1; }

gw_project=sanctuary-gateway
realm_project=sanctuary-stub-realm

build_gateway
build_realm
if [ "$config" = dev ]; then
    keys=.dev/keys
    dev_keys "$keys"
else
    keys="$(mktemp -d "${TMPDIR:-/tmp}/sanctuary-keys.XXXXXX")"
    chmod 700 "$keys"
    trap 'rm -rf "$keys"' EXIT
    ./bin/sanctuary-gateway -gen-identity "$keys/gateway" >/dev/null
    ./bin/sanctuary-realm -gen-identity "$keys/realm-stub" >/dev/null
fi

# set PROJECT NAME=VALUE...: plain settings, none of them secret.
set_plain() {
    local project="$1"; shift
    doppler secrets set --project "$project" --config "$config" --silent "$@" >/dev/null
}
# set_file PROJECT NAME FILE: one value from a file, through stdin.
set_file() {
    doppler secrets set --project "$1" --config "$config" --silent --no-interactive "$2" <"$3" >/dev/null
}

case "$config" in
    dev)
        # Both processes in the devcontainer, on loopback.
        gw_listen=127.0.0.1:9030
        realm_gateway=127.0.0.1:9030
        level=debug
        realm_name="Stub realm"
        publish=()
        ;;
    stg)
        # compose.yaml: the realm port on the compose network only.
        gw_listen=:9030
        realm_gateway=gateway:9030
        level=info
        realm_name="Stub realm (staging)"
        # Host ports for compose, clear of a devcontainer that forwards
        # 9000-9020. Read by scripts/compose.sh, not by the gateway.
        publish=(PUBLISH_TELNET=19000 PUBLISH_TELNETS=19010 PUBLISH_WS=19020)
        ;;
esac

echo "==> $gw_project/$config"
set_plain "$gw_project" \
    SANCTUARY_LOG_LEVEL="$level" \
    SANCTUARY_STUB_REALM=false \
    SANCTUARY_REALM_LISTEN="$gw_listen" \
    SANCTUARY_REALM_PINS="stub=$(cat "$keys/realm-stub.pin")" \
    "${publish[@]+"${publish[@]}"}"
set_file "$gw_project" SANCTUARY_REALM_CERT "$keys/gateway.crt"
set_file "$gw_project" SANCTUARY_REALM_KEY "$keys/gateway.key"

echo "==> $realm_project/$config"
set_plain "$realm_project" \
    SANCTUARY_LOG_LEVEL="$level" \
    SANCTUARY_ID=stub \
    SANCTUARY_NAME="$realm_name" \
    SANCTUARY_GATEWAY="$realm_gateway" \
    SANCTUARY_GATEWAY_PINS="$(cat "$keys/gateway.pin")"
set_file "$realm_project" SANCTUARY_CERT "$keys/realm-stub.crt"
set_file "$realm_project" SANCTUARY_KEY "$keys/realm-stub.key"

echo "==> done; secret names now set:"
for p in "$gw_project" "$realm_project"; do
    echo "  $p/$config: $(doppler secrets --project "$p" --config "$config" --only-names --json | grep -o '"SANCTUARY_[A-Z_]*"' | tr -d '"' | sort | tr '\n' ' ')"
done
