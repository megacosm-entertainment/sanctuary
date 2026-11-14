# Shared helpers for the gateway scripts. Sourced, not run.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SRC_DIR"

# need_go: scripts that build or test call this. Scripts that only run
# containers (compose.sh -doppler) do not need Go on the host: the runtime
# image builds the binaries itself.
need_go() {
    if ! command -v go >/dev/null 2>&1; then
        echo "error: Go is not installed in this environment." >&2
        echo "Build and test in the devcontainer (image: docker/dev/Dockerfile), which provides it." >&2
        exit 1
    fi
}

# The bind mount can make git refuse to stamp version info; it isn't needed.
export GOFLAGS="${GOFLAGS:-} -buildvcs=false"

build_gateway() {
    need_go
    echo "==> building bin/sanctuary-gateway"
    go build -o bin/sanctuary-gateway ./cmd/sanctuary-gateway
}

build_realm() {
    need_go
    echo "==> building bin/sanctuary-realm"
    go build -o bin/sanctuary-realm ./cmd/sanctuary-realm
}

# dev_keys DIR: realm-link identities for local runs, created once. The
# files are git-ignored (*.key, *.crt) and never leave the machine; a real
# deployment makes its own with -gen-identity or uses a CA.
dev_keys() {
    local dir="$1"
    mkdir -p "$dir"
    chmod 700 "$dir"
    [ -e "$dir/gateway.key" ] || ./bin/sanctuary-gateway -gen-identity "$dir/gateway" >/dev/null
    [ -e "$dir/realm-stub.key" ] || ./bin/sanctuary-realm -gen-identity "$dir/realm-stub" >/dev/null
}

# -race needs cgo and a C compiler; the devcontainer has gcc.
race_flag() {
    if [ "$(go env CGO_ENABLED)" = "1" ] && command -v "$(go env CC)" >/dev/null 2>&1; then
        echo "-race"
    fi
}

# dev_env KEYS DIR: write DIR/gateway.env and DIR/realm-stub.env, the
# per-environment half of compose.yaml's settings, from the identities in
# KEYS. They hold private keys, so the directory and files are owner-only.
dev_env() {
    local keys="$1" dir="$2"
    mkdir -p "$dir"
    chmod 700 "$dir"
    # pem FILE: the file as one double-quoted env value, newlines as \n.
    pem() { printf '"%s"' "$(awk '{printf "%s\\n", $0}' "$1")"; }
    (
        umask 077
        {
            echo "# Written by scripts/devkeys.sh from $keys. Private: never commit."
            echo "SANCTUARY_REALM_CERT=$(pem "$keys/gateway.crt")"
            echo "SANCTUARY_REALM_KEY=$(pem "$keys/gateway.key")"
            echo "SANCTUARY_REALM_PINS=stub=$(cat "$keys/realm-stub.pin")"
        } >"$dir/gateway.env"
        {
            echo "# Written by scripts/devkeys.sh from $keys. Private: never commit."
            echo "SANCTUARY_CERT=$(pem "$keys/realm-stub.crt")"
            echo "SANCTUARY_KEY=$(pem "$keys/realm-stub.key")"
            echo "SANCTUARY_GATEWAY_PINS=$(cat "$keys/gateway.pin")"
        } >"$dir/realm-stub.env"
    )
}
