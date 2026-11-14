# Shared helpers for the gateway scripts. Sourced, not run.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SRC_DIR"

if ! command -v go >/dev/null 2>&1; then
    echo "error: Go is not installed in this environment." >&2
    echo "Build and test in the devcontainer (image: docker/dev/Dockerfile), which provides it." >&2
    exit 1
fi

# The bind mount can make git refuse to stamp version info; it isn't needed.
export GOFLAGS="${GOFLAGS:-} -buildvcs=false"

build_gateway() {
    echo "==> building bin/sanctuary-gateway"
    go build -o bin/sanctuary-gateway ./cmd/sanctuary-gateway
}

build_realm() {
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
