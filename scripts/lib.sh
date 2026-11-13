# Shared helpers for the gateway scripts. Sourced, not run.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SRC_DIR"

if ! command -v go >/dev/null 2>&1; then
    echo "error: Go is not installed in this environment." >&2
    echo "Add the Go feature to .devcontainer/devcontainer.json and rebuild the container:" >&2
    echo '    "ghcr.io/devcontainers/features/go:1": { "version": "1.23" }' >&2
    exit 1
fi

# The bind mount can make git refuse to stamp version info; it isn't needed.
export GOFLAGS="${GOFLAGS:-} -buildvcs=false"

build_gateway() {
    echo "==> building bin/sentience-gateway"
    go build -o bin/sentience-gateway ./cmd/sentience-gateway
}

# -race needs cgo and a C compiler; the devcontainer has gcc.
race_flag() {
    if [ "$(go env CGO_ENABLED)" = "1" ] && command -v "$(go env CC)" >/dev/null 2>&1; then
        echo "-race"
    fi
}
