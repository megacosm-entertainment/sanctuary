#!/usr/bin/env bash
# Known-vulnerability scan: checks the code against the Go vulnerability
# database with govulncheck, which reports only vulnerabilities whose code
# the gateway can actually reach. Exits non-zero if any are found.
#
#   scripts/vulncheck.sh          scan the module
#   scripts/vulncheck.sh -show traces   pass flags through to govulncheck
#
# govulncheck is run at a pinned version with `go run`, which downloads it
# into the Go module cache on first use. Run this in the devcontainer.
source "$(dirname "$0")/lib.sh"
need_go

# Pinned: bump deliberately, not implicitly.
GOVULNCHECK_VERSION="v1.9.0"

# Build govulncheck with the module's own toolchain (the go line in go.mod):
# `go run pkg@version` otherwise uses the installed toolchain, and a tool
# built with an older Go cannot analyse code that requires a newer one.
toolchain="$(go env GOVERSION)"
echo "==> ${toolchain}, govulncheck ${GOVULNCHECK_VERSION}"
GOTOOLCHAIN="${toolchain}" go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" "$@" ./...
