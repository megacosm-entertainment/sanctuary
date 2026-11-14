#!/usr/bin/env bash
# Unit and integration tests. No running gateway needed.
#
#   scripts/test.sh              all tests (race detector when available)
#   scripts/test.sh -fuzz 30     ...then fuzz every parser of untrusted
#                                input for 30 seconds each
#   scripts/test.sh -run MTTS    pass anything else through to go test
source "$(dirname "$0")/lib.sh"

fuzz=0
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        -fuzz) fuzz="${2:?seconds}"; shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done

echo "==> go vet"
go vet ./...

race="$(race_flag)"
[ -z "$race" ] && echo "note: race detector unavailable (needs cgo + gcc); running without it"
echo "==> go test $race ./..."
go test $race -count=1 "${args[@]+"${args[@]}"}" ./...

# Shrinking each new interesting input may otherwise take up to Go's default
# of 60s, during which a short run makes no progress; large valid messages
# (the realm protocol accepts up to 256 KiB) are slow to shrink.
fuzz_one() { # target package description
    echo "==> fuzzing $3 (${fuzz}s)"
    go test -run=NONE -fuzz="$1" -fuzztime="${fuzz}s" -fuzzminimizetime=5s "$2"
}

if [ "$fuzz" -gt 0 ]; then
    fuzz_one FuzzProcess     ./internal/telnet/     "telnet parser"
    fuzz_one FuzzUntrusted   ./internal/sanitize/   "sanitiser (untrusted text)"
    fuzz_one FuzzServer      ./internal/sanitize/   "sanitiser (server output)"
    fuzz_one FuzzParse       ./internal/gmcp/       "GMCP parser"
    fuzz_one FuzzReadMessage ./internal/websocket/  "WebSocket frame reader"
    fuzz_one FuzzDecode      ./internal/realmproto/ "realm protocol decoder"
fi
echo "==> tests passed"
