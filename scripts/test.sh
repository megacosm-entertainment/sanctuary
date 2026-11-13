#!/usr/bin/env bash
# Unit and integration tests. No running gateway needed.
#
#   scripts/test.sh              all tests (race detector when available)
#   scripts/test.sh -fuzz 30     ...then fuzz the telnet parser and the
#                                sanitiser for 30 seconds each
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

if [ "$fuzz" -gt 0 ]; then
    echo "==> fuzzing telnet parser (${fuzz}s)"
    go test -run=NONE -fuzz=FuzzProcess -fuzztime="${fuzz}s" ./internal/telnet/
    echo "==> fuzzing sanitiser (${fuzz}s)"
    go test -run=NONE -fuzz=FuzzUntrusted -fuzztime="${fuzz}s" ./internal/sanitize/
    echo "==> fuzzing GMCP parser (${fuzz}s)"
    go test -run=NONE -fuzz=FuzzParse -fuzztime="${fuzz}s" ./internal/gmcp/
    echo "==> fuzzing WebSocket frame reader (${fuzz}s)"
    go test -run=NONE -fuzz=FuzzReadMessage -fuzztime="${fuzz}s" ./internal/websocket/
fi
echo "==> tests passed"
