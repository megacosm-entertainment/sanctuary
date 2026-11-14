#!/usr/bin/env bash
# Staff account commands for the compose deployment:
#
#   scripts/account.sh [-doppler CONFIG] COMMAND [args]
#   scripts/account.sh -doppler stg list
#   scripts/account.sh -doppler stg create -role staff Mara
#
# It runs `sanctuary-gateway account` in a short-lived container of the
# gateway service: the same image, settings and gateway-data volume as the
# running gateway, without entering it. The file store's lock works across
# containers on one volume, so this is safe while the gateway runs.
#
# Why not `compose exec`: under rootless Podman, exec into the hardened
# gateway container fails before the command starts (crun cannot set the
# new process's oom_score_adj). A fresh container has no such problem and
# works the same under Docker.
#
# Outside compose, run bin/sanctuary-gateway account ... directly.
set -euo pipefail
dir="$(dirname "$0")"
via=()
if [ "${1:-}" = -doppler ]; then
    via=(-doppler "${2:?usage: scripts/account.sh -doppler CONFIG COMMAND [args]}")
    shift 2
fi
[ $# -gt 0 ] || set -- help
exec "$dir/compose.sh" "${via[@]+"${via[@]}"}" run --rm --no-deps -T gateway /sanctuary-gateway account "$@"
