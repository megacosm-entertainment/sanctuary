#!/usr/bin/env bash
# Run compose.yaml with its per-environment settings.
#
#   scripts/compose.sh [compose args]               .dev/env, from local
#                                                   identities (devkeys.sh)
#   scripts/compose.sh -doppler stg [compose args]  both services' settings
#                                                   from Doppler config stg
#
# With -doppler, each project's secrets are served by `doppler run --mount`
# as an ephemeral env file for the life of the compose command: nothing is
# written to disk. Default compose args: up --build.
source "$(dirname "$0")/lib.sh"

doppler_config=
if [ "${1:-}" = -doppler ]; then
    doppler_config="${2:?usage: scripts/compose.sh -doppler CONFIG [compose args]}"
    shift 2
fi
[ $# -gt 0 ] || set -- up --build
# Which engine: Docker if its daemon is reachable, otherwise Podman, whose
# `podman compose` points the compose provider at the Podman socket. (A
# `docker` command alone proves nothing: compose packages install one.)
podman_sock="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
if [ -n "${DOCKER_HOST:-}" ] || [ -S /var/run/docker.sock ]; then
    compose=(docker compose)
elif command -v podman >/dev/null; then
    if [ ! -S "$podman_sock" ]; then
        echo "Podman's socket is not running. Start it once with:" >&2
        echo "    systemctl --user enable --now podman.socket" >&2
        exit 1
    fi
    export DOCKER_HOST="unix://$podman_sock"
    compose=(podman compose)
else
    echo "neither Docker nor Podman found" >&2
    exit 1
fi

if [ -z "$doppler_config" ]; then
    [ -e .dev/env/gateway.env ] || scripts/devkeys.sh >/dev/null
    exec "${compose[@]}" "$@"
fi

command -v doppler >/dev/null || { echo "the Doppler CLI is not installed" >&2; exit 1; }
env_dir="$(mktemp -d "${TMPDIR:-/tmp}/sanctuary-env.XXXXXX")"
chmod 700 "$env_dir"
trap 'rm -rf "$env_dir"' EXIT
# One doppler run per project, nested: each mounts its project's config as
# an env file that exists only while the inner command runs.
doppler run --project sanctuary-gateway --config "$doppler_config" \
    --mount "$env_dir/gateway.env" --format env -- \
  doppler run --project sanctuary-stub-realm --config "$doppler_config" \
    --mount "$env_dir/realm-stub.env" --format env -- \
  env SANCTUARY_ENV_DIR="$env_dir" "${compose[@]}" "$@"
