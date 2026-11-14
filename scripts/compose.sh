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

# Rootless Podman: compose.rootless.yaml keeps players' real addresses.
files=()
rootless="${SANCTUARY_ROOTLESS:-}"
if [ -z "$rootless" ] && [ "${compose[0]}" = podman ]; then
    [ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" = true ] && rootless=1
fi
if [ "$rootless" = 1 ]; then
    files=(-f compose.yaml -f compose.rootless.yaml)
    echo "==> rootless Podman: pasta networking, so the gateway sees players' addresses"
fi
compose+=("${files[@]+"${files[@]}"}")

if [ -z "$doppler_config" ]; then
    [ -e .dev/env/gateway.env ] || scripts/devkeys.sh >/dev/null
    exec "${compose[@]}" "$@"
fi

command -v doppler >/dev/null || { echo "the Doppler CLI is not installed" >&2; exit 1; }
# Host ports are read by compose itself, before any container exists, so
# they come from the gateway's Doppler config into this shell (unless
# already set). They are not secrets.
for v in PUBLISH_TELNET PUBLISH_TELNETS PUBLISH_WS; do
    if [ -z "${!v:-}" ]; then
        val="$(doppler secrets get "$v" --plain --project sanctuary-gateway --config "$doppler_config" 2>/dev/null || true)"
        [ -n "$val" ] && export "$v=$val"
    fi
done
echo "==> publishing telnet ${PUBLISH_TELNET:-9000}, telnet+TLS ${PUBLISH_TELNETS:-9010}, WebSocket ${PUBLISH_WS:-9020}"
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
