#!/usr/bin/env bash
# Create the development realm-link identities in .dev/keys, if missing
# (gateway and realm-stub: .crt, .key, .pin; never overwritten), and write
# .dev/env/{gateway,realm-stub}.env from them for compose.yaml. Used by
# scripts/run.sh -split and scripts/compose.sh. .dev is git-ignored.
source "$(dirname "$0")/lib.sh"
build_gateway
build_realm
dev_keys .dev/keys
dev_env .dev/keys .dev/env
ls -l .dev/keys .dev/env
