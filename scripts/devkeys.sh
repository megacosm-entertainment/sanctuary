#!/usr/bin/env bash
# Create the development realm-link identities in .dev/keys, if missing:
# gateway.{crt,key,pin} and realm-stub.{crt,key,pin}. Used by
# scripts/run.sh -split and compose.yaml. The directory is git-ignored and
# existing keys are never overwritten.
source "$(dirname "$0")/lib.sh"
build_gateway
build_realm
dev_keys .dev/keys
ls -l .dev/keys
