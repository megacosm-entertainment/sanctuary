#!/usr/bin/env bash
# Build and run the gateway in the foreground on 9000 (telnet), 9010
# (telnet+TLS) and 9020 (WSS), with a generated dev certificate. Extra
# arguments go to the gateway, e.g. scripts/run.sh -ws-plain -log-level debug
# Ctrl-C shuts it down gracefully.
source "$(dirname "$0")/lib.sh"
build_gateway
exec ./bin/sanctuary-gateway "$@"
