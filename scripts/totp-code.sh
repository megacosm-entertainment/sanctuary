#!/usr/bin/env bash
# Print the TOTP code for a key, computed independently of the gateway
# (coreutils and OpenSSL only), to tell whether an authenticator app or the
# server is wrong when codes are refused:
#
#   scripts/totp-code.sh        asks for the key (input hidden), prints the
#                               previous, current and next codes
#
# Paste the key as the gateway shows it; spaces are ignored. The key is read
# from a hidden prompt, so it never reaches shell history or a process list.
# TOTP_TIME=unix-seconds computes for another moment (for testing).
set -euo pipefail
read -rsp "Key: " key
echo
key="$(printf '%s' "$key" | tr -d ' \t' | tr '[:lower:]' '[:upper:]')"
printf '%s' "$key" | grep -Eq '^[A-Z2-7]+$' || { echo "that is not a base32 key (letters A-Z and digits 2-7)" >&2; exit 1; }
while [ $(( ${#key} % 8 )) -ne 0 ]; do key="$key="; done
hex="$(printf '%s' "$key" | base32 -d | od -An -tx1 | tr -d ' \n')"
now="${TOTP_TIME:-$(date +%s)}"
code() { # step
    local esc mac off part
    esc="$(printf '%016x' "$1" | sed 's/../\\x&/g')"
    mac="$(printf "$esc" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$hex" | awk '{print $NF}')"
    off=$(( 16#${mac:39:1} ))
    part=$(( 16#${mac:$((off * 2)):8} & 0x7fffffff ))
    printf '%06d' $(( part % 1000000 ))
}
step=$(( now / 30 ))
echo "previous $(code $((step - 1)))   current $(code "$step")   next $(code $((step + 1)))   ($(( 30 - now % 30 ))s left)"
