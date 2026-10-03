#!/bin/sh
# Return success only for an FQDN usable as the suffix of dynamic Web UI
# token subdomains. Keep this standalone so the proxy startup contract is
# directly testable without Apache or Docker.
set -eu

hostname="${1:-}"
case "$hostname" in
    localhost|*:*|*..*|.*|*.) exit 1 ;;
esac
[ "${#hostname}" -le 253 ] || exit 1

printf '%s\n' "$hostname" | grep -Eq \
    '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$' \
    || exit 1

# Reject numeric dotted strings, including values that are not valid IPv4
# addresses but cannot be a practical Web UI DNS namespace.
printf '%s\n' "$hostname" | grep -Eq '[A-Za-z]'
