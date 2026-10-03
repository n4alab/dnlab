#!/bin/sh
# Production boundary for the signed FLINOS launcher.
set -eu
fail() { echo "error: $*" >&2; exit 64; }

[ -c /dev/kvm ] || fail "FLINOS requires /dev/kvm"
[ -d /persist ] || fail "FLINOS requires a /persist bind mount"
[ -w /persist ] || fail "FLINOS persistence location is not writable"
if [ "${QEMU_ADDITIONAL_ARGS+x}" = x ]; then
    fail "QEMU_ADDITIONAL_ARGS is not supported for FLINOS"
fi

runtime=/persist/OVMF_VARS.fd
if [ -e "$runtime" ] && [ ! -f "$runtime" ]; then
    fail "FLINOS runtime NVRAM location is not a regular file"
fi
if [ -e "$runtime" ] && [ ! -w "$runtime" ]; then
    fail "FLINOS runtime NVRAM location is not writable"
fi
probe=$(mktemp /persist/.flinos-write-check.XXXXXX) || fail "FLINOS persistence location is not writable"
rm -f "$probe"

unset FLINOS_IMAGE FLINOS_OVMF_CODE FLINOS_OVMF_VARS_TEMPLATE FLINOS_OVMF_VARS_RUNTIME
export FLINOS_IMAGE=/opt/flinos/flinos.qcow2
export FLINOS_OVMF_CODE=/opt/flinos/firmware/OVMF_CODE.fd
export FLINOS_OVMF_VARS_TEMPLATE=/opt/flinos/firmware/OVMF_VARS.fd
export FLINOS_OVMF_VARS_RUNTIME="$runtime"
exec /opt/flinos/launch.sh
