#!/bin/sh
set -eu
[ -c /dev/kvm ] || { echo 'error: generic_vm requires /dev/kvm' >&2; exit 64; }
[ -d /persist ] && [ -w /persist ] || { echo 'error: generic_vm requires writable /persist' >&2; exit 64; }
if grep -q '"firmware": "uefi"' /opt/generic/spec.json; then
  [ -f /persist/OVMF_VARS.fd ] || cp /opt/generic/OVMF_VARS.fd /persist/OVMF_VARS.fd
fi
export PYTHONPATH="/opt/vrnetlab/common${PYTHONPATH:+:$PYTHONPATH}"
exec python3 /opt/generic/launch.py
