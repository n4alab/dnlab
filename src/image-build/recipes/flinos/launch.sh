#!/bin/sh
set -eu
export PYTHONPATH="/opt/vrnetlab/common${PYTHONPATH:+:$PYTHONPATH}"
exec python3 /opt/flinos/launch.py
