#!/bin/sh
# Static verification only. Never builds, loads modules, or accesses devices.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    echo 'FAIL: required tool unavailable: python3' >&2
    exit 1
fi
exec python3 "$HERE/verify.py" "$@"
