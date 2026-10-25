#!/bin/sh
# Native Kbuild only; artifacts are statically checked before any promotion.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -f "$HERE/../work/build-abi-port/include/config/kernel.release" ]; then
    "$HERE/prepare.sh"
fi
exec python3 "$HERE/build.py"
