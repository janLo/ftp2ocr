#!/bin/sh
# Container entrypoint for ftp2ocr.
#
# Optionally preloads jemalloc (genuinely helpful for long-running Python
# processes). The library path is detected at runtime so the same image works
# across CPU architectures (amd64, arm64, ...). Set FTP2OCR_JEMALLOC=0 to
# disable preloading.
set -eu

if [ "${FTP2OCR_JEMALLOC:-1}" != "0" ]; then
    # Find the multiarch libjemalloc.so.2 without hardcoding the triplet.
    lib="$(find /usr/lib -name 'libjemalloc.so.2' -print -quit 2>/dev/null || true)"
    if [ -n "${lib:-}" ]; then
        LD_PRELOAD="${LD_PRELOAD:+$LD_PRELOAD:}${lib}"
        export LD_PRELOAD
    fi
fi

exec "$@"
