#!/bin/sh
set -eu

mkdir -p /data
chown -R app:app /data 2>/dev/null || true

exec su-exec app "$@"
