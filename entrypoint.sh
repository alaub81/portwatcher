#!/bin/sh
set -eu

# Nur noch starten; MMDBs kommen aus dem Volume (/usr/share/GeoIP)
echo "[entrypoint] starting portwatcher on 0.0.0.0:${PW_PORT:-5555} (user: $(id -u))"
exec python3 /app/portwatcher.py
