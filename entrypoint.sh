#!/bin/sh
set -eu

# Nur noch starten; MMDBs kommen aus dem Volume (/var/lib/GeoIP)
echo "[entrypoint] starting portwatcher on 0.0.0.0:${PW_PORT:-5555} (user: $(id -u))"
exec python3 /app/portwatcher.py
