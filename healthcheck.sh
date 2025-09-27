#!/bin/sh
host="127.0.0.1"
port="${PW_PORT:-5555}"
timeout=2
python3 - <<'PY'
import os, socket, sys
host="127.0.0.1"
port=int(os.environ.get("PW_PORT","5555"))
s=socket.socket()
s.settimeout(2)
try:
    s.connect((host, port))
    # Option: kurz lesen, falls Banner gesetzt ist (nicht zwingend)
    try:
        s.settimeout(0.5)
        s.recv(64)
    except Exception:
        pass
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
