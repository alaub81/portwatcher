# Portwatcher

Ein schlanker TCP-Watcher für Debian/Python, der eingehende Verbindungen erfasst und dich per **E-Mail** und **ntfy push** benachrichtigt.  
Mit **Offline-Geolokalisierung (MaxMind)**, optionalem **Online-Fallback**, **rDNS**, **Cooldown pro IP**, **Healthcheck-/CIDR-Ignore**, **Payload-Snippet & Protokoll-Erkennung** (HTTP/TLS/SSH/…).

## Features

- Lauscht auf frei wählbarem TCP-Port (IPv4/IPv6)
- Benachrichtigung via **E-Mail** (SMTP) und **ntfy** (konfigurierbar)
- **Betreff**: `DE Heidelberg 78.43.247.28` (ISO-Land, Ort/Region/Land, IP)
- **Geodaten offline** via MaxMind **GeoLite2-City/ASN** (Sidecar aktualisiert Datenbanken)
- **rDNS** (optional, kurzer Timeout)
- **Cooldown pro IP** (Mail/Push-Stürme werden verhindert)
- **Healthcheck-/lokale Netze ignorieren** – keine Benachrichtigungen und (optional) kein Logging
- **Payload-Snippet** der ersten Bytes (Text/Hex/Base64; Länge & Modus per ENV)
- **Protokoll-Erkennung** (HTTP Request-Line/Host/UA, TLS SNI/ALPN/optional JA3, SSH-Banner, VNC/RDP/Redis…)
- Zeitstempel **timezone-aware** (Standard: `Europe/Berlin`, konfigurierbar)

---

## Architektur

- **portwatcher** (App-Container): Python-Service mit allen Features  
- **geoipupdate** (Sidecar): lädt/aktualisiert MaxMind-Datenbanken regelmäßig in ein **shared Volume**  
- **Volume** `/var/lib/GeoIP`: wird von beiden Containern gemeinsam genutzt

```
[geoipupdate] ──writes──>  [volume: /var/lib/GeoIP]  <──reads── [portwatcher]
```

---

## Voraussetzungen

- Docker & Docker Compose
- MaxMind Account (kostenlos für **GeoLite2**) → **Account ID** & **License Key**
- SMTP-Zugang (für E-Mail) und/oder ntfy-Topic

---

## Repository-Struktur (Beispiel)

```
.
├─ portwatcher.py
├─ Dockerfile
├─ docker-compose.yml
├─ .env                # App-Umgebung (PW_* Variablen)
└─ geoipupdate.env     # nur für den Sidecar (MaxMind)
```

---

## Installation & Start

1. **.env** (App) erstellen/anpassen:
   ```env
   PW_HOST=0.0.0.0
   PW_PORT=1417
   PW_MAX_CONCURRENCY=200
   PW_LOG_LEVEL=INFO
   PW_BANNER=

   PW_ENABLE_EMAIL=1
   PW_ENABLE_PUSH=1

   # SMTP
   PW_SMTP_SERVER=mx.example.de
   PW_SMTP_PORT=587
   PW_SMTP_STARTTLS=1
   PW_SMTP_USER=user@example.de
   PW_SMTP_PASS=CHANGE_ME        # oder per Secret: PW_SMTP_PASS_FILE=/run/secrets/smtp_pass
   PW_MAIL_FROM=portwatch@example.de
   PW_MAIL_TO=you@example.de

   # ntfy
   PW_NTFY_SERVER=https://ntfy.sh
   PW_NTFY_TOPIC=your-topic
   PW_NTFY_PRIORITY=5
   PW_NTFY_TAGS=rotating_light,shield

   # Geo (offline)
   PW_GEOIP_CITY_DB=/var/lib/GeoIP/GeoLite2-City.mmdb
   PW_GEOIP_ASN_DB=/var/lib/GeoIP/GeoLite2-ASN.mmdb

   # Optionaler Online-Fallback (standard: aus)
   PW_IPAPI_ENABLE=0
   PW_IPAPI_BUDGET_PER_MIN=40

   # rDNS
   PW_RDNS_ENABLE=1
   PW_RDNS_TIMEOUT=1.0

   # Detailfelder
   PW_INCLUDE_CITY=1
   PW_INCLUDE_COORDS=0
   PW_LATLON_PRECISION=2

   # Rate-Limit (Cooldown)
   PW_RL_COOLDOWN_S=1800
   PW_RL_FORGET_S=86400
   PW_CACHE_SIZE=20000

   # Zeiten
   PW_TZ=Europe/Berlin
   PW_TS_INCLUDE_UTC=0

   # Healthchecks/Netze ignorieren
   PW_NOTIFY_IGNORE_LOOPBACK=1
   # PW_NOTIFY_IGNORE_PRIVATES=1
   # PW_NOTIFY_IGNORE_CIDRS=172.24.0.0/16,::1/128
   PW_LOG_IGNORE_SUPPRESSED=1

   # Payload-Erfassung
   PW_CAPTURE_PAYLOAD=1
   PW_PROBE_MAX_BYTES=2048
   PW_PROBE_TIMEOUT_MS=800
   PW_PAYLOAD_IN_NOTIF=1
   PW_PAYLOAD_MAX_CHARS=600
   PW_PAYLOAD_MODE=auto        # auto|text|hex|base64
   PW_PAYLOAD_STRIP_CONTROL=1
   # PW_TLS_JA3=1
   ```

2. **geoipupdate.env** (nur Sidecar):
   ```
   GEOIPUPDATE_ACCOUNT_ID=YOUR_ID
   GEOIPUPDATE_LICENSE_KEY=YOUR_KEY
   GEOIPUPDATE_EDITION_IDS=GeoLite2-City GeoLite2-ASN
   GEOIPUPDATE_FREQUENCY=24
   GEOIPUPDATE_DB_DIR=/var/lib/GeoIP
   ```

3. **docker-compose.yml** (Beispiel):
   ```yaml
   services:
     geoipupdate:
       image: ghcr.io/maxmind/geoipupdate:latest
       restart: unless-stopped
       env_file:
         - ./geoipupdate.env
       volumes:
         - geoip-db:/var/lib/GeoIP
       healthcheck:
         test: ["CMD", "sh", "-c", "test -f /var/lib/GeoIP/GeoLite2-City.mmdb -a -f /var/lib/GeoIP/GeoLite2-ASN.mmdb"]
         interval: 1m
         timeout: 5s
         retries: 3
         start_period: 30s

     portwatcher:
       build: .
       image: portwatcher:latest
       restart: unless-stopped

       env_file:
         - ./.env
       environment:
         TZ: ${PW_TZ}
         PYTHONDONTWRITEBYTECODE: "1"

       ports:
         - "${PW_PORT:-5555}:${PW_PORT:-5555}/tcp"

       volumes:
         - geoip-db:/var/lib/GeoIP

       user: "10001:10001"
       read_only: true
       tmpfs:
         - /tmp
       cap_drop:
         - ALL
       security_opt:
         - no-new-privileges:true
       ulimits:
         nofile: 16384

       depends_on:
         geoipupdate:
           condition: service_started

       healthcheck:
         test:
           - CMD
           - python3
           - -c
           - >
             import os,socket,sys;
             p=int(os.environ.get('PW_PORT','5555'));
             ok=0;
             # v4
             try:
               s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(2); s.connect(('127.0.0.1',p)); s.close(); ok=1
             except Exception:
               pass
             # v6
             if not ok:
               try:
                 s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.settimeout(2); s.connect(('::1',p)); s.close(); ok=1
               except Exception:
                 pass
             sys.exit(0 if ok else 1)
         interval: 30s
         timeout: 5s
         retries: 3

   volumes:
     geoip-db:
   ```

4. **Dockerfile** (App-Image):
   ```dockerfile
   FROM python:3.12-slim
   RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata python3-geoip2 \
    && rm -rf /var/lib/apt/lists/*

   WORKDIR /app
   RUN adduser --disabled-password --gecos "" --home /app --uid 10001 app
   COPY --chown=app:app portwatcher.py /app/portwatcher.py
   USER app
   EXPOSE 5555/tcp
   CMD ["python3", "/app/portwatcher.py"]
   ```

5. **Build & Run**
   ```bash
   docker compose build
   docker compose up -d
   docker compose logs -f portwatcher
   ```

## Testen

- **HTTP**:
  ```bash
  curl -v http://<DEINE-IP>:1417/
  ```
- **TLS**:
  ```bash
  openssl s_client -connect <DEINE-IP>:1417 -servername test.example
  ```
- **SSH**:
  ```bash
  ssh -p 1417 <DEINE-IP>
  ```

## Konfiguration (ENV-Referenz)

### Basis
| Variable | Default | Beschreibung |
|---|---:|---|
| `PW_HOST` | `0.0.0.0` | Bind-Adresse (für IPv6 `::`) |
| `PW_PORT` | `1417` | Port |
| `PW_MAX_CONCURRENCY` | `200` | gleichzeitige Handler |
| `PW_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/… |
| `PW_BANNER` | `""` | optionaler Banner-Text an Clients (roh) |

### Benachrichtigungen
`PW_ENABLE_EMAIL`, `PW_ENABLE_PUSH`  
**E-Mail (SMTP):** `PW_SMTP_SERVER`, `PW_SMTP_PORT`, `PW_SMTP_STARTTLS`, `PW_SMTP_USER`, `PW_SMTP_PASS`/`PW_SMTP_PASS_FILE`, `PW_MAIL_FROM`, `PW_MAIL_TO`  
**ntfy:** `PW_NTFY_SERVER`, `PW_NTFY_TOPIC`, `PW_NTFY_PRIORITY`, `PW_NTFY_TAGS`

### Geo
`PW_GEOIP_CITY_DB`, `PW_GEOIP_ASN_DB`, `PW_IPAPI_ENABLE`, `PW_IPAPI_BUDGET_PER_MIN`, `PW_GEO_ALLOW_PRIVATE`

### rDNS & Details
`PW_RDNS_ENABLE`, `PW_RDNS_TIMEOUT`, `PW_INCLUDE_CITY`, `PW_INCLUDE_COORDS`, `PW_LATLON_PRECISION`

### Rate-Limit & Cache
`PW_RL_COOLDOWN_S`, `PW_RL_FORGET_S`, `PW_CACHE_SIZE`

### Zeit
`PW_TZ`, `PW_TS_INCLUDE_UTC`

### Healthchecks/Ignore
`PW_NOTIFY_IGNORE_LOOPBACK`, `PW_NOTIFY_IGNORE_PRIVATES`, `PW_NOTIFY_IGNORE_CIDRS`, `PW_LOG_IGNORE_SUPPRESSED`

### Payload/Erkennung
`PW_CAPTURE_PAYLOAD`, `PW_PROBE_MAX_BYTES`, `PW_PROBE_TIMEOUT_MS`,  
`PW_PAYLOAD_IN_NOTIF`, `PW_PAYLOAD_MAX_CHARS`, `PW_PAYLOAD_MODE`, `PW_PAYLOAD_STRIP_CONTROL`, `PW_TLS_JA3`

## Sicherheit

- SMTP-Passwort am besten per Docker **Secret** (`PW_SMTP_PASS_FILE`)  
- Container läuft als Non-Root; Filesystem read-only; `no-new-privileges`; `cap_drop: [ALL]`  
- Payload-Snippets limitiert & maskiert; bei Bedarf Header-Redaction ergänzen

## Troubleshooting

- **geoip2 fehlt** → App-Image muss `python3-geoip2` (APT) oder `geoip2` (pip) enthalten  
- **Geo-Felder leer** → prüfen, ob DBs unter `/var/lib/GeoIP` vorhanden sind  
- **Healthcheck-Mails** → `PW_NOTIFY_IGNORE_LOOPBACK=1` (und ggf. `PW_LOG_IGNORE_SUPPRESSED=1`)  
- **Timezone/Warnings** → bereits timezone-aware; `PW_TZ` setzen

## Lizenz

Privat/Intern. Bei Bedarf anpassen.
