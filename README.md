# Portwatcher

A lightweight TCP watcher (Python/asyncio) that logs inbound connections and notifies you via **email** and **ntfy push**.  
Includes **offline geolocation (MaxMind)** with an optional online fallback, **rDNS**, **per‑IP cooldown**, **healthcheck/CIDR ignore**, **payload snippet & protocol detection** (HTTP/TLS/SSH/…).

## Features

- Listens on a configurable TCP port (IPv4/IPv6)
- Notifications via **email** (SMTP) and **ntfy** (toggle per channel)
- Subject/title like `DE Heidelberg 78.43.247.28` (ISO country, city/region, IP)
- **Offline geo** using MaxMind **GeoLite2-City/ASN** (sidecar keeps DBs fresh)
- **rDNS** (short timeout, optional)
- **Per-IP cooldown** to prevent mail/push storms
- **Ignore** healthchecks and local/CIDR ranges (optionally also remove from logs)
- **Payload snippet** (text/hex/base64, length-limited) + **protocol detection**: HTTP (method/host/UA), TLS (SNI/ALPN/optional JA3), SSH banner, VNC/RDP/Redis…
- Timezone‑aware timestamps (default: `Europe/Berlin`)
- Multi-arch container image on **GHCR** (`linux/amd64`, `linux/arm64`)

---

## Architecture

- **portwatcher** (app): `/app/portwatcher.py` listens on the port and sends notifications
- **geoipupdate** (sidecar): downloads/refreshes MaxMind DBs into a **shared volume** `/usr/share/GeoIP`

```txt
[geoipupdate] ──writes──>  [volume: /usr/share/GeoIP]  <──reads── [portwatcher]
```

---

## Quick start

1) **Clone** and enter the repo

```bash
git clone https://github.com/alaub81/portwatcher.git
cd portwatcher
```

2) **Create configs** from the examples

- Copy `.env.example` → `.env` and adjust (port, timezone …)
- Copy `portwatcher.env.example` → `portwatcher.env` and adjust (SMTP, ntfy, …)
- Copy `geoipupdate.env.example` → `geoipupdate.env` and fill in your **MaxMind** Account/Key

3) **Start with Docker Compose**

```bash
docker compose pull
docker compose up -d
docker compose logs -f portwatcher
```

---

## Docker Compose (excerpt)

```yaml
services:
  geoipupdate:
    image: ghcr.io/maxmind/geoipupdate:latest
    restart: unless-stopped
    env_file:
      - geoipupdate.env
    environment:
      TZ: ${PW_TZ}  
    volumes:
      - geoip-db:/usr/share/GeoIP
    healthcheck:
      test: ["CMD", "sh", "-c", "test -f /usr/share/GeoIP/GeoLite2-City.mmdb -a -f /usr/share/GeoIP/GeoLite2-ASN.mmdb"]
      interval: 1m
      timeout: 5s
      retries: 3
      start_period: 30s

  portwatcher:
    image: ghcr.io/alaub81/portwatcher:latest
    restart: unless-stopped
    env_file:
      - portwatcher.env
      - .env
    environment:
      TZ: ${PW_TZ}
      # vermeidet __pycache__-Writes auf read-only FS
      PYTHONDONTWRITEBYTECODE: "1"
    ports:
      - "${PW_PORT:-5555}:${PW_PORT:-5555}/tcp"
    volumes:
      - geoip-db:/usr/share/GeoIP
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
        #condition: service_started  # oder 'service_healthy' falls HC gesetzt
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/bin/sh", "/app/healthcheck.sh"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  geoip-db:
```

**Local dev / own build (optional):**  
You can also build locally (Dockerfile included) or add a `docker-compose.dev.yml` override.

---

## Configuration

All variables are documented in **`*.env.example`** files. Key groups:

### Basics

- `PW_HOST` (`0.0.0.0`) – bind address
- `PW_LOG_LEVEL` (`INFO`/`DEBUG`/…)
- `PW_BANNER` – optional banner text sent to clients

### Notifications

- `PW_ENABLE_EMAIL`, `PW_ENABLE_PUSH`
- **SMTP:** `PW_SMTP_SERVER`, `PW_SMTP_PORT`, `PW_SMTP_STARTTLS`, `PW_SMTP_USER`, `PW_SMTP_PASS` **or** `PW_SMTP_PASS_FILE`, `PW_MAIL_FROM`, `PW_MAIL_TO`
- **ntfy:** `PW_NTFY_SERVER`, `PW_NTFY_TOPIC`, `PW_NTFY_PRIORITY`, `PW_NTFY_TAGS`

### Geo / rDNS

- **Offline:** `PW_GEOIP_CITY_DB=/usr/share/GeoIP/GeoLite2-City.mmdb`, `PW_GEOIP_ASN_DB=/usr/share/GeoIP/GeoLite2-ASN.mmdb`
- **Online (optional):** `PW_IPAPI_ENABLE=0|1`, `PW_IPAPI_BUDGET_PER_MIN`
- `PW_RDNS_ENABLE`, `PW_RDNS_TIMEOUT`

### Ignore / Healthchecks

- `PW_NOTIFY_IGNORE_LOOPBACK=1` – mute 127.0.0.0/8, ::1
- `PW_NOTIFY_IGNORE_PRIVATES=0|1` – mute RFC1918/link-local
- `PW_NOTIFY_IGNORE_CIDRS="172.24.0.0/16,::1/128"` – custom ranges
- `PW_LOG_IGNORE_SUPPRESSED=1` – also remove suppressed events from logs

### Payload & detection

- `PW_CAPTURE_PAYLOAD=1`, `PW_PROBE_MAX_BYTES` (default 2048), `PW_PROBE_TIMEOUT_MS` (default 800)
- `PW_PAYLOAD_IN_NOTIF=1`, `PW_PAYLOAD_MAX_CHARS` (default 600), `PW_PAYLOAD_MODE=auto|text|hex|base64`, `PW_PAYLOAD_STRIP_CONTROL=1`
- `PW_TLS_JA3=0|1` – optional TLS JA3 fingerprint

### Rate-limit, time, detail fields

- `PW_RL_COOLDOWN_S` (default 1800), `PW_RL_FORGET_S` (default 86400)
- `PW_TZ=Europe/Berlin`, `PW_TS_INCLUDE_UTC=0|1`
- `PW_INCLUDE_CITY=1`, `PW_INCLUDE_COORDS=0`, `PW_LATLON_PRECISION=2`

> **Note:** `.env` and `geoipupdate.env` are **gitignored**. Examples are tracked: `.env.example`, `geoipupdate.env.example`.

---

## Local build (optional)

The simplified Dockerfile uses `python:3.13-slim` and installs `python3-geoip2` via APT.

```bash
docker build -t portwatcher:dev .
docker run --rm -it -p 1417:1417 --env-file .env -v geoip-db:/usr/share/GeoIP portwatcher:dev
```

---

## CI/CD (GitHub Actions)

- **CI:** Python syntax check & Docker build (no push)
- **Release:** Buildx (driver `docker-container`) + push to **GHCR** (`ghcr.io/alaub81/portwatcher:{latest,SHA}`), optional multi-arch

> Tip: In repo **Settings → Actions → Workflow permissions**, set **Read and write** so `GITHUB_TOKEN` can push to GHCR.

---

## Security

- Never commit secrets. Use `*.env` (gitignored), `PW_SMTP_PASS_FILE` (Docker Secrets), or Actions secrets.
- Container runs **non-root**, filesystem **read-only**, `cap_drop: [ALL]`, `no-new-privileges`.
- Payload snippets are length‑limited and control chars are sanitized; consider header redaction if needed.

---

## Troubleshooting

- **Geo fields empty:** ensure DBs exist in the app container (`/usr/share/GeoIP`); check sidecar health.
- **`ModuleNotFoundError: geoip2`:** ensure the image contains `python3-geoip2` (APT) or `geoip2` (pip).
- **Healthcheck messages/logs:** set `PW_NOTIFY_IGNORE_LOOPBACK=1` and optionally `PW_LOG_IGNORE_SUPPRESSED=1`.
- **Timezone/UTC suffix:** set `PW_TZ`, optionally enable `PW_TS_INCLUDE_UTC`.
- **GHA cache error (“docker driver”):** set up Buildx with `driver: docker-container`.

---
