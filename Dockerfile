# syntax=docker/dockerfile:1
FROM python:3.13-slim

# Systempakete nur, was nötig ist
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "geoip2>=4,<5"

# App-User & Verzeichnisse
WORKDIR /app
RUN adduser --disabled-password --gecos "" --home /app --uid 10001 app \
 && mkdir -p /var/lib/GeoIP \
 && chown -R app:app /app /var/lib/GeoIP

# Dateien
COPY --chown=app:app portwatcher.py /app/portwatcher.py
COPY --chown=app:app entrypoint.sh /app/entrypoint.sh
COPY --chown=app:app healthcheck.sh /app/healthcheck.sh
RUN chmod +x /app/*.sh

EXPOSE 5555/tcp
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/bin/sh", "/app/healthcheck.sh"]

USER app
ENTRYPOINT ["/app/entrypoint.sh"]
