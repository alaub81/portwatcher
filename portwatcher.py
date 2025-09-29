#!/usr/bin/env python3
import asyncio
import logging
import os
import socket
import json
import smtplib
import ipaddress
import re
import time
import threading
import urllib.request
import base64
import string
import hashlib
from email.message import EmailMessage
from functools import lru_cache
from urllib.request import urlopen, Request
from urllib.error import URLError
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

# ===== Helpers to robustly parse ENV (strip inline comments) =====
def _env_raw(name: str, default: str | None = None) -> str | None:
    """Return env value with trailing '# …' comment stripped and whitespace trimmed."""
    v = os.environ.get(name)
    if v is None:
        return default
    v = v.split("#", 1)[0].strip()
    return v if v != "" else default

def _env_bool(name: str, default: bool) -> bool:
    v = _env_raw(name, None)
    if v is None:
        return default
    return v.lower() not in ("0", "false", "no", "off", "")

def _env_int(name: str, default: int) -> int:
    v = _env_raw(name, None)
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        logging.warning(f"Invalid integer for {name}='{os.environ.get(name)}', using default {default}")
        return default

def _env_float(name: str, default: float) -> float:
    v = _env_raw(name, None)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        logging.warning(f"Invalid float for {name}='{os.environ.get(name)}', using default {default}")
        return default

def _env_secret(name: str, fallback_value: str) -> str:
    """Allow PW_SMTP_PASS or PW_SMTP_PASS_FILE (Docker Secrets)."""
    file_var = f"{name}_FILE"
    path = _env_raw(file_var, None)
    if path:
        try:
            return open(path, "r", encoding="utf-8").read().strip()
        except Exception as e:
            logging.warning(f"Could not read secret file {path}: {e}")
    return _env_raw(name, fallback_value) or fallback_value

# ===== Notification ignore rules (for healthchecks etc.) =====
def _parse_cidrs(v: str | None) -> list:
    if not v:
        return []
    nets = []
    for tok in re.split(r"[,\s]+", v.strip()):
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except Exception:
            pass
    return nets

NOTIFY_IGNORE_LOOPBACK = _env_bool("PW_NOTIFY_IGNORE_LOOPBACK", True)   # 127.0.0.0/8, ::1
NOTIFY_IGNORE_PRIVATES = _env_bool("PW_NOTIFY_IGNORE_PRIVATES", False)  # RFC1918 & link-local
NOTIFY_IGNORE_CIDRS    = _parse_cidrs(_env_raw("PW_NOTIFY_IGNORE_CIDRS", ""))  # e.g. "172.24.0.0/16,::1/128"
LOG_IGNORE_SUPPRESSED  = _env_bool("PW_LOG_IGNORE_SUPPRESSED", True)    # unterdrückte Quellen auch nicht loggen?

def _notify_suppress(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if NOTIFY_IGNORE_LOOPBACK and ip_obj.is_loopback:
        return True
    if NOTIFY_IGNORE_PRIVATES and (ip_obj.is_private or ip_obj.is_link_local):
        return True
    for net in NOTIFY_IGNORE_CIDRS:
        if ip_obj in net:
            return True
    return False

# ========== Basis-Konfig ==========
HOST = _env_raw("PW_HOST", "0.0.0.0")
PORT = _env_int("PW_PORT", 1417)
MAX_CONCURRENCY = _env_int("PW_MAX_CONCURRENCY", 200)
BANNER = _env_raw("PW_BANNER", "") or ""
LOG_LEVEL = (_env_raw("PW_LOG_LEVEL", "INFO") or "INFO").upper()

# --- Zeitzone & Timestamps ---
PW_TZ = _env_raw("PW_TZ", "Europe/Berlin") or "Europe/Berlin"
PW_TS_INCLUDE_UTC = _env_bool("PW_TS_INCLUDE_UTC", False)
try:
    TZ = ZoneInfo(PW_TZ)
except Exception:
    logging.warning(f"Invalid timezone '{PW_TZ}', falling back to UTC")
    TZ = ZoneInfo("UTC")

def now_local_iso():
    return datetime.now(TZ).isoformat(timespec="seconds")  # e.g. 2025-09-26T21:07:42+02:00

def now_utc_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")  # e.g. 2025-09-26T19:07:42+00:00

# ========== Kanäle enable/disable ==========
ENABLE_EMAIL = _env_bool("PW_ENABLE_EMAIL", True)
ENABLE_PUSH  = _env_bool("PW_ENABLE_PUSH",  True)

# ========== E-Mail ==========
SMTP_SERVER   = _env_raw("PW_SMTP_SERVER", "")
SMTP_PORT     = _env_int("PW_SMTP_PORT", 587)
SMTP_STARTTLS = _env_bool("PW_SMTP_STARTTLS", True)
SMTP_USER     = _env_raw("PW_SMTP_USER", "")
SMTP_PASS     = _env_secret("PW_SMTP_PASS", "")
MAIL_FROM     = _env_raw("PW_MAIL_FROM", "")
MAIL_TO       = _env_raw("PW_MAIL_TO", "")

# ========== ntfy Push ==========
NTFY_SERVER = (_env_raw("PW_NTFY_SERVER", "https://ntfy.sh") or "https://ntfy.sh").rstrip("/")
NTFY_TOPIC  = _env_raw("PW_NTFY_TOPIC", "")     # z.B. andreas-portwatcher-<random>
NTFY_PRIO   = _env_raw("PW_NTFY_PRIORITY", "5") # 1..5 oder min/low/default/high/urgent
NTFY_TAGS   = _env_raw("PW_NTFY_TAGS", "rotating_light,shield") or "rotating_light,shield"

# ========== Geo OFFLINE (MaxMind) with lazy/reload ==========
GEOIP_CITY_DB = _env_raw("PW_GEOIP_CITY_DB", "")  # /usr/share/GeoIP/GeoLite2-City.mmdb
GEOIP_ASN_DB  = _env_raw("PW_GEOIP_ASN_DB", "")   # /usr/share/GeoIP/GeoLite2-ASN.mmdb
_city_reader = None; _city_mtime = 0.0
_asn_reader  = None; _asn_mtime  = 0.0
_geo_lock    = threading.Lock()

def _get_city_reader():
    global _city_reader, _city_mtime
    p = GEOIP_CITY_DB
    if not p:
        return None
    try:
        m = os.path.getmtime(p)
    except FileNotFoundError:
        return None
    with _geo_lock:
        if _city_reader is None or m != _city_mtime:
            try:
                import geoip2.database  # lazy import
                try:
                    _city_reader and _city_reader.close()
                except Exception:
                    pass
                _city_reader = geoip2.database.Reader(p)
                _city_mtime = m
                logging.info(f"Loaded City DB: {p} (mtime={m})")
            except Exception as e:
                logging.warning(f"City DB load failed: {e}")
                _city_reader = None
    return _city_reader

def _get_asn_reader():
    global _asn_reader, _asn_mtime
    p = GEOIP_ASN_DB
    if not p:
        return None
    try:
        m = os.path.getmtime(p)
    except FileNotFoundError:
        return None
    with _geo_lock:
        if _asn_reader is None or m != _asn_mtime:
            try:
                import geoip2.database  # lazy import
                try:
                    _asn_reader and _asn_reader.close()
                except Exception:
                    pass
                _asn_reader = geoip2.database.Reader(p)
                _asn_mtime = m
                logging.info(f"Loaded ASN DB: {p} (mtime={m})")
            except Exception as e:
                logging.warning(f"ASN DB load failed: {e}")
                _asn_reader = None
    return _asn_reader

# Optional: auch private IPs geolokalisieren (nur für Tests sinnvoll)
GEO_ALLOW_PRIVATE = _env_bool("PW_GEO_ALLOW_PRIVATE", False)

def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def _ip_ok_for_geo(ip: str) -> bool:
    return _is_public_ip(ip) or GEO_ALLOW_PRIVATE

def geo_lookup_offline(ip: str):
    if not _ip_ok_for_geo(ip):
        return {}
    out = {}
    try:
        cr = _get_city_reader()
        if cr:
            r = cr.city(ip)
            out["country"] = (r.country.name or "") if r.country else ""
            out["country_iso"] = (r.country.iso_code or "") if r.country else ""
            out["region"] = (r.subdivisions[0].name or "") if (r.subdivisions and len(r.subdivisions) > 0) else ""
            out["city"] = (r.city.name or "") if r.city else ""
            out["zip"] = (r.postal.code or "") if r.postal else ""
            if r.location:
                out["lat"] = r.location.latitude
                out["lon"] = r.location.longitude
    except Exception:
        pass
    try:
        ar = _get_asn_reader()
        if ar:
            r = ar.asn(ip)
            if getattr(r, "autonomous_system_organization", None):
                out["org"] = r.autonomous_system_organization or ""
                out.setdefault("isp", out["org"])
    except Exception:
        pass
    return out

# ========== Geo ONLINE (Fallback) ==========
IPAPI_ENABLE   = _env_bool("PW_IPAPI_ENABLE", False)  # Default: aus (offline-first)
IPAPI_ENDPOINT = _env_raw("PW_IPAPI_ENDPOINT", "http://ip-api.com/json/") or "http://ip-api.com/json/"
IPAPI_FIELDS   = "status,message,country,countryCode,regionName,city,zip,lat,lon,isp,org,query"
IPAPI_BUDGET_PER_MIN = _env_int("PW_IPAPI_BUDGET_PER_MIN", 40)
_last_window = int(time.time() // 60)
_calls_this_window = 0

@lru_cache(maxsize=_env_int("PW_CACHE_SIZE", 20000))
def geo_lookup_online(ip: str):
    global _last_window, _calls_this_window
    if not (IPAPI_ENABLE and _ip_ok_for_geo(ip)):
        return {}
    now_window = int(time.time() // 60)
    if now_window != _last_window:
        _last_window = now_window
        _calls_this_window = 0
    if _calls_this_window >= IPAPI_BUDGET_PER_MIN:
        return {}
    try:
        req = Request(f"{IPAPI_ENDPOINT}{ip}?fields={IPAPI_FIELDS}", headers={"User-Agent": "portwatcher"})
        with urlopen(req, timeout=2) as resp:
            _calls_this_window += 1
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") != "success":
            return {}
        return {
            "country": data.get("country") or "",
            "country_iso": data.get("countryCode") or "",
            "region": data.get("regionName") or "",
            "city": data.get("city") or "",
            "zip": data.get("zip") or "",
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "org": data.get("org") or "",
            "isp": data.get("isp") or "",
        }
    except URLError:
        return {}
    except Exception:
        return {}

def enrich_ip(ip: str):
    off = geo_lookup_offline(ip)
    if IPAPI_ENABLE:
        on = geo_lookup_online(ip)
        merged = dict(off)
        for k, v in on.items():
            if not merged.get(k) and v not in (None, ""):
                merged[k] = v
        return merged
    return off

# ========== rDNS ==========
RDNS_ENABLE  = _env_bool("PW_RDNS_ENABLE", True)
RDNS_TIMEOUT = _env_float("PW_RDNS_TIMEOUT", 1.0)

async def reverse_dns(ip: str, timeout: float = RDNS_TIMEOUT) -> str:
    if not (RDNS_ENABLE and _ip_ok_for_geo(ip)):
        return ""
    try:
        host = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=timeout)
        return host[0] if host and host[0] else ""
    except Exception:
        return ""

# ========== Rate-Limit pro IP (Cooldown) ==========
RL_COOLDOWN_S = _env_int("PW_RL_COOLDOWN_S", 1800)  # 30 min
RL_FORGET_S   = _env_int("PW_RL_FORGET_S", 86400)   # 24h
_rl_state = {}  # ip -> {"last_sent": ts, "suppressed": n, "last_seen": ts}
_rl_lock = asyncio.Lock()
_rl_last_cleanup = 0.0

async def _rl_allow(ip: str):
    """Cooldown je IP. Liefert (allowed: bool, suppressed_count: int)."""
    now = time.time()
    async with _rl_lock:
        # gelegentlich alte Einträge aufräumen
        global _rl_last_cleanup
        if now - _rl_last_cleanup > 300:
            for k, st in list(_rl_state.items()):
                if now - st.get("last_seen", now) > RL_FORGET_S:
                    _rl_state.pop(k, None)
            _rl_last_cleanup = now

        st = _rl_state.get(ip)
        if not st:
            st = {"last_sent": 0.0, "suppressed": 0, "last_seen": now}
            _rl_state[ip] = st
        st["last_seen"] = now
        if (now - st["last_sent"]) < RL_COOLDOWN_S:
            st["suppressed"] += 1
            return False, st["suppressed"]
        suppressed = st["suppressed"]
        st["suppressed"] = 0
        st["last_sent"] = now
        return True, suppressed

# ========== Payload capture / classification ==========
CAPTURE_PAYLOAD   = _env_bool("PW_CAPTURE_PAYLOAD", True)
PROBE_MAX_BYTES   = _env_int("PW_PROBE_MAX_BYTES", 2048)
PROBE_TIMEOUT_MS  = _env_int("PW_PROBE_TIMEOUT_MS", 800)
TLS_JA3_ENABLE    = _env_bool("PW_TLS_JA3", False)

PAYLOAD_IN_NOTIF   = _env_bool("PW_PAYLOAD_IN_NOTIF", True)
PAYLOAD_MAX_CHARS  = _env_int("PW_PAYLOAD_MAX_CHARS", 600)
PAYLOAD_MODE       = (_env_raw("PW_PAYLOAD_MODE", "auto") or "auto").lower()  # auto|text|hex|base64
PAYLOAD_STRIP_CTRL = _env_bool("PW_PAYLOAD_STRIP_CONTROL", True)

_PRINTABLE = set(string.printable) - set("\x0b\x0c")

def _bytes_as_text(buf: bytes) -> str:
    s = buf.decode("utf-8", "replace")
    if PAYLOAD_STRIP_CTRL:
        out = []
        for ch in s:
            o = ord(ch)
            if ch in ("\r", "\n", "\t"):
                out.append(ch)
            elif o < 32 or o == 127:
                out.append(".")
            else:
                out.append(ch)
        s = "".join(out)
    return s

def _payload_to_str(buf: bytes) -> tuple[str, str, int]:
    total = len(buf)
    mode = PAYLOAD_MODE
    if mode == "auto":
        nul = buf.count(0)
        try:
            s_try = buf.decode("utf-8")
            printable_ratio = sum(ch in _PRINTABLE for ch in s_try) / max(1, len(s_try))
            auto_text = (nul == 0 and printable_ratio >= 0.85)
        except Exception:
            auto_text = False
        mode = "text" if auto_text else "hex"
    if mode == "text":
        s = _bytes_as_text(buf)
    elif mode == "base64":
        s = base64.b64encode(buf).decode("ascii")
    else:  # hex
        max_hex = min(total, 2048)
        s = buf[:max_hex].hex(" ")
        if total > max_hex:
            s += f"  … (+{total-max_hex}B)"
    if len(s) > PAYLOAD_MAX_CHARS:
        s = s[:PAYLOAD_MAX_CHARS] + f" … (+{len(s)-PAYLOAD_MAX_CHARS} chars)"
    return s, mode, total

def _parse_tls_client_hello(buf: bytes) -> dict:
    out = {}
    try:
        if len(buf) < 5 or buf[0] != 0x16 or buf[1] != 0x03:
            return out
        rec_len = (buf[3] << 8) | buf[4]
        if 5 + rec_len > len(buf):
            rec_len = len(buf) - 5
        p = 5
        if buf[p] != 0x01:
            return out
        hs_len = (buf[p+1] << 16) | (buf[p+2] << 8) | buf[p+3]
        p += 4
        if p + 2 > len(buf): return out
        ver = (buf[p] << 8) | buf[p+1]; p += 2
        p += 32
        if p >= len(buf): return out
        sid_len = buf[p]; p += 1 + sid_len
        if p + 2 > len(buf): return out
        cs_len = (buf[p] << 8) | buf[p+1]; p += 2
        ciphers = []
        for i in range(0, min(cs_len, max(0, len(buf)-p)), 2):
            ciphers.append((buf[p+i] << 8) | buf[p+i+1])
        p += cs_len
        if p >= len(buf): return out
        comp_len = buf[p]; p += 1 + comp_len
        if p + 2 > len(buf): return out
        ext_total = (buf[p] << 8) | buf[p+1]; p += 2
        exts = []
        alpn = []
        curves = []
        ecpt  = []
        sni = None
        end = min(len(buf), p + ext_total)
        while p + 4 <= end:
            et = (buf[p] << 8) | buf[p+1]
            el = (buf[p+2] << 8) | buf[p+3]
            p += 4
            ev_end = min(end, p + el)
            exts.append(et)
            if et == 0x00:  # server_name
                pp = p + 2 if p + 2 <= ev_end else ev_end
                while pp + 3 <= ev_end:
                    nt = buf[pp]; ln = (buf[pp+1] << 8) | buf[pp+2]; pp += 3
                    if nt == 0 and pp + ln <= ev_end:
                        try:
                            sni = buf[pp:pp+ln].decode("idna", "ignore")
                        except Exception:
                            sni = None
                        break
                    pp += ln
            elif et == 0x10:  # ALPN
                pp = p + 2 if p + 2 <= ev_end else ev_end
                while pp < ev_end:
                    if pp >= ev_end: break
                    ln = buf[pp]; pp += 1
                    if pp + ln <= ev_end:
                        try:
                            alpn.append(buf[pp:pp+ln].decode("ascii", "ignore"))
                        except Exception:
                            pass
                    pp += ln
            elif et in (0x0a, 0x000a):  # supported_groups
                pp = p + 2 if p + 2 <= ev_end else ev_end
                while pp + 1 < ev_end:
                    curves.append((buf[pp] << 8) | buf[pp+1]); pp += 2
            elif et == 0x0b:  # ec_point_formats
                pp = p + 1 if p + 1 <= ev_end else ev_end
                while pp < ev_end:
                    ecpt.append(buf[pp]); pp += 1
            p = ev_end
        out["tls_version"] = ver
        if sni: out["tls_sni"] = sni
        if alpn: out["tls_alpn"] = ",".join(alpn)
        if TLS_JA3_ENABLE:
            ver_s = str(ver)
            ciph_s = "-".join(str(x) for x in ciphers) if ciphers else ""
            ext_s  = "-".join(str(x) for x in exts) if exts else ""
            grp_s  = "-".join(str(x) for x in curves) if curves else ""
            ecp_s  = "-".join(str(x) for x in ecpt) if ecpt else ""
            ja3_str = ",".join([ver_s, ciph_s, ext_s, grp_s, ecp_s])
            out["tls_ja3"] = hashlib.md5(ja3_str.encode("ascii", "ignore")).hexdigest()
        return out
    except Exception:
        return out

def _classify_probe(buf: bytes) -> dict:
    res = {"kind": "none", "bytes": len(buf)}
    if not buf:
        return res
    try:
        if buf.startswith(b"SSH-"):
            res["kind"] = "ssh"
            try:
                res["ssh_ident"] = buf.decode("latin1", "ignore").splitlines()[0][:80]
            except Exception:
                pass
            return res
        if len(buf) >= 5 and buf[0] == 0x16 and buf[1] == 0x03:
            info = _parse_tls_client_hello(buf)
            res["kind"] = "tls"
            res.update(info)
            return res
        txt = buf.decode("latin1", "ignore")
        if any(txt.startswith(m) for m in ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "TRACE ", "PATCH ", "PRI * HTTP/2.0")):
            res["kind"] = "http"
            line0 = txt.split("\r\n", 1)[0]
            res["http_request"] = line0[:120]
            host = ua = ""
            for line in txt.split("\r\n"):
                if not host and line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                elif not ua and line.lower().startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()
            if host: res["http_host"] = host
            if ua:   res["http_ua"] = ua[:140]
            return res
        if buf.startswith(b"RFB "):
            res["kind"] = "vnc"
            return res
        if len(buf) >= 7 and buf[0] == 0x03 and buf[1] == 0x00 and buf[5] == 0x02 and buf[6] == 0xF0:
            res["kind"] = "rdp"
            return res
        if buf[:1] in (b"*", b"+", b"-", b":", b"$"):
            res["kind"] = "redis-like"
            return res
        res["kind"] = "other"
        return res
    except Exception:
        return res

# ========== Versand: E-Mail & ntfy ==========
async def send_email_async(subject: str, body: str):
    if not ENABLE_EMAIL or not (SMTP_SERVER and MAIL_FROM and MAIL_TO):
        return
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = MAIL_TO
    msg["Subject"] = subject
    msg.set_content(body)
    def _send():
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as s:
            if SMTP_STARTTLS:
                s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    await asyncio.to_thread(_send)

async def send_push_async(title: str, body: str):
    if not ENABLE_PUSH or not NTFY_TOPIC:
        return
    url = f"{NTFY_SERVER}/{NTFY_TOPIC}"
    headers = {
        "Title": title[:250],
        "Priority": str(NTFY_PRIO),
        "Tags": NTFY_TAGS,
    }
    req = urllib.request.Request(url, method="POST", data=body.encode("utf-8"), headers=headers)
    await asyncio.to_thread(urllib.request.urlopen, req, None, 10)

# ========== Server/Handler ==========
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
sem = asyncio.Semaphore(MAX_CONCURRENCY)

def _parse_addrinfo(info):
    if not isinstance(info, tuple):
        return "?", "?"
    ip = info[0]
    port = info[1] if len(info) >= 2 else "?"
    return ip, port

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    async with sem:
        peer = writer.get_extra_info("peername")
        local = writer.get_extra_info("sockname")

        peer_ip, peer_port = _parse_addrinfo(peer)
        local_ip, local_port = _parse_addrinfo(local)

        ts_local = now_local_iso()
        ts_utc   = now_utc_iso()

        suppress = _notify_suppress(peer_ip) if isinstance(peer_ip, str) else False
        if not (LOG_IGNORE_SUPPRESSED and suppress):
            logging.info(f"TCP connect {peer_ip}:{peer_port} -> {local_ip}:{local_port} at {ts_local}")

        # --- Probe lesen & klassifizieren (ohne die Gegenseite aktiv anzutriggern)
        probe = b""; probe_ms = 0; proto = {}
        if CAPTURE_PAYLOAD:
            try:
                t0 = time.monotonic()
                probe = await asyncio.wait_for(reader.read(PROBE_MAX_BYTES), PROBE_TIMEOUT_MS / 1000)
                probe_ms = int((time.monotonic() - t0) * 1000)
                proto = _classify_probe(probe)
            except Exception:
                pass

        # Optional Banner (erst nach dem Lesen)
        try:
            if BANNER:
                writer.write(BANNER.encode("utf-8", "ignore"))
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        # Benachrichtigungen für ignorierte Quellen komplett unterdrücken
        if suppress:
            return

        # Rate-Limit (gemeinsam für Mail & Push)
        try:
            ip_key = peer_ip if isinstance(peer_ip, str) else "?"
            allowed, suppressed = await _rl_allow(ip_key)
            if not allowed:
                return

            # rDNS/Geo
            rdns = await reverse_dns(peer_ip) if isinstance(peer_ip, str) else ""
            geo = enrich_ip(peer_ip) if isinstance(peer_ip, str) else {}

            # Subject/Title: "DE Heidelberg 78.43.247.28"
            country_iso = (geo.get("country_iso") or "").upper()
            location = geo.get("city") or geo.get("region") or geo.get("country") or ""
            subject = " ".join(x for x in [country_iso, location, peer_ip] if x)

            # Für Body
            country_line = ""
            if geo.get("country_iso") or geo.get("country"):
                country_line = f"{geo.get('country_iso','')}".strip()
                if geo.get("country"):
                    country_line = (country_line + " / " if country_line else "") + geo["country"]

            INCLUDE_CITY = _env_bool("PW_INCLUDE_CITY", True)
            INCLUDE_COORDS = _env_bool("PW_INCLUDE_COORDS", False)
            LATLON_PRECISION = _env_int("PW_LATLON_PRECISION", 2)

            city_line = ""
            if INCLUDE_CITY:
                city_line = geo.get("city") or ""
                if geo.get("region"):
                    city_line = (city_line + ", " if city_line else "") + geo["region"]
                if geo.get("zip"):
                    city_line = (city_line + " " if city_line else "") + geo["zip"]

            coord_line = ""
            if INCLUDE_COORDS and isinstance(geo.get("lat"), (int, float)) and isinstance(geo.get("lon"), (int, float)):
                lat = round(float(geo["lat"]), LATLON_PRECISION)
                lon = round(float(geo["lon"]), LATLON_PRECISION)
                coord_line = f"{lat}, {lon}"

            body_lines = [
                f"Timestamp: {ts_local}",
                f"Peer IP: {peer_ip}",
                f"Port: {peer_port}",
                f"rDNS: {rdns or '-'}",
                f"Country: {country_line or '-'}",
            ]
            if INCLUDE_CITY:
                body_lines.append(f"City/Region: {city_line or '-'}")
            if coord_line:
                body_lines.append(f"Coords (approx): {coord_line}")

            # Zusatzinfos zur ersten Payload/Erkennung
            body_lines.append(f"BytesIn/Probe: {proto.get('bytes', 0)} in {probe_ms}ms")
            if proto.get("kind") and proto["kind"] != "none":
                body_lines.append(f"Detected: {proto['kind']}")
            if proto.get("http_request"):
                body_lines.append(f"HTTP: {proto['http_request']}")
            if proto.get("http_host"):
                body_lines.append(f"Host: {proto['http_host']}")
            if proto.get("http_ua"):
                body_lines.append(f"User-Agent: {proto['http_ua']}")
            if proto.get("tls_sni"):
                body_lines.append(f"SNI: {proto['tls_sni']}")
            if proto.get("tls_alpn"):
                body_lines.append(f"ALPN: {proto['tls_alpn']}")

            # rohe Payload (kompakt)
            if PAYLOAD_IN_NOTIF and probe:
                ptxt, pmode, plen = _payload_to_str(probe)
                body_lines.append(f"Payload ({pmode}, {plen}B):")
                body_lines.append(ptxt)

            body_lines += [
                f"Org: {geo.get('org') or '-'}",
                f"Provider: {geo.get('isp') or '-'}",
                f"Local: {local_ip}:{local_port}",
            ]
            if PW_TS_INCLUDE_UTC:
                body_lines.insert(1, f"Timestamp (UTC): {ts_utc}")
            if suppressed:
                body_lines.append(f"Suppressed (since last notify for this IP): {suppressed}")

            body = "\n".join(body_lines)

            # Versand
            try:
                await send_email_async(subject, body)
            except Exception as e:
                logging.warning(f"E-Mail-Versand fehlgeschlagen: {e}")
            try:
                await send_push_async(subject, body)
            except Exception as e:
                logging.warning(f"ntfy-Push fehlgeschlagen: {e}")

        except Exception as e:
            logging.warning(f"Benachrichtigung/RL fehlgeschlagen: {e}")

async def main():
    family = socket.AF_INET6 if ":" in (HOST or "") else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_REUSEPORT", 15), 1)
    except Exception:
        pass
    sock.bind((HOST, PORT))
    sock.listen(512)
    sock.setblocking(False)

    server = await asyncio.start_server(handle_client, sock=sock)
    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
    logging.info(f"portwatcher listening on {addr} (max_concurrency={MAX_CONCURRENCY})")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
