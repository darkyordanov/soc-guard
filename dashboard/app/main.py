#!/usr/bin/env python3
"""
SOC-Guard Dashboard — FastAPI read/ack view over the collector's SQLite DB.

Binds to 127.0.0.1 only; reach it over an SSH tunnel (see README). It never
opens a public port. It reads events/alerts and can only toggle the
`acknowledged` column on an alert — no other writes.

Config from env (same file style as the collector):
  SOC_DB_PATH        path to soc.db  (default /opt/soc/data/soc.db)
  DASH_HOST          bind host        (default 127.0.0.1)
  DASH_PORT          bind port        (default 8899)
  SOC_SITE_URL       site to show health for (optional)
  SOC_GEOIP_CITY_DB  GeoLite2 City .mmdb (optional, enables geo columns)
  SOC_GEOIP_ASN_DB   GeoLite2 ASN .mmdb  (optional)
"""
import os
import sys
import sqlite3
import urllib.request
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DB_PATH = os.environ.get("SOC_DB_PATH", "/opt/soc/data/soc.db")
SITE_URL = os.environ.get("SOC_SITE_URL", "")
BASE = os.path.dirname(os.path.abspath(__file__))

# GeoIP: reuse the collector's stdlib mmdb reader if it's importable and the
# databases are configured. Entirely optional — the dashboard degrades to '—'.
GEOIP_CITY_DB = os.environ.get("SOC_GEOIP_CITY_DB", "/var/lib/GeoIP/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.environ.get("SOC_GEOIP_ASN_DB", "/var/lib/GeoIP/GeoLite2-ASN.mmdb")
# allow importing mmdb.py from the collector's install dir if it's on the path
for p in ("/opt/soc/app", "/opt/soc-guard", os.path.join(BASE, "..", "..")):
    if os.path.isdir(p) and p not in sys.path:
        sys.path.append(p)
try:
    import mmdb
except Exception:
    mmdb = None

_geo_cache = {}


def geo_lookup(ip):
    """Return {'country':cc,'city':name,'asn':'ASxxx Org'} for a public IP."""
    if not (mmdb and ip):
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]
    out = {}
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        if a.is_private or a.is_loopback or a.is_reserved or a.is_link_local:
            _geo_cache[ip] = {}
            return {}
        if os.path.exists(GEOIP_CITY_DB):
            rec = mmdb.reader(GEOIP_CITY_DB).get(ip)
            if rec:
                out["country"] = (rec.get("country") or {}).get("iso_code")
                out["city"] = ((rec.get("city") or {}).get("names") or {}).get("en")
        if os.path.exists(GEOIP_ASN_DB):
            arec = mmdb.reader(GEOIP_ASN_DB).get(ip)
            if arec:
                asn = arec.get("autonomous_system_number")
                org = arec.get("autonomous_system_organization")
                if asn:
                    out["asn"] = f"AS{asn}" + (f" {org}" if org else "")
    except Exception:
        out = {}
    _geo_cache[ip] = out
    return out


app = FastAPI(title="SOC-Guard Dashboard", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE, "templates"))

SEV_ORDER = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END"


def db():
    # read-only-ish connection; we only ever UPDATE alerts.acknowledged
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def rows(sql, params=()):
    with db() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def one(sql, params=()):
    with db() as c:
        r = c.execute(sql, params).fetchone()
        return r[0] if r else 0


# -------------------------------------------------------------- pages
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# -------------------------------------------------------------- API (JSON)
@app.get("/api/summary")
def api_summary():
    since24 = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    health = "unknown"
    if SITE_URL:
        try:
            req = urllib.request.Request(SITE_URL, headers={"User-Agent": "soc-dash"})
            code = urllib.request.urlopen(req, timeout=8).getcode()
            health = "up" if 200 <= code < 400 else f"warn:{code}"
        except Exception:
            health = "down"
    return {
        "health": health,
        "site": SITE_URL,
        "geoip": bool(mmdb and os.path.exists(GEOIP_CITY_DB)),
        "events_24h": one("SELECT COUNT(*) FROM events WHERE source='nginx' AND ts>=?", (since24,))
                      or one("SELECT COUNT(*) FROM events WHERE source='web' AND ts>=?", (since24,)),
        "unique_ips_24h": one("SELECT COUNT(DISTINCT ip) FROM events WHERE ts>=?", (since24,)),
        "alerts_open": one("SELECT COUNT(*) FROM alerts WHERE acknowledged=0"),
        "crit_24h": one("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND ts>=?", (since24,)),
        "high_24h": one("SELECT COUNT(*) FROM alerts WHERE severity='HIGH' AND ts>=?", (since24,)),
        "med_24h": one("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM' AND ts>=?", (since24,)),
    }


@app.get("/api/alerts")
def api_alerts(limit: int = 50, show: str = "open"):
    where = "WHERE acknowledged=0" if show == "open" else ""
    limit = max(1, min(limit, 200))
    data = rows(
        f"SELECT id,ts,rule,severity,ip,summary,detail,mitre,acknowledged "
        f"FROM alerts {where} ORDER BY {SEV_ORDER}, id DESC LIMIT ?", (limit,))
    # enrich each alert's IP with country/city/ASN (cached, best-effort)
    for a in data:
        g = geo_lookup(a.get("ip")) if a.get("ip") else {}
        loc = ", ".join(x for x in (g.get("city"), g.get("country")) if x)
        a["geo"] = loc
        a["country"] = g.get("country") or ""
        a["asn"] = g.get("asn") or ""
    return data


@app.post("/api/alerts/{alert_id}/ack")
def api_ack(alert_id: int):
    with db() as c:
        cur = c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "alert not found")
    return {"ok": True, "id": alert_id}


@app.get("/api/traffic")
def api_traffic():
    # requests per hour, last 24h
    data = rows(
        "SELECT substr(ts,1,13) h, COUNT(*) c FROM events "
        "WHERE ts>=? GROUP BY h ORDER BY h",
        ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds"),))
    return {"labels": [d["h"][11:13] + "h" for d in data], "values": [d["c"] for d in data]}


@app.get("/api/severity")
def api_severity():
    data = rows("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    data.sort(key=lambda d: order.get(d["severity"], 9))
    return {"labels": [d["severity"] for d in data], "values": [d["c"] for d in data]}


@app.get("/api/top-ips")
def api_top_ips():
    data = rows(
        "SELECT ip, COUNT(*) c FROM events WHERE status IN (404,403) AND ip IS NOT NULL "
        "GROUP BY ip ORDER BY c DESC LIMIT 10")
    return {"labels": [d["ip"] for d in data], "values": [d["c"] for d in data]}


@app.get("/api/top-countries")
def api_top_countries():
    """Group the top offending IPs (404/403) by GeoIP country. Empty if GeoIP off."""
    if not (mmdb and os.path.exists(GEOIP_CITY_DB)):
        return {"labels": [], "values": [], "enabled": False}
    data = rows(
        "SELECT ip, COUNT(*) c FROM events WHERE status IN (404,403) AND ip IS NOT NULL "
        "GROUP BY ip ORDER BY c DESC LIMIT 200")
    tally = {}
    for d in data:
        cc = geo_lookup(d["ip"]).get("country") or "??"
        tally[cc] = tally.get(cc, 0) + d["c"]
    top = sorted(tally.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {"labels": [k for k, _ in top], "values": [v for _, v in top], "enabled": True}


@app.get("/api/events")
def api_events(q: str = "", limit: int = 50):
    limit = max(1, min(limit, 200))
    if q:
        like = f"%{q}%"
        return rows(
            "SELECT ts,source,ip,method,path,status,rt FROM events "
            "WHERE ip LIKE ? OR path LIKE ? OR CAST(status AS TEXT) LIKE ? "
            "ORDER BY id DESC LIMIT ?", (like, like, like, limit))
    return rows("SELECT ts,source,ip,method,path,status,rt FROM events ORDER BY id DESC LIMIT ?", (limit,))


@app.get("/healthz")
def healthz():
    try:
        one("SELECT 1")
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
