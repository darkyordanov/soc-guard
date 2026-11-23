#!/usr/bin/env python3
"""
SOC-Guard - a self-hosted SIEM-lite for a single Linux web server.

Tails a web-server access log and the SSH journal, applies detection rules
mapped to MITRE ATT&CK, stores events/alerts in SQLite, and pushes
CRITICAL/HIGH alerts to Telegram in real time. A built-in health check raises
SITE_DOWN; a companion heartbeat script + daily report complete the pipeline.

Design goals: zero external dependencies (Python 3 stdlib only), runs as an
unprivileged user, fully configured through an env file - no code edits to
deploy on a new host.

Config: all paths, thresholds, and secrets come from the env file
(default /etc/soc-guard/soc-guard.env, override with SOC_GUARD_ENV).
See soc-guard.env.example and docs/INSTALL.md.

License: MIT
"""
import glob as globmod
import hashlib
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timezone

try:
    import mmdb  # local stdlib MaxMind DB reader (ships alongside this file)
except Exception:
    mmdb = None

# ---------------------------------------------------------------- config load
ENV_PATH = os.environ.get("SOC_GUARD_ENV", "/etc/soc-guard/soc-guard.env")


def load_env(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    except OSError:
        pass
    # real environment variables override (and may add to) file values, so the
    # collector also works with no env file at all - e.g. systemd Environment=
    # or a container passing SOC_* vars directly.
    for k, v in os.environ.items():
        if k.startswith("SOC_"):
            env[k] = v
    return env


ENV = load_env(ENV_PATH)


def cfg(key, default=None):
    return ENV.get(key, default)


def cfg_int(key, default):
    try:
        return int(ENV.get(key, default))
    except (ValueError, TypeError):
        return default


# core
DB_PATH = cfg("SOC_DB_PATH", "/var/lib/soc-guard/soc.db")
ACCESS_LOG = cfg("SOC_ACCESS_LOG", "/var/log/nginx/access.log")
SSH_UNIT = cfg("SOC_SSH_UNIT", "ssh")           # 'ssh' (Debian/Ubuntu) or 'sshd' (RHEL)
SITE_URL = cfg("SOC_SITE_URL", "https://example.com")
ALLOWED_SSH = set(u.strip() for u in cfg("SOC_ALLOWED_SSH_USERS", "root").split(",") if u.strip())

# telegram
TG_TOKEN = cfg("SOC_TG_TOKEN", "")
TG_CHAT = cfg("SOC_TG_CHAT", "")

# thresholds (all overridable from env)
BRUTE_WINDOW = cfg_int("SOC_BRUTE_WINDOW", 300)
BRUTE_LIMIT = cfg_int("SOC_BRUTE_LIMIT", 10)
SCAN_WINDOW = cfg_int("SOC_SCAN_WINDOW", 60)
SCAN_404_LIMIT = cfg_int("SOC_SCAN_404_LIMIT", 15)
FIVEXX_WINDOW = cfg_int("SOC_5XX_WINDOW", 300)
FIVEXX_LIMIT = cfg_int("SOC_5XX_LIMIT", 5)
HEALTH_INTERVAL = cfg_int("SOC_HEALTH_INTERVAL", 60)
HEALTH_FAILS = cfg_int("SOC_HEALTH_FAILS", 3)
COOLDOWN = cfg_int("SOC_ALERT_COOLDOWN", 600)

# suspicious request paths (credential / config / admin probing)
SCANNER_PATHS = re.compile(
    cfg("SOC_SCANNER_REGEX",
        r"/\.(env|git|aws|ssh)|/wp-(admin|login|content)|/phpmyadmin"
        r"|/\.well-known/(?!acme)|/api/|/actuator|/vendor/|/\.vscode|/config\."
        r"|/owa/|/autodiscover"),
    re.I,
)

# SQLi / XSS / traversal / command-injection probe signatures, matched against
# the URL-decoded request URI (bots url-encode their payloads).
EXPLOIT_SIG = re.compile(
    cfg("SOC_EXPLOIT_REGEX",
        r"union\s+select|select.+from|insert\s+into|drop\s+table"
        r"|'\s*or\s+'?1'?\s*=\s*'?1|\bor\s+1=1|sleep\s*\(|benchmark\s*\("
        r"|information_schema"                                            # SQLi
        r"|<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+src\s*="   # XSS
        r"|\.\./\.\.|\.\.%2f|%2e%2e%2f|/etc/passwd|/proc/self"            # traversal/LFI
        r"|;\s*(cat|wget|curl|bash|sh)\s|\|\s*(cat|wget|curl|bash|sh)\s"),  # cmd-inj
    re.I,
)

# ---- File Integrity Monitoring (hash-based, portable - no git required) ----
FIM_ENABLED = cfg("SOC_FIM_ENABLED", "0") == "1"
# comma-separated list of files and/or shell globs, e.g.
#   /etc/nginx/nginx.conf, /var/www/html/*.php, /etc/ssh/sshd_config
FIM_PATHS = [p.strip() for p in cfg("SOC_FIM_PATHS", "").split(",") if p.strip()]
FIM_INTERVAL = cfg_int("SOC_FIM_INTERVAL", 300)

# ---- GeoIP enrichment (MaxMind GeoLite2 .mmdb; optional) ----
GEOIP_ENABLED = cfg("SOC_GEOIP_ENABLED", "0") == "1"
GEOIP_CITY_DB = cfg("SOC_GEOIP_CITY_DB", "/var/lib/GeoIP/GeoLite2-City.mmdb")
GEOIP_ASN_DB = cfg("SOC_GEOIP_ASN_DB", "/var/lib/GeoIP/GeoLite2-ASN.mmdb")

# ---------------------------------------------------------------- db
DDL = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, source TEXT, ip TEXT, user TEXT,
    method TEXT, path TEXT, status INTEGER, rt REAL, ua TEXT, raw TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, rule TEXT, severity TEXT, ip TEXT,
    summary TEXT, detail TEXT, mitre TEXT, acknowledged INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS fim_baseline (
    path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, updated TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""

db_lock = threading.Lock()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as conn:
        conn.executescript(DDL)


def save_event(**k):
    with db_lock, db() as conn:
        conn.execute(
            "INSERT INTO events(ts,source,ip,user,method,path,status,rt,ua,raw)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (k.get("ts"), k.get("source"), k.get("ip"), k.get("user"),
             k.get("method"), k.get("path"), k.get("status"), k.get("rt"),
             k.get("ua"), k.get("raw")),
        )


_last_alert = {}


def alert(rule, severity, ip, summary, detail="", mitre=""):
    """Record an alert, de-duplicating per (rule, ip) within COOLDOWN."""
    key = (rule, ip or "")
    now = time.time()
    if now - _last_alert.get(key, 0) < COOLDOWN:
        return
    _last_alert[key] = now
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db_lock, db() as conn:
        conn.execute(
            "INSERT INTO alerts(ts,rule,severity,ip,summary,detail,mitre)"
            " VALUES(?,?,?,?,?,?,?)",
            (ts, rule, severity, ip, summary, detail, mitre),
        )
    if severity in ("CRITICAL", "HIGH"):
        send_telegram(rule, severity, ip, summary, detail, mitre)
    print(f"[{severity}] {rule} ip={ip} {summary}", flush=True)


EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}

# cache per-IP enrichment so repeat offenders don't re-hit the DB every alert
_geo_cache = {}


def geo_enrich(ip):
    """Return 'City, CC · ASxxx Org' for a public IP, or '' on miss/private.

    Best-effort: never raises, so enrichment can't break alerting if a DB is
    missing or an address is malformed.
    """
    if not (GEOIP_ENABLED and mmdb and ip):
        return ""
    if ip in _geo_cache:
        return _geo_cache[ip]
    out = ""
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        if a.is_private or a.is_loopback or a.is_reserved or a.is_link_local:
            _geo_cache[ip] = ""
            return ""
        parts = []
        if os.path.exists(GEOIP_CITY_DB):
            rec = mmdb.reader(GEOIP_CITY_DB).get(ip)
            if rec:
                country = (rec.get("country") or {}).get("iso_code")
                city = ((rec.get("city") or {}).get("names") or {}).get("en")
                loc = ", ".join(x for x in (city, country) if x)
                if loc:
                    parts.append(loc)
        if os.path.exists(GEOIP_ASN_DB):
            arec = mmdb.reader(GEOIP_ASN_DB).get(ip)
            if arec:
                asn = arec.get("autonomous_system_number")
                org = arec.get("autonomous_system_organization")
                if asn:
                    parts.append(f"AS{asn}" + (f" {org}" if org else ""))
        out = " · ".join(parts)
    except Exception as e:
        print(f"geoip error for {ip}: {e}", flush=True)
        out = ""
    _geo_cache[ip] = out
    return out


def send_telegram(rule, severity, ip, summary, detail, mitre):
    if not TG_TOKEN or not TG_CHAT:
        return
    lines = [f"{EMOJI.get(severity,'')} <b>{severity}</b> — {rule}",
             f"<b>{summary}</b>"]
    if ip:
        lines.append(f"Source IP: <code>{ip}</code>")
        geo = geo_enrich(ip)
        if geo:
            lines.append(f"🌍 {geo}")
    if detail:
        lines.append(detail)
    if mitre:
        lines.append(f"MITRE ATT&CK: {mitre}")
    lines.append(f"🕒 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    text = "\n".join(lines)
    data = urllib.parse.urlencode(
        {"chat_id": TG_CHAT, "text": text, "parse_mode": "HTML",
         "disable_web_page_preview": "true"}
    ).encode()
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10).read()
    except Exception as e:
        print(f"telegram error: {e}", flush=True)

# ---------------------------------------------------------------- tail helper
def tail_follow(path):
    """Yield new lines from a growing file, surviving truncation/rotation."""
    while not os.path.exists(path):
        time.sleep(2)
    f = open(path, errors="replace")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line.rstrip("\n")
            continue
        time.sleep(0.5)
        try:
            if os.stat(path).st_ino != inode or os.stat(path).st_size < f.tell():
                f.close()
                f = open(path, errors="replace")
                inode = os.fstat(f.fileno()).st_ino
        except OSError:
            time.sleep(2)

# ---------------------------------------------------------------- web rules
# Matches the common/combined nginx & apache access log format. The optional
# rt= suffix (nginx $request_time) is parsed when present.
WEB_RE = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"(?:.*?\brt=(?P<rt>\S+))?'
)

win_404 = defaultdict(deque)   # ip -> deque of timestamps
win_5xx = deque()              # site-wide 5xx timestamps


def process_web(line):
    m = WEB_RE.search(line)
    if not m:
        return
    d = m.groupdict()
    ip = d["ip"]
    status = int(d["status"])
    rt = None
    if d.get("rt"):
        try:
            rt = float(d["rt"])
        except ValueError:
            rt = None
    now = time.time()
    save_event(ts=datetime.now(timezone.utc).isoformat(timespec="seconds"),
               source="web", ip=ip, user=None, method=d["method"],
               path=d["path"][:300], status=status, rt=rt, ua=d["ua"][:200],
               raw=line[:500])

    # URL-decode once for exploit matching (payloads are usually percent-encoded)
    try:
        decoded = urllib.parse.unquote(d["path"])
    except Exception:
        decoded = d["path"]

    if EXPLOIT_SIG.search(decoded):
        alert("WEB_EXPLOIT", "HIGH", ip,
              f"Exploit probe: {d['method']} {d['path'][:90]}",
              detail=f"UA: {d['ua'][:70]} · status {status}",
              mitre="T1190 - Exploit Public-Facing Application")

    if SCANNER_PATHS.search(d["path"]):
        alert("WEB_SCANNER_PATH", "MEDIUM", ip,
              f"Suspicious path probe: {d['method']} {d['path'][:80]}",
              detail=f"User-Agent: {d['ua'][:80]}",
              mitre="T1595 - Active Scanning")

    if status == 404:
        q = win_404[ip]
        q.append(now)
        while q and now - q[0] > SCAN_WINDOW:
            q.popleft()
        if len(q) >= SCAN_404_LIMIT:
            alert("WEB_SCANNER_404", "MEDIUM", ip,
                  f"{len(q)} x HTTP 404 in {SCAN_WINDOW}s (enumeration)",
                  detail=f"last path: {d['path'][:80]}",
                  mitre="T1595 - Active Scanning")
            q.clear()

    if 500 <= status < 600:
        win_5xx.append(now)
        while win_5xx and now - win_5xx[0] > FIVEXX_WINDOW:
            win_5xx.popleft()
        if len(win_5xx) >= FIVEXX_LIMIT:
            alert("HTTP_5XX_SPIKE", "HIGH", None,
                  f"{len(win_5xx)} server errors in {FIVEXX_WINDOW}s",
                  detail=f"last: {d['method']} {d['path'][:80]} -> {status}",
                  mitre="T1499 - Endpoint Denial of Service")
            win_5xx.clear()

# ---------------------------------------------------------------- ssh rules
SSH_ACCEPT = re.compile(r"Accepted (\w+) for (\S+) from (\S+)")
SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
SSH_INVALID = re.compile(r"Invalid user (\S+) from (\S+)")

win_ssh_fail = defaultdict(deque)


def process_ssh(line):
    now = time.time()
    m = SSH_ACCEPT.search(line)
    if m:
        method, user, ip = m.group(1), m.group(2), m.group(3)
        save_event(ts=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   source="ssh", ip=ip, user=user, method="LOGIN",
                   path=None, status=None, rt=None, ua=None, raw=line[:500])
        if user not in ALLOWED_SSH:
            alert("SSH_LOGIN_UNEXPECTED", "CRITICAL", ip,
                  f"Successful SSH login as '{user}' (not in allowlist)",
                  detail=f"auth method: {method}",
                  mitre="T1078 - Valid Accounts")
        return
    m = SSH_FAIL.search(line) or SSH_INVALID.search(line)
    if m:
        user, ip = m.group(1), m.group(2)
        q = win_ssh_fail[ip]
        q.append(now)
        while q and now - q[0] > BRUTE_WINDOW:
            q.popleft()
        if len(q) >= BRUTE_LIMIT:
            alert("SSH_BRUTEFORCE", "HIGH", ip,
                  f"{len(q)} failed SSH attempts in {BRUTE_WINDOW}s",
                  detail=f"last target user: {user}",
                  mitre="T1110 - Brute Force")
            q.clear()

# ---------------------------------------------------------------- FIM (hash)
def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _expand_fim_paths():
    """Resolve the configured files/globs to a concrete set of file paths."""
    files = set()
    for pat in FIM_PATHS:
        if any(c in pat for c in "*?["):
            files.update(p for p in globmod.glob(pat, recursive=True)
                         if os.path.isfile(p))
        elif os.path.isfile(pat):
            files.add(pat)
        else:
            # configured path that isn't a file (yet) - track so we can alert if
            # it was expected but is missing against the baseline
            files.add(pat)
    return files


def _load_baseline():
    with db_lock, db() as conn:
        return {r[0]: r[1] for r in conn.execute("SELECT path, sha256 FROM fim_baseline")}


def _store_baseline(path, digest):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db_lock, db() as conn:
        conn.execute(
            "INSERT INTO fim_baseline(path,sha256,updated) VALUES(?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256, updated=excluded.updated",
            (path, digest, ts))


def _delete_baseline(path):
    with db_lock, db() as conn:
        conn.execute("DELETE FROM fim_baseline WHERE path=?", (path,))


def rebaseline():
    """(Re)set the FIM baseline to the current on-disk state, then exit.

    Run this once after a legitimate deploy:  soc_guard.py --rebaseline
    """
    init_db()
    with db_lock, db() as conn:
        conn.execute("DELETE FROM fim_baseline")
    n = 0
    for path in sorted(_expand_fim_paths()):
        digest = _sha256(path)
        if digest:
            _store_baseline(path, digest)
            n += 1
    print(f"FIM baseline reset: {n} file(s) recorded", flush=True)


def fim_worker():
    if not FIM_ENABLED or not FIM_PATHS:
        return
    # seed baseline on first run (empty table) without alerting
    if not _load_baseline():
        for path in sorted(_expand_fim_paths()):
            digest = _sha256(path)
            if digest:
                _store_baseline(path, digest)
        print("FIM: initial baseline recorded", flush=True)

    while True:
        time.sleep(FIM_INTERVAL)
        try:
            baseline = _load_baseline()
            current = _expand_fim_paths()
            seen = set()
            for path in sorted(current):
                digest = _sha256(path)
                seen.add(path)
                old = baseline.get(path)
                if digest is None:
                    # configured path that is not a readable file right now
                    if old is not None:
                        alert("FILE_INTEGRITY_DELETED", "HIGH", None,
                              f"Monitored file missing: {path}",
                              detail="was present in baseline, now unreadable/gone",
                              mitre="T1565.001 - Stored Data Manipulation")
                        _delete_baseline(path)
                    continue
                if old is None:
                    # a new file matched by a glob - strict: alert, then adopt
                    alert("FILE_INTEGRITY_NEW", "MEDIUM", None,
                          f"New file appeared in monitored scope: {path}",
                          detail=f"sha256 {digest[:16]}…",
                          mitre="T1565.001 - Stored Data Manipulation")
                    _store_baseline(path, digest)
                elif digest != old:
                    alert("FILE_INTEGRITY_MODIFIED", "HIGH", None,
                          f"Monitored file changed: {path}",
                          detail=f"{old[:12]}… → {digest[:12]}…",
                          mitre="T1565.001 - Stored Data Manipulation")
                    _store_baseline(path, digest)
            # files in baseline that no longer resolve at all (glob stopped matching)
            for path in set(baseline) - seen:
                alert("FILE_INTEGRITY_DELETED", "HIGH", None,
                      f"Monitored file missing: {path}",
                      detail="was present in baseline, no longer found",
                      mitre="T1565.001 - Stored Data Manipulation")
                _delete_baseline(path)
        except Exception as e:
            print(f"fim error: {e}", flush=True)


# ---------------------------------------------------------------- workers
def web_worker():
    for line in tail_follow(ACCESS_LOG):
        try:
            process_web(line)
        except Exception as e:
            print(f"web worker error: {e}", flush=True)


def ssh_worker():
    p = subprocess.Popen(
        ["journalctl", "-u", SSH_UNIT, "-f", "-n", "0", "-o", "cat"],
        stdout=subprocess.PIPE, text=True, errors="replace",
    )
    for line in p.stdout:
        try:
            process_ssh(line.rstrip("\n"))
        except Exception as e:
            print(f"ssh worker error: {e}", flush=True)


def health_worker():
    fails = 0
    down = False
    while True:
        ok = False
        try:
            req = urllib.request.Request(SITE_URL, method="GET",
                                         headers={"User-Agent": "soc-guard-healthcheck"})
            code = urllib.request.urlopen(req, timeout=15).getcode()
            ok = 200 <= code < 400
        except Exception:
            ok = False
        if ok:
            if down:
                alert("SITE_RECOVERED", "HIGH", None,
                      "Site is back UP", detail=SITE_URL, mitre="")
                down = False
            fails = 0
        else:
            fails += 1
            if fails >= HEALTH_FAILS and not down:
                down = True
                alert("SITE_DOWN", "CRITICAL", None,
                      f"Site unreachable {fails}x in a row",
                      detail=SITE_URL,
                      mitre="T1499 - Endpoint Denial of Service")
        time.sleep(HEALTH_INTERVAL)


def main():
    init_db()
    print(f"SOC-Guard started (env={ENV_PATH})", flush=True)
    extras = []
    if FIM_ENABLED and FIM_PATHS:
        extras.append(f"FIM({len(FIM_PATHS)} pattern(s))")
    if GEOIP_ENABLED and mmdb:
        extras.append("GeoIP")
    extra = (" + " + " + ".join(extras)) if extras else ""
    send_telegram("SOC_START", "LOW", None, "SOC-Guard started",
                  f"Monitoring: {ACCESS_LOG} + SSH journal ({SSH_UNIT}){extra}", "")
    threads = [
        threading.Thread(target=web_worker, daemon=True),
        threading.Thread(target=ssh_worker, daemon=True),
        threading.Thread(target=health_worker, daemon=True),
        threading.Thread(target=fim_worker, daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    if "--rebaseline" in sys.argv:
        rebaseline()
    else:
        main()
