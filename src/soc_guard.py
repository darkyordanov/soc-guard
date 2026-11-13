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
import os
import re
import sqlite3
import subprocess
import threading
import time
import urllib.request
import urllib.parse
from collections import deque, defaultdict
from datetime import datetime, timezone

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
    # environment variables override file values
    for k in list(env):
        if k in os.environ:
            env[k] = os.environ[k]
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


def send_telegram(rule, severity, ip, summary, detail, mitre):
    if not TG_TOKEN or not TG_CHAT:
        return
    lines = [f"{EMOJI.get(severity,'')} <b>{severity}</b> — {rule}",
             f"<b>{summary}</b>"]
    if ip:
        lines.append(f"Source IP: <code>{ip}</code>")
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
    f = open(path, "r", errors="replace")
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
                f = open(path, "r", errors="replace")
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
    send_telegram("SOC_START", "LOW", None, "SOC-Guard started",
                  f"Monitoring: {ACCESS_LOG} + SSH journal ({SSH_UNIT})", "")
    threads = [
        threading.Thread(target=web_worker, daemon=True),
        threading.Thread(target=ssh_worker, daemon=True),
        threading.Thread(target=health_worker, daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
