#!/usr/bin/env python3
"""
SOC-Guard - daily report.
Reads the last 24h from the SQLite DB and sends a Telegram summary.
Scheduled once a day from cron. Stdlib only.

Config comes from the same env file as soc_guard.py
(default /etc/soc-guard/soc-guard.env, override with SOC_GUARD_ENV).
"""
import os
import sqlite3
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

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
    for k in list(env):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


ENV = load_env(ENV_PATH)
TG_TOKEN = ENV.get("SOC_TG_TOKEN", "")
TG_CHAT = ENV.get("SOC_TG_CHAT", "")
SITE = ENV.get("SOC_SITE_URL", "https://example.com")
DB_PATH = ENV.get("SOC_DB_PATH", "/var/lib/soc-guard/soc.db")

since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")


def q(conn, sql, params=()):
    return conn.execute(sql, params).fetchall()


def build():
    conn = sqlite3.connect(DB_PATH, timeout=10)

    total = q(conn, "SELECT COUNT(*) FROM events WHERE source='web' AND ts>=?", (since,))[0][0]
    uniq_ip = q(conn, "SELECT COUNT(DISTINCT ip) FROM events WHERE source='web' AND ts>=?", (since,))[0][0]
    err404 = q(conn, "SELECT COUNT(*) FROM events WHERE source='web' AND status=404 AND ts>=?", (since,))[0][0]
    err5xx = q(conn, "SELECT COUNT(*) FROM events WHERE source='web' AND status>=500 AND ts>=?", (since,))[0][0]
    avg_rt = q(conn, "SELECT ROUND(AVG(rt)*1000) FROM events WHERE source='web' AND rt IS NOT NULL AND ts>=?", (since,))[0][0]

    by_sev = dict(q(conn, "SELECT severity,COUNT(*) FROM alerts WHERE ts>=? GROUP BY severity", (since,)))
    by_rule = q(conn, "SELECT rule,COUNT(*) c FROM alerts WHERE ts>=? GROUP BY rule ORDER BY c DESC LIMIT 6", (since,))
    top_ips = q(conn,
                "SELECT ip,COUNT(*) c FROM events WHERE source='web' AND status IN (404,403) AND ts>=? "
                "AND ip IS NOT NULL GROUP BY ip ORDER BY c DESC LIMIT 5", (since,))
    ssh_fail = q(conn, "SELECT COUNT(*) FROM alerts WHERE rule='SSH_BRUTEFORCE' AND ts>=?", (since,))[0][0]
    ssh_ok = q(conn, "SELECT COUNT(*) FROM events WHERE source='ssh' AND method='LOGIN' AND ts>=?", (since,))[0][0]
    conn.close()

    try:
        req = urllib.request.Request(SITE, method="GET", headers={"User-Agent": "soc-guard-report"})
        code = urllib.request.urlopen(req, timeout=15).getcode()
        health = f"🟢 UP ({code})" if 200 <= code < 400 else f"🟡 {code}"
    except Exception:
        health = "🔴 DOWN"

    crit = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    med = by_sev.get("MEDIUM", 0)
    verdict = "🟢 All clear" if crit == 0 and high == 0 else ("🟠 Attention" if crit == 0 else "🔴 Incident")

    L = []
    L.append(f"📊 <b>Daily SOC Report</b> — {datetime.now().strftime('%Y-%m-%d')}")
    L.append(f"Posture: {verdict}   Site: {health}")
    L.append("")
    L.append("<b>Traffic (24h)</b>")
    L.append(f"• Requests: {total}   Unique IPs: {uniq_ip}")
    L.append(f"• HTTP 404: {err404}   5xx: {err5xx}   Avg response: {avg_rt or 0} ms")
    L.append("")
    L.append("<b>Security (24h)</b>")
    L.append(f"• Alerts — 🔴 {crit}  🟠 {high}  🟡 {med}")
    L.append(f"• SSH: {ssh_ok} successful logins, {ssh_fail} brute-force alerts")
    if by_rule:
        L.append("• By rule: " + ", ".join(f"{r}×{c}" for r, c in by_rule))
    if top_ips:
        L.append("")
        L.append("<b>Top offending IPs</b>")
        for ip, c in top_ips:
            L.append(f"• <code>{ip}</code> — {c} hits (404/403)")
    L.append("")
    L.append(f"🕒 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    return "\n".join(L)


def send(text):
    if not TG_TOKEN or not TG_CHAT:
        print(text)
        return
    data = urllib.parse.urlencode(
        {"chat_id": TG_CHAT, "text": text, "parse_mode": "HTML",
         "disable_web_page_preview": "true"}
    ).encode()
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=15).read()


if __name__ == "__main__":
    send(build())
