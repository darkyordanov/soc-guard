# Architecture

## Components

**collector (`soc_guard.py`)** — three daemon threads in one process:
- `web_worker` — follows the access log, parses combined/nginx format, applies
  web rules. Survives log rotation (inode + size check).
- `ssh_worker` — reads `journalctl -u <unit> -f`, applies SSH rules.
- `health_worker` — GETs the site every N seconds; M consecutive failures =
  `SITE_DOWN`.

**storage — SQLite (`soc.db`, WAL mode)**
- `events` — every parsed line (ts, source, ip, user, method, path, status,
  rt, ua, raw).
- `alerts` — fired detections (ts, rule, severity, ip, summary, detail, mitre,
  acknowledged).
WAL mode lets the report read without blocking the collector's writes.

**alerting — Telegram Bot API** — CRITICAL/HIGH pushed instantly; MEDIUM/LOW
stored only. Per-`(rule, ip)` cooldown prevents a single scanner from flooding
the channel.

**external heartbeat — `heartbeat.sh` + healthchecks.io** — pings every few
minutes *only if* the service is active. Host dies → pings stop → the external
monitor alerts you. The dead-man's switch an in-host SOC can't provide.

**daily report — `soc_report.py`** — a cron job summarizing the last 24h:
traffic, latency, alerts by severity, top offending IPs, live health.

## Data flow

```
 access.log ──tail──▶ web_worker ─┐
 SSH journal ──────▶ ssh_worker ──┼─▶ detections ─▶ de-dup ─┬─▶ SQLite
 HTTP probe ───────▶ health_worker┘                         └─▶ Telegram (CRIT/HIGH)

 cron */5  ─▶ heartbeat.sh ─▶ healthchecks.io
 cron 08:00 ─▶ soc_report.py ─▶ Telegram
```

## Configuration

Everything is read from one env file (`SOC_GUARD_ENV`,
default `/etc/soc-guard/soc-guard.env`): log paths, SSH unit name, site URL,
SSH allowlist, all thresholds, the scanner-path regex, and secrets. No code
edit is needed to deploy on a new host. Environment variables override file
values, which is handy for testing.

## Privilege & hardening

- Dedicated `socguard` user, shell `nologin`, groups `adm` +
  `systemd-journal` (read-only).
- systemd unit: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `ReadWritePaths=/var/lib/soc-guard`.
- Secrets in a 600-mode env file owned by the service user.
