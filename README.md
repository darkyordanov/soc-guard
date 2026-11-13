<p align="center">
  <img src="assets/logo.png" alt="SOC-Guard" width="420">
</p>

<p align="center">
  <em>Self-hosted SIEM-lite for a single Linux web server — detections mapped to MITRE ATT&CK, real-time Telegram alerts, ~14&nbsp;MB RAM.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.8%2B-blue">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-none%20(stdlib)-brightgreen">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20systemd-lightgrey">
</p>

---

**A self-hosted SIEM-lite for a single Linux web server.** Pure Python 3
stdlib — no dependencies, no agent, no 4 GB stack. It tails your web access log
and the SSH journal, detects attacker behaviour with rules mapped to
**MITRE ATT&CK**, stores everything in SQLite, and pushes real-time
**Telegram** alerts. A daily report and an external dead-man's-switch heartbeat
round it out.

> Built to run on a small VPS alongside your app — the collector uses about
> **14 MB of RAM**.

```
          ┌───────────────── your Linux web server ──────────────────┐
 access.log ─┐                                                        │
 (nginx/apache) ├──tail──▶┌──────────────┐    ┌─────────┐   ┌────────┐│
 SSH journal ───┘         │  soc_guard   │───▶│ SQLite  │   │Telegram││
 journalctl -u ssh        │  detections  │───▶│ soc.db  │──▶│CRIT/HGH││
 HTTP health probe ──────▶│  + health    │    └─────────┘   └────────┘│
          │               └──────┬───────┘                            │
          └───── heartbeat.sh ───┼── cron */5 ──▶ healthchecks.io ─────┘
                 soc_report.py ──┴── cron 08:00 ─▶ Telegram daily report
```

## Features

- **Zero dependencies** — Python 3 stdlib only; auditable, no supply-chain CVEs.
- **Config-driven** — every path, threshold, allowlist and secret lives in one
  env file. Deploy on a new host without touching code.
- **MITRE ATT&CK-mapped detections** — T1078, T1110, T1595, T1499.
- **Real-time Telegram alerts** for `CRITICAL`/`HIGH`, de-duplicated per source.
- **External heartbeat** — if the whole host dies, the monitor still alerts you.
- **Daily report** — traffic, alert breakdown, top offending IPs.
- **Runs unprivileged + systemd-sandboxed** — read-only on logs, no root,
  write access limited to its own data dir.

## Detection rules

| Rule | Severity | MITRE ATT&CK | Trigger |
|------|----------|--------------|---------|
| `SSH_LOGIN_UNEXPECTED` | CRITICAL | T1078 Valid Accounts | successful SSH login by a user not in the allowlist |
| `SITE_DOWN` | CRITICAL | T1499 Endpoint DoS | HTTP health check fails 3× in a row |
| `SSH_BRUTEFORCE` | HIGH | T1110 Brute Force | > N failed SSH / window / IP |
| `HTTP_5XX_SPIKE` | HIGH | T1499 Endpoint DoS | > N server errors / window (site-wide) |
| `WEB_SCANNER_PATH` | MEDIUM | T1595 Active Scanning | request to `/.env`, `/.git`, `/api/`, `wp-admin`, … |
| `WEB_SCANNER_404` | MEDIUM | T1595 Active Scanning | > N × HTTP 404 / window / IP |

Thresholds are configurable. Details & tuning: [docs/02-detection-rules.md](docs/02-detection-rules.md).

## Quick start

```bash
git clone https://github.com/darkyordanov/server-soc-guard.git
cd server-soc-guard
sudo cp examples/soc-guard.env.example /etc/soc-guard/soc-guard.env
sudo nano /etc/soc-guard/soc-guard.env          # fill in token, paths, allowlist
# ...then follow docs/INSTALL.md (user, service, cron, heartbeat)
```

Full step-by-step for any server: **[docs/INSTALL.md](docs/INSTALL.md)**.

## Requirements

- Linux with **systemd** and **journald** (Debian/Ubuntu or RHEL/Alma/Rocky)
- Python 3.8+ (stdlib only)
- nginx or apache access log in combined/common format
- A Telegram bot (free) for alerts; optionally a healthchecks.io check (free)

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md) — install on your own server, step by step
- [docs/00-overview.md](docs/00-overview.md) — design, threat model, why not Wazuh
- [docs/01-architecture.md](docs/01-architecture.md) — components & data flow
- [docs/02-detection-rules.md](docs/02-detection-rules.md) — rules → MITRE ATT&CK
- [docs/03-ir-playbooks.md](docs/03-ir-playbooks.md) — incident-response playbooks

## Roadmap

- [ ] FastAPI + HTMX web dashboard (live alerts, acknowledge, traffic charts)
- [ ] File Integrity Monitoring (git-based config drift detection)
- [ ] GeoIP / ASN enrichment on offender IPs
- [ ] SQLi/XSS probe detection on request URIs
- [ ] Apache-tuned log regex preset

## Scope & ethics

Defensive tooling for infrastructure **you own or are authorized to monitor**.
It watches your own logs and your own service health. It performs no scanning
of third parties.

## License

MIT — see [LICENSE](LICENSE).
