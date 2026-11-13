# Detection Rules

Each rule maps to a [MITRE ATT&CK](https://attack.mitre.org/) technique.
Thresholds ship with sane defaults and are overridable per environment via the
config.

> Alert routing: CRITICAL + HIGH → Telegram (real time). MEDIUM + LOW → SQLite
> only, surfaced in the daily report. Per-(rule, ip) cooldown stops floods.

## SSH_LOGIN_UNEXPECTED — CRITICAL — T1078 Valid Accounts
A **successful** SSH login by a user not in `SOC_ALLOWED_SSH_USERS`. The
highest-value rule: it fires on actual account use, not just attempts. Keep the
allowlist tight.
```
Accepted publickey for deploy from 1.2.3.4   → CRITICAL (deploy not allowlisted)
Accepted publickey for youruser from 1.2.3.4 → no alert
```

## SITE_DOWN — CRITICAL — T1499 Endpoint DoS
HTTP health probe fails `SOC_HEALTH_FAILS` times in a row. Paired with
`SITE_RECOVERED` (HIGH) on return. The external heartbeat covers a full-host
outage where this check can't run.

## SSH_BRUTEFORCE — HIGH — T1110 Brute Force
More than `SOC_BRUTE_LIMIT` failed SSH attempts from one IP within
`SOC_BRUTE_WINDOW`. fail2ban may already ban these at the network layer; this
rule gives the SOC an auditable record and visibility, not just a silent ban.

## HTTP_5XX_SPIKE — HIGH — T1499 Endpoint DoS
More than `SOC_5XX_LIMIT` server (5xx) errors site-wide within
`SOC_5XX_WINDOW` — an outage, a bad deploy, or exploitation hitting errors.

## WEB_SCANNER_PATH — MEDIUM — T1595 Active Scanning
A request to a known-sensitive path (`/.env`, `/.git`, `wp-admin`,
`phpmyadmin`, `/api/`, `/actuator`, …). In practice the most frequent alert —
the background radiation of scanners probing for secrets and admin panels.
Tune the set with `SOC_SCANNER_REGEX`.

## WEB_SCANNER_404 — MEDIUM — T1595 Active Scanning
More than `SOC_SCAN_404_LIMIT` HTTP 404s from one IP within `SOC_SCAN_WINDOW` —
directory/endpoint brute forcing (gobuster/ffuf-style).

## Threshold defaults

| Rule | Window | Threshold | Scope | Env keys |
|------|--------|-----------|-------|----------|
| SSH_BRUTEFORCE | 300 s | 10 | per IP | `SOC_BRUTE_WINDOW`, `SOC_BRUTE_LIMIT` |
| WEB_SCANNER_404 | 60 s | 15 | per IP | `SOC_SCAN_WINDOW`, `SOC_SCAN_404_LIMIT` |
| HTTP_5XX_SPIKE | 300 s | 5 | site-wide | `SOC_5XX_WINDOW`, `SOC_5XX_LIMIT` |
| SITE_DOWN | 60 s probe | 3 consecutive | host | `SOC_HEALTH_INTERVAL`, `SOC_HEALTH_FAILS` |
| cooldown | 600 s | — | per (rule, ip) | `SOC_ALERT_COOLDOWN` |

## Tuning

After ~1–2 weeks of real traffic, review the daily reports and adjust. A quiet
site can lower `SOC_SCAN_404_LIMIT`; a busy one should raise it. Add legitimate
SSH users to the allowlist rather than muting the rule.

## Roadmap rules
- File Integrity Monitoring — `git status` on the app tree; change outside a
  deploy = CRITICAL.
- GeoIP / ASN enrichment on offender IPs (MaxMind GeoLite2).
- SQLi/XSS probe detection — regex on URI/query (`union select`, `../`,
  `<script`).
