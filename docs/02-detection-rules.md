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

## FILE_INTEGRITY_MODIFIED — HIGH — T1565.001 Stored Data Manipulation
A watched file's SHA-256 changed since the baseline. The baseline is set on
first run (stored in the `fim_baseline` table) and is authoritative: any change
after it is an alert. After a legitimate deploy, re-trust the new state:
```bash
sudo -u socguard SOC_GUARD_ENV=/etc/soc-guard/soc-guard.env \
  python3 /opt/soc-guard/soc_guard.py --rebaseline
```
The baseline lives in the DB, so a plain service restart re-trusts nothing.

## FILE_INTEGRITY_DELETED — HIGH — T1565.001 Stored Data Manipulation
A file that was in the baseline is now gone or unreadable — defacement,
tampering, or an attacker clearing evidence.

## FILE_INTEGRITY_NEW — MEDIUM — T1565.001 Stored Data Manipulation
A new file appeared inside a watched glob (e.g. a dropped web shell under
`/var/www/html/*.php`). MEDIUM because new files are also normal during
maintenance; it's adopted into the baseline after the first sighting.

> **FIM config.** `SOC_FIM_PATHS` takes a comma-separated mix of exact files and
> shell globs — glob, not blind recursion, so you choose the scope. Point it at
> the handful of files that matter (web root, server configs, `sshd_config`,
> cron, sudoers), not a whole tree. For a web root that writes cache/upload
> files at runtime, narrow the glob or watch only source + configs to avoid
> `FILE_INTEGRITY_NEW` noise.

## WEB_EXPLOIT — HIGH — T1190 Exploit Public-Facing Application
A SQLi / XSS / path-traversal / command-injection signature in a request URI.
The path+query is URL-decoded once (bots percent-encode payloads), then matched
against patterns covering `union select`, `or 1=1`, `sleep()`,
`information_schema`, `<script>`, `onerror=`, `../../`, `/etc/passwd`,
`; cat`, `| wget`, etc. Override the whole set with `SOC_EXPLOIT_REGEX`.
```
GET /?id=1%20union%20select%201,2,3  → WEB_EXPLOIT (HIGH)
GET /search?q=<script>alert(1)       → WEB_EXPLOIT (HIGH)
GET /about-us/team                   → no alert
```
> A `WEB_EXPLOIT` at HTTP 200 means the probe was *attempted* and the app
> handled the input normally — it is an edge early-warning, not proof of a
> breach. That's exactly where you want to catch it.

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

## GeoIP enrichment (not a rule)
When `SOC_GEOIP_ENABLED=1`, every alert carrying a source IP gets a
`🌍 City, CC · ASxxx Org` line, resolved locally from MaxMind GeoLite2
databases via a from-scratch stdlib `.mmdb` reader (`src/mmdb.py`, no `geoip2`
package). Private / loopback / reserved addresses are skipped. Setup:
[INSTALL.md](INSTALL.md).

## Threshold defaults

| Rule | Window | Threshold | Scope | Env keys |
|------|--------|-----------|-------|----------|
| SSH_BRUTEFORCE | 300 s | 10 | per IP | `SOC_BRUTE_WINDOW`, `SOC_BRUTE_LIMIT` |
| WEB_SCANNER_404 | 60 s | 15 | per IP | `SOC_SCAN_WINDOW`, `SOC_SCAN_404_LIMIT` |
| HTTP_5XX_SPIKE | 300 s | 5 | site-wide | `SOC_5XX_WINDOW`, `SOC_5XX_LIMIT` |
| SITE_DOWN | 60 s probe | 3 consecutive | host | `SOC_HEALTH_INTERVAL`, `SOC_HEALTH_FAILS` |
| FILE_INTEGRITY_* | 300 s | on change | per file | `SOC_FIM_PATHS`, `SOC_FIM_INTERVAL` |
| cooldown | 600 s | — | per (rule, ip) | `SOC_ALERT_COOLDOWN` |

## Tuning

After ~1–2 weeks of real traffic, review the daily reports and adjust. A quiet
site can lower `SOC_SCAN_404_LIMIT`; a busy one should raise it. Add legitimate
SSH users to the allowlist rather than muting the rule. For FIM, narrow globs
or `--rebaseline` after each deploy rather than disabling the rule.
