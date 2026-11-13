# Overview

## What it is

A single-host SIEM-lite: it collects web + SSH logs, detects attacker
behaviour, alerts in real time, and reports daily. Built to demonstrate and
practice detection engineering and incident response on a real server, without
operating a heavyweight stack.

## Why not Wazuh / ELK

A Wazuh manager + indexer needs 2–4 GB RAM and competes with your app on a
small VPS. A purpose-built collector runs in ~14 MB, every line is auditable,
and there are zero third-party dependencies to carry CVEs. For a multi-host
lab, Wazuh/ELK are still the right tools — SOC-Guard targets the
"one server, watch it properly" case.

## Threat model

| Actor | Goal | Primary signal |
|-------|------|----------------|
| Opportunistic bots | credential stuffing, secret theft | SSH brute force, `/.env` `/.git` probes |
| Vulnerability scanners | find exploitable endpoints | 404 enumeration, `/api/` `/actuator` probes |
| Account compromise | persistence via valid creds | SSH login outside allowlist |
| DoS / instability | take the site down | 5xx spike, failed health checks |

## Kill chain coverage

```
Reconnaissance ──▶ Initial Access ──▶ Persistence ──▶ Impact
   │                   │                  │              │
 WEB_SCANNER_*      SSH_BRUTEFORCE    SSH_LOGIN_      SITE_DOWN
 (T1595)            (T1110)           UNEXPECTED      HTTP_5XX_SPIKE
                                      (T1078)         (T1499)
```

## Design principles

- **Least privilege** — runs as a dedicated non-root user, read-only on logs.
- **No secrets in code** — token, URLs, allowlist live in a 600-mode env file.
- **Signal over noise** — only CRITICAL/HIGH reach the phone; everything is
  stored for the daily report and later review.
- **Fail loud when the host dies** — an external heartbeat covers the blind
  spot an in-host monitor can't.
