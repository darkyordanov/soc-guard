# Installation

Set up SOC-Guard on any systemd Linux server (Debian/Ubuntu or
RHEL/Alma/Rocky). Every step is copy-paste. Replace placeholders in CAPS.

> Time: ~10 minutes. You need sudo, Python 3, a Telegram bot token, and
> optionally a healthchecks.io check.

---

## 1. Create a Telegram bot

1. In Telegram, open **@BotFather** → `/newbot` → follow prompts → copy the
   **bot token**.
2. Send any message to your new bot (so it can message you back).
3. Get your numeric **chat id**:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | grep -oE '"id":[0-9]+' | head -1
   ```
   Keep the token secret. It never goes into code or git.

---

## 2. Create an unprivileged service user

The collector must not run as root. It only needs to **read** logs.

```bash
# adm: read nginx/apache logs; systemd-journal: read the SSH journal
sudo useradd -r -M -s /usr/sbin/nologin -G adm,systemd-journal socguard
sudo install -d -o socguard -g socguard -m 750 /opt/soc-guard /var/lib/soc-guard
```

Verify it can read what it needs:

```bash
sudo -u socguard test -r /var/log/nginx/access.log && echo "CAN_READ_WEB_LOG"
sudo -u socguard journalctl -u ssh -n1 >/dev/null 2>&1 && echo "CAN_READ_JOURNAL"
```

> On RHEL/Alma/Rocky the SSH unit is `sshd` and logs live under the `adm`-like
> group `wheel`/`systemd-journal`; set `SOC_SSH_UNIT=sshd` in the config below.

---

## 3. Install the code

```bash
sudo cp src/soc_guard.py src/soc_report.py /opt/soc-guard/
sudo cp src/heartbeat.sh /opt/soc-guard/
sudo chown -R socguard:socguard /opt/soc-guard
sudo chmod 755 /opt/soc-guard/heartbeat.sh
```

---

## 4. Configure

```bash
sudo install -d -m 755 /etc/soc-guard
sudo cp examples/soc-guard.env.example /etc/soc-guard/soc-guard.env
sudo nano /etc/soc-guard/soc-guard.env
sudo chown socguard:socguard /etc/soc-guard/soc-guard.env
sudo chmod 600 /etc/soc-guard/soc-guard.env
```

Fill in at minimum:

| Key | What |
|-----|------|
| `SOC_TG_TOKEN` / `SOC_TG_CHAT` | from step 1 |
| `SOC_SITE_URL` | the URL to health-check |
| `SOC_ACCESS_LOG` | path to your web access log |
| `SOC_SSH_UNIT` | `ssh` (Debian/Ubuntu) or `sshd` (RHEL) |
| `SOC_ALLOWED_SSH_USERS` | comma-separated users you expect to log in via SSH |

> **Tip:** for clean `WEB_SCANNER_*` signal, point `SOC_ACCESS_LOG` at a
> per-site access log, not the global one.

### nginx log format (recommended)

For response-time metrics in the daily report, use a log format that appends
`rt=`:

```nginx
log_format soc '$remote_addr - $remote_user [$time_local] '
               '"$request" $status $body_bytes_sent '
               '"$http_referer" "$http_user_agent" '
               'rt=$request_time urt=$upstream_response_time';
access_log /var/log/nginx/access.log soc;
```

The parser also accepts the stock `combined` format (without `rt=`); you just
lose the latency metric. **Apache:** the default `combined` LogFormat works as
is; response time is unavailable unless you add `%D` and adjust the regex via
`SOC_SCANNER_REGEX`/log format.

---

## 5. Test by hand

```bash
sudo -u socguard SOC_GUARD_ENV=/etc/soc-guard/soc-guard.env python3 /opt/soc-guard/soc_guard.py
```

You should get a Telegram "SOC-Guard started" message. From another host,
trigger a rule:

```bash
curl -s "https://YOUR-SITE/.env" -o /dev/null      # -> WEB_SCANNER_PATH (MEDIUM, stored)
```

Stop it with Ctrl+C. (MEDIUM is stored, not pushed — only CRITICAL/HIGH ping
Telegram. Verify it recorded:)

```bash
sudo -u socguard sqlite3 /var/lib/soc-guard/soc.db \
  "SELECT ts,rule,severity,ip FROM alerts ORDER BY id DESC LIMIT 5;"
```

---

## 6. Run as a service

```bash
sudo cp systemd/soc-guard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-guard
sudo systemctl status soc-guard --no-pager | head -8
```

Expect `active (running)`.

---

## 7. Daily report (cron)

```bash
# 06:00 UTC — adjust to your timezone
( sudo -u socguard crontab -l 2>/dev/null; \
  echo "0 6 * * * SOC_GUARD_ENV=/etc/soc-guard/soc-guard.env /usr/bin/python3 /opt/soc-guard/soc_report.py" ) \
  | sudo -u socguard crontab -
# test now:
sudo -u socguard SOC_GUARD_ENV=/etc/soc-guard/soc-guard.env python3 /opt/soc-guard/soc_report.py
```

---

## 8. External heartbeat (dead-man's switch)

An in-host monitor can't report its own host dying. Add an external check:

1. Sign up at **healthchecks.io** (free), create a check (period 5 min, grace
   5 min), add a notification channel (Telegram/email), copy its **ping URL**.
2. Put the URL in the config as `SOC_HEARTBEAT_URL`, then:

```bash
( sudo -u socguard crontab -l 2>/dev/null; \
  echo "*/5 * * * * /opt/soc-guard/heartbeat.sh" ) | sudo -u socguard crontab -
sudo -u socguard /opt/soc-guard/heartbeat.sh && echo FIRST_PING_OK
```

The check turns green within a minute. If the host or the collector stops,
pings stop and healthchecks.io alerts you independently.

---

## Done

You now have: real-time alerts, a daily report, and an external watchdog — a
working SOC pipeline on one host, in ~14 MB of RAM. Tune thresholds in the
config after a week of real traffic (see
[02-detection-rules.md](02-detection-rules.md)).

## Uninstall

```bash
sudo systemctl disable --now soc-guard
sudo rm /etc/systemd/system/soc-guard.service
sudo -u socguard crontab -r
sudo rm -rf /opt/soc-guard /etc/soc-guard /var/lib/soc-guard
sudo userdel socguard
```
