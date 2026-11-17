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
sudo cp src/soc_guard.py src/soc_report.py src/mmdb.py /opt/soc-guard/
sudo cp src/heartbeat.sh /opt/soc-guard/
sudo chown -R socguard:socguard /opt/soc-guard
sudo chmod 755 /opt/soc-guard/heartbeat.sh
```

> `mmdb.py` is the stdlib MaxMind reader used by GeoIP enrichment (step 5c). It
> has no dependencies; deploy it next to `soc_guard.py` even if you enable GeoIP
> later.

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

## 5b. (Optional) File Integrity Monitoring

Pick the handful of files whose change would matter — web root, server configs,
auth config — and list them in the env file:

```
SOC_FIM_ENABLED=1
SOC_FIM_PATHS=/etc/nginx/nginx.conf, /etc/ssh/sshd_config, /var/www/html/*.php
SOC_FIM_INTERVAL=300
```

`SOC_FIM_PATHS` is a comma-separated mix of exact files and shell globs — glob,
not blind recursion, so you control the scope. The collector runs unprivileged,
so it needs **read** access to each watched file. If a file lives under another
user's home, grant read access narrowly with a POSIX ACL rather than loosening
ownership:

```bash
sudo setfacl -m u:socguard:--x /home/appuser
sudo setfacl -R -m u:socguard:rX /home/appuser/app
```

> If the service unit sets `ProtectHome=true`, the collector can't see `/home`
> at all — relax it to `ProtectHome=read-only` so FIM can read a watched file
> there while writes stay blocked.

The baseline is strict: after any legitimate deploy, re-trust the new state:

```bash
sudo -u socguard SOC_GUARD_ENV=/etc/soc-guard/soc-guard.env \
  python3 /opt/soc-guard/soc_guard.py --rebaseline
```

---

## 5c. (Optional) GeoIP enrichment

Enrich every IP-bearing alert with country / city / ASN, resolved locally — no
per-alert API calls, no `geoip2` package (SOC-Guard ships its own stdlib
`.mmdb` reader).

1. Create a free **MaxMind** account → sign up for **GeoLite2** → generate a
   **license key** (answer "yes" to "used for GeoIP Update").
2. Install the updater and fetch the databases:

   ```bash
   sudo apt-get install -y geoipupdate            # Debian/Ubuntu
   sudo tee /etc/GeoIP.conf >/dev/null <<'EOF'
   AccountID YOUR_ACCOUNT_ID
   LicenseKey YOUR_LICENSE_KEY
   EditionIDs GeoLite2-City GeoLite2-Country GeoLite2-ASN
   EOF
   sudo chmod 600 /etc/GeoIP.conf
   sudo geoipupdate -v
   ```

   Databases land in `/var/lib/GeoIP/`. Let the collector read them:

   ```bash
   sudo chmod 755 /var/lib/GeoIP
   sudo -u socguard test -r /var/lib/GeoIP/GeoLite2-City.mmdb && echo OK
   ```

3. Keep them fresh (MaxMind publishes ~twice weekly):

   ```bash
   echo '0 3 * * 2,5 root /usr/bin/geoipupdate' | sudo tee /etc/cron.d/geoipupdate
   ```

4. Enable in the env file:

   ```
   SOC_GEOIP_ENABLED=1
   SOC_GEOIP_CITY_DB=/var/lib/GeoIP/GeoLite2-City.mmdb
   SOC_GEOIP_ASN_DB=/var/lib/GeoIP/GeoLite2-ASN.mmdb
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
# if you enabled GeoIP:
sudo rm -f /etc/cron.d/geoipupdate /etc/GeoIP.conf
```
