# Incident Response Playbooks

Each follows **Triage → Contain → Eradicate → Recover → Lessons**. Commands
assume an admin user with sudo; adapt unit/user names to your host.

## SSH_LOGIN_UNEXPECTED (CRITICAL, T1078)
**Triage**
```bash
who; w; last -a | head
sudo journalctl -u ssh --since "1 hour ago" | grep Accepted
```
**Contain**
```bash
sudo pkill -KILL -u <user>            # kill their sessions
sudo usermod -L -e 1 <user>           # lock the account
sudo fail2ban-client set sshd banip <ip>
```
**Eradicate** — remove the key from `~/.ssh/authorized_keys`; audit all
accounts; confirm `AllowUsers`; rotate any secret the account could read.
**Recover** — rebuild if persistence is suspected; re-enable only with a fresh
key. **Lessons** — wrong allowlist or real breach? Record it.

## SSH_BRUTEFORCE (HIGH, T1110)
**Triage** `sudo journalctl -u ssh --since "1 hour ago" | grep -E 'Failed|Invalid' | grep <ip>`
**Contain** fail2ban usually bans automatically; else
`sudo fail2ban-client set sshd banip <ip>`. **Lessons** — recurring source
range → firewall drop or geo-block.

## HTTP_5XX_SPIKE (HIGH, T1499)
**Triage** check web error log + app logs + `systemctl status`.
**Contain** roll back a bad deploy, ban a single abusive IP, or fix the DB.
**Recover** restart the app, confirm `200`. **Lessons** — add a pre-deploy
smoke test if a deploy caused it.

## WEB_SCANNER_PATH / WEB_SCANNER_404 (MEDIUM, T1595)
**Triage** `sudo grep <ip> <access_log> | tail -30`. Usually automated noise.
**Escalate** only if a probe got a 200 on a sensitive path, or if it's followed
by targeted requests. **Contain** (optional) ban persistent sources.

## SITE_DOWN (CRITICAL, T1499)
**Triage** `curl -sI https://SITE | head -1`; check services, containers, and
`df -h /` (disk full is a common cause). **Recover** restart the failed unit /
free disk, confirm `200` and that the external heartbeat is green.
