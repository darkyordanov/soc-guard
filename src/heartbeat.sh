#!/bin/bash
# SOC-Guard - external heartbeat (dead-man's switch).
# Pings a monitoring URL (e.g. healthchecks.io) ONLY if the collector is alive.
# If the host or the collector dies, pings stop and the monitor alerts you.
# Schedule from cron every few minutes.
set -a
# shellcheck disable=SC1090
. "${SOC_GUARD_ENV:-/etc/soc-guard/soc-guard.env}"
set +a

# only ping while the collector service is actually running
systemctl is-active --quiet "${SOC_SERVICE_NAME:-soc-guard}" || exit 0

[ -n "$SOC_HEARTBEAT_URL" ] || exit 0
curl -fsS -m 10 --retry 3 "$SOC_HEARTBEAT_URL" >/dev/null
