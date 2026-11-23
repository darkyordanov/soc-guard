# Detections (Sigma)

SOC-Guard's detections, written as portable [Sigma](https://sigmahq.io) rules.

The collector (`src/soc_guard.py`) runs these checks inline against the nginx
access log, the SSH journal, file hashes and a health probe. The `.yml` files
here express the **same detection logic** in Sigma — the vendor-neutral standard
— so the rules are:

- **portable** — convert to Splunk, Elastic, Microsoft Sentinel, QRadar and
  others with [pySigma](https://github.com/SigmaHQ/pySigma) / `sigma-cli`, no
  rewrite;
- **reviewable** — each rule is a small, diff-able file with a stable UUID,
  MITRE ATT&CK tags, references and documented false positives;
- **testable** — the detection logic is covered by `tests/` and validated in CI.

This is *detection-as-code*: rules live in version control, are validated on
every change, and ship the same way code does.

## Layout

```
detections/
├── web/           # nginx / apache access-log detections
│   ├── web_exploit_probe.yml       WEB_EXPLOIT          T1190  high
│   ├── web_scanner_path.yml        WEB_SCANNER_PATH     T1595  medium
│   ├── web_scanner_404_flood.yml   WEB_SCANNER_404      T1595  medium
│   └── http_5xx_spike.yml          HTTP_5XX_SPIKE       T1499  high
├── ssh/           # sshd journal detections
│   ├── ssh_login_unexpected.yml    SSH_LOGIN_UNEXPECTED T1078  critical
│   └── ssh_bruteforce.yml          SSH_BRUTEFORCE       T1110  high
├── integrity/     # file-integrity monitoring (SOC-Guard native events)
│   ├── file_modified.yml           FILE_INTEGRITY_MODIFIED  T1565.001  high
│   ├── file_deleted.yml            FILE_INTEGRITY_DELETED   T1565.001  high
│   └── file_new.yml                FILE_INTEGRITY_NEW       T1565.001  medium
└── availability/
    └── site_down.yml               SITE_DOWN            T1499  critical
```

The `web/` and `ssh/` rules use standard Sigma log sources (`category:
webserver`, `service: sshd`), so they drop straight into any SIEM ingesting
those logs. The `integrity/` and `availability/` rules match SOC-Guard's own
normalised events (`product: soc-guard`).

## Validate

```bash
pip install sigma-cli pysigma
sigma check detections/              # lint + validate every rule
```

## Convert to a SIEM query

```bash
pip install pysigma-backend-splunk pysigma-backend-elasticsearch

# Splunk SPL
sigma convert -t splunk detections/web/web_exploit_probe.yml

# Elastic (Lucene / ES|QL via the elasticsearch backend)
sigma convert -t elasticsearch detections/web/web_exploit_probe.yml
```

One rule, written once, runs anywhere.

## Mapping to the engine

Each Sigma rule mirrors a rule in [`src/soc_guard.py`](../src/soc_guard.py); the
threshold-based ones (`*_404_flood`, `http_5xx_spike`, `ssh_bruteforce`) carry
their window/count in the engine's env config. See
[`docs/02-detection-rules.md`](../docs/02-detection-rules.md) for thresholds and
tuning, and [`docs/04-detection-as-code.md`](../docs/04-detection-as-code.md)
for the test + CI pipeline.
