# Tests

Detection tests for SOC-Guard. Every detection is covered by a test that feeds
synthetic log lines (both malicious and benign) through the collector's
detection functions and asserts the right rule fires — and that nothing fires on
clean traffic. This is the "code" half of *detection-as-code*: detections are
verified, not assumed.

## Run

```bash
pip install -r tests/requirements.txt
pytest
```

## Coverage

| File | What it checks |
|------|----------------|
| `test_web_detections.py` | WEB_EXPLOIT (SQLi/XSS/traversal/cmd-inj + no false positives + MITRE tag), WEB_SCANNER_PATH, WEB_SCANNER_404 flood (threshold + per-IP), HTTP_5XX_SPIKE |
| `test_ssh_detections.py` | SSH_LOGIN_UNEXPECTED (allowlist logic), SSH_BRUTEFORCE (threshold + per-IP + invalid-user) |
| `test_mmdb.py` | The from-scratch `.mmdb` reader against MaxMind's official test databases (city, ASN, private IP, caching, 28-bit records) |
| `test_sigma_rules.py` | Every Sigma rule parses with pySigma, carries a UUID + MITRE ATT&CK tag, and threshold rules use correlations |

## How it works

The detection functions (`process_web`, `process_ssh`, FIM) all call
`alert(rule, severity, ip, …)`. The tests monkeypatch `alert` to capture calls
into a list instead of writing to SQLite or sending Telegram — so detection
logic is tested in isolation, with no database, no network, and no real clock.
Sliding-window and cooldown state is reset between tests.

The MaxMind test databases under `tests/data/` are small fixtures published by
MaxMind for exactly this purpose; the `test_mmdb.py` tests skip automatically if
they are absent.
