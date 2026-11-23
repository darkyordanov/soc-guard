# MITRE ATT&CK Navigator layer

`soc-guard-coverage.json` is a [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
layer showing the techniques SOC-Guard detects, shaded by how many rules cover
each one.

## View it

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. **Open Existing Layer → Upload from local** and pick
   `soc-guard-coverage.json`.

Each highlighted cell is a technique with at least one SOC-Guard detection;
hover for the rule name(s).

## Coverage

| Technique | Rules |
|-----------|-------|
| T1078 Valid Accounts | SSH_LOGIN_UNEXPECTED |
| T1110 Brute Force | SSH_BRUTEFORCE |
| T1190 Exploit Public-Facing Application | WEB_EXPLOIT |
| T1499 Endpoint Denial of Service | HTTP_5XX_SPIKE, SITE_DOWN |
| T1565.001 Stored Data Manipulation | FILE_INTEGRITY_MODIFIED / DELETED / NEW |
| T1505.003 Web Shell | FILE_INTEGRITY_NEW |
| T1595 Active Scanning | WEB_SCANNER_PATH, WEB_SCANNER_404 |

The layer is generated from the Sigma rules' `attack.*` tags, so it stays
honest: it reflects exactly what the rules in `detections/` claim to cover.
