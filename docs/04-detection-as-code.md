# Detection-as-Code

SOC-Guard treats its detections the way a software team treats code: every rule
lives in version control, is written in a portable standard, is covered by a
test, and is validated automatically before it ships. This is *detection-as-code*
(DaC) — the practice that lets a SOC change detections quickly without flooding
analysts with false positives or silently breaking coverage.

```
   write rule ──▶ test it ──▶ CI validates ──▶ merge ──▶ deploy
   (Sigma +       (pytest,     (lint, tests,     (git)     (collector /
    engine)        synthetic    sigma check)               any SIEM)
                   logs)
```

## The three layers

### 1. Rules as data — Sigma

Every detection is expressed as a [Sigma](https://sigmahq.io) rule under
[`detections/`](../detections/). Sigma is the vendor-neutral standard for
detections, so a rule written once converts to Splunk, Elastic, Microsoft
Sentinel, QRadar and others with [pySigma](https://github.com/SigmaHQ/pySigma) —
no rewrite per platform.

```bash
sigma convert -t splunk detections/web/web_exploit_probe.yml
sigma convert -t elasticsearch detections/web/web_exploit_probe.yml
```

Each rule carries a stable UUID, MITRE ATT&CK tags, references and documented
false positives — so a reviewer can reason about *what* it catches and *why* it
might misfire, from the rule file alone. Threshold detections (brute force, 404
flood, 5xx spike) use modern Sigma **correlations** rather than deprecated
pipe syntax.

The live engine (`src/soc_guard.py`) runs the same logic inline against the
nginx log, the SSH journal, file hashes and a health probe. The Sigma files are
the portable, reviewable expression of those detections.

### 2. Detections are tested — pytest

A detection you can't test is a detection you hope works. Every rule is covered
by [`tests/`](../tests/): synthetic log lines — both malicious and benign — are
fed through the collector's detection functions, asserting the right rule fires
**and** that nothing fires on clean traffic. False-positive tests matter as much
as true-positive ones: a noisy rule is as useless as a blind one.

```bash
pip install -r tests/requirements.txt
pytest          # 55 tests
```

`alert()` is monkeypatched to capture calls, so detections run in isolation —
no database, no network, no real clock. Thresholds and per-IP windowing are
tested at and around their boundaries.

### 3. Everything is validated — CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every push and
pull request:

| Step | What it guarantees |
|------|--------------------|
| `compileall` | the stdlib-only collector imports cleanly |
| `ruff` | no unused imports, undefined names, or obvious bugs |
| `pytest` | all 55 detection tests pass |
| `sigma check` | every Sigma rule is valid and its ATT&CK tags are real |

A detection — or a change to one — cannot land on `main` without passing all
four. That's the point of the pipeline: coverage and quality are enforced
mechanically, not by memory.

## Why this matters

As AI takes over first-line alert triage, the durable work moves to the people
who **build and tune the detections** that the automation runs on. DaC is how
that work is done at scale: rules reviewed like code, regressions caught by
tests, coverage mapped to ATT&CK, and the whole thing portable across whatever
SIEM an organisation runs. SOC-Guard is a small, end-to-end example of that
workflow on a single host.

## Keeping the engine and the rules in sync

The Sigma files mirror the engine; they don't drive it. When you change a
detection in `src/soc_guard.py` (or a threshold in the env config), update the
matching Sigma rule and its test in the same change — CI will fail the PR if a
rule stops parsing, but it can't know that a regex drifted out of sync, so that
discipline is on the author. See [`02-detection-rules.md`](02-detection-rules.md)
for the rule-by-rule reference and thresholds.
