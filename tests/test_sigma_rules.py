"""Validate the Sigma detection rules in detections/.

Ensures every rule parses with pySigma, carries a UUID and MITRE ATT&CK tags,
and that threshold rules use modern Sigma correlations. Skipped automatically
if pySigma isn't installed (it is installed in CI).
"""
import glob
import os
import uuid

import pytest

sigma_collection = pytest.importorskip(
    "sigma.collection", reason="pySigma not installed"
).SigmaCollection

DETECTIONS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detections"
)
RULE_FILES = sorted(glob.glob(os.path.join(DETECTIONS, "**", "*.yml"), recursive=True))


def _rules(path):
    with open(path) as f:
        return sigma_collection.from_yaml(f.read())


def test_rule_files_exist():
    assert RULE_FILES, "no Sigma rule files found under detections/"
    assert len(RULE_FILES) == 10, f"expected 10 rule files, found {len(RULE_FILES)}"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: os.path.relpath(p, DETECTIONS))
def test_rule_parses(path):
    coll = _rules(path)
    assert len(coll.rules) >= 1


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: os.path.relpath(p, DETECTIONS))
def test_rules_have_uuid_and_attack_tag(path):
    for r in _rules(path).rules:
        # every object carries a valid UUID
        uuid.UUID(str(r.id))
        # every object carries at least one MITRE technique tag (attack.tNNNN)
        tags = [str(t) for t in r.tags]
        assert any(t.startswith("attack.t") for t in tags), f"{path}: no attack technique tag in {tags}"


def test_threshold_rules_use_correlations():
    # the three threshold detections must contain a correlation object
    for name in ("web_scanner_404_flood.yml", "http_5xx_spike.yml", "ssh_bruteforce.yml"):
        path = [p for p in RULE_FILES if p.endswith(name)][0]
        coll = _rules(path)
        kinds = [type(r).__name__ for r in coll.rules]
        assert any("Correlation" in k for k in kinds), f"{name}: expected a correlation, got {kinds}"
