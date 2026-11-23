"""Shared pytest fixtures for SOC-Guard detection tests.

The collector's detection functions (`process_web`, `process_ssh`, FIM) all
funnel into `alert(rule, severity, ip, ...)`. To test detection logic in
isolation — no SQLite, no Telegram, no clock — we import the module with a
throwaway env and monkeypatch `alert` to capture calls into a list.
"""
import importlib
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


@pytest.fixture()
def soc(monkeypatch, tmp_path):
    """Import soc_guard fresh with a temp DB + no Telegram, and capture alerts.

    Returns the module with an extra `.captured` list; each entry is a dict
    {rule, severity, ip, summary, detail, mitre}. Per-test sliding-window and
    cooldown state is reset so tests don't bleed into each other.
    """
    # point the collector at a temp env file that doesn't exist -> defaults,
    # plus a temp DB path so nothing touches a real database
    monkeypatch.setenv("SOC_GUARD_ENV", str(tmp_path / "nonexistent.env"))
    monkeypatch.setenv("SOC_DB_PATH", str(tmp_path / "soc.db"))
    monkeypatch.setenv("SOC_TG_TOKEN", "")
    monkeypatch.setenv("SOC_TG_CHAT", "")

    # import (or re-import) cleanly so module-level config picks up the env
    if "soc_guard" in sys.modules:
        del sys.modules["soc_guard"]
    soc_guard = importlib.import_module("soc_guard")

    captured = []

    def fake_alert(rule, severity, ip, summary, detail="", mitre=""):
        captured.append({
            "rule": rule, "severity": severity, "ip": ip,
            "summary": summary, "detail": detail, "mitre": mitre,
        })

    monkeypatch.setattr(soc_guard, "alert", fake_alert)
    monkeypatch.setattr(soc_guard, "save_event", lambda **k: None)
    soc_guard.captured = captured

    # reset sliding-window + cooldown state between tests
    soc_guard.win_404.clear()
    soc_guard.win_5xx.clear()
    soc_guard.win_ssh_fail.clear()
    soc_guard._last_alert.clear()

    return soc_guard


def nginx_line(ip="203.0.113.7", method="GET", path="/", status=200,
               ua="curl/8.0", rt="0.012"):
    """Build one combined+rt nginx access-log line the WEB_RE parser accepts."""
    return (
        f'{ip} - - [23/Nov/2026:12:00:00 +0000] '
        f'"{method} {path} HTTP/1.1" {status} 1234 '
        f'"-" "{ua}" rt={rt}'
    )


def rules_fired(soc):
    """Set of rule names that fired during the test."""
    return {a["rule"] for a in soc.captured}
