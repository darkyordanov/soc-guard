"""Tests for the SSH (journal) detection rules."""
import importlib
import sys


def reload_soc_with_allowlist(monkeypatch, tmp_path, allow):
    """Re-import soc_guard with a specific SSH allowlist, capturing alerts."""
    monkeypatch.setenv("SOC_GUARD_ENV", str(tmp_path / "nonexistent.env"))
    monkeypatch.setenv("SOC_DB_PATH", str(tmp_path / "soc.db"))
    monkeypatch.setenv("SOC_ALLOWED_SSH_USERS", allow)
    if "soc_guard" in sys.modules:
        del sys.modules["soc_guard"]
    s = importlib.import_module("soc_guard")
    captured = []
    monkeypatch.setattr(s, "alert", lambda rule, sev, ip, summary, detail="", mitre="":
                        captured.append({"rule": rule, "severity": sev, "ip": ip, "mitre": mitre}))
    monkeypatch.setattr(s, "save_event", lambda **k: None)
    s.captured = captured
    s.win_ssh_fail.clear()
    s._last_alert.clear()
    return s


# ------------------------------------------------------- SSH_LOGIN_UNEXPECTED
def test_unexpected_login_fires(monkeypatch, tmp_path):
    s = reload_soc_with_allowlist(monkeypatch, tmp_path, allow="ghost")
    s.process_ssh("Accepted publickey for intruder from 45.9.1.2 port 51000 ssh2")
    rules = {a["rule"] for a in s.captured}
    assert "SSH_LOGIN_UNEXPECTED" in rules
    hit = [a for a in s.captured if a["rule"] == "SSH_LOGIN_UNEXPECTED"][0]
    assert hit["severity"] == "CRITICAL"
    assert "T1078" in hit["mitre"]


def test_allowlisted_login_is_silent(monkeypatch, tmp_path):
    s = reload_soc_with_allowlist(monkeypatch, tmp_path, allow="ghost")
    s.process_ssh("Accepted publickey for ghost from 45.9.1.2 port 51000 ssh2")
    assert {a["rule"] for a in s.captured} == set()


# ------------------------------------------------------------- SSH_BRUTEFORCE
def test_bruteforce_fires_over_threshold(monkeypatch, tmp_path):
    s = reload_soc_with_allowlist(monkeypatch, tmp_path, allow="ghost")
    for _ in range(10):
        s.process_ssh("Failed password for root from 185.3.4.5 port 2222 ssh2")
    assert "SSH_BRUTEFORCE" in {a["rule"] for a in s.captured}


def test_bruteforce_quiet_under_threshold(monkeypatch, tmp_path):
    s = reload_soc_with_allowlist(monkeypatch, tmp_path, allow="ghost")
    for _ in range(5):
        s.process_ssh("Failed password for root from 185.3.4.5 port 2222 ssh2")
    assert "SSH_BRUTEFORCE" not in {a["rule"] for a in s.captured}


def test_bruteforce_invalid_user_counts(monkeypatch, tmp_path):
    s = reload_soc_with_allowlist(monkeypatch, tmp_path, allow="ghost")
    for _ in range(10):
        s.process_ssh("Invalid user admin from 185.3.4.5 port 2222")
    assert "SSH_BRUTEFORCE" in {a["rule"] for a in s.captured}


def test_bruteforce_is_per_ip(monkeypatch, tmp_path):
    s = reload_soc_with_allowlist(monkeypatch, tmp_path, allow="ghost")
    for _ in range(9):
        s.process_ssh("Failed password for root from 1.1.1.1 port 2222 ssh2")
    for _ in range(9):
        s.process_ssh("Failed password for root from 2.2.2.2 port 2222 ssh2")
    assert "SSH_BRUTEFORCE" not in {a["rule"] for a in s.captured}
