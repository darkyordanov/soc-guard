"""Tests for the web (nginx/apache access-log) detection rules."""
import pytest

from conftest import nginx_line, rules_fired


# ----------------------------------------------------------------- WEB_EXPLOIT
@pytest.mark.parametrize("path", [
    "/?id=1%20union%20select%201,2,3",            # SQLi, url-encoded
    "/?id=1'%20or%20'1'='1",                        # SQLi tautology (encoded spaces)
    "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",  # XSS (encoded)
    "/download?f=../../../../etc/passwd",           # path traversal
    "/?x=;%20cat%20/etc/shadow",                    # command injection
])
def test_web_exploit_fires(soc, path):
    soc.process_web(nginx_line(path=path, status=200))
    assert "WEB_EXPLOIT" in rules_fired(soc), f"expected WEB_EXPLOIT for {path}"


@pytest.mark.parametrize("path", [
    "/about-us/team",
    "/blog/2026/my-article",
    "/static/css/base.css",
    "/products?category=books&sort=price",
])
def test_web_exploit_no_false_positive(soc, path):
    soc.process_web(nginx_line(path=path, status=200))
    assert "WEB_EXPLOIT" not in rules_fired(soc), f"false positive on {path}"


def test_web_exploit_maps_to_t1190(soc):
    soc.process_web(nginx_line(path="/?id=1%20union%20select%201", status=200))
    hit = [a for a in soc.captured if a["rule"] == "WEB_EXPLOIT"][0]
    assert "T1190" in hit["mitre"]
    assert hit["severity"] == "HIGH"


# ------------------------------------------------------------- WEB_SCANNER_PATH
@pytest.mark.parametrize("path", [
    "/.env",
    "/.git/config",
    "/wp-admin/",
    "/phpmyadmin/index.php",
    "/actuator/health",
])
def test_scanner_path_fires(soc, path):
    soc.process_web(nginx_line(path=path, status=404))
    assert "WEB_SCANNER_PATH" in rules_fired(soc), f"expected scanner probe for {path}"


def test_scanner_path_is_medium(soc):
    soc.process_web(nginx_line(path="/.env", status=404))
    hit = [a for a in soc.captured if a["rule"] == "WEB_SCANNER_PATH"][0]
    assert hit["severity"] == "MEDIUM"
    assert "T1595" in hit["mitre"]


# -------------------------------------------------------------- WEB_SCANNER_404
def test_404_flood_fires_over_threshold(soc):
    # default threshold: >= 15 x 404 in 60s per IP
    for i in range(16):
        soc.process_web(nginx_line(ip="198.51.100.9", path=f"/admin{i}", status=404))
    assert "WEB_SCANNER_404" in rules_fired(soc)


def test_404_flood_quiet_under_threshold(soc):
    for i in range(5):
        soc.process_web(nginx_line(ip="198.51.100.9", path=f"/admin{i}", status=404))
    assert "WEB_SCANNER_404" not in rules_fired(soc)


def test_404_flood_is_per_ip(soc):
    # 10 from one IP + 10 from another: neither crosses the 15 threshold alone
    for i in range(10):
        soc.process_web(nginx_line(ip="198.51.100.1", path=f"/a{i}", status=404))
    for i in range(10):
        soc.process_web(nginx_line(ip="198.51.100.2", path=f"/b{i}", status=404))
    assert "WEB_SCANNER_404" not in rules_fired(soc)


# --------------------------------------------------------------- HTTP_5XX_SPIKE
def test_5xx_spike_fires(soc):
    # default: >= 5 server errors in 300s, site-wide
    for i in range(6):
        soc.process_web(nginx_line(ip=f"203.0.113.{i}", path="/api", status=500))
    assert "HTTP_5XX_SPIKE" in rules_fired(soc)


def test_5xx_spike_quiet_under_threshold(soc):
    for i in range(3):
        soc.process_web(nginx_line(ip=f"203.0.113.{i}", path="/api", status=503))
    assert "HTTP_5XX_SPIKE" not in rules_fired(soc)


def test_2xx_never_alerts(soc):
    for i in range(30):
        soc.process_web(nginx_line(ip="203.0.113.5", path="/", status=200))
    assert rules_fired(soc) == set()
