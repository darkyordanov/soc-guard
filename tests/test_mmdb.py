"""Tests for the from-scratch MaxMind .mmdb reader (src/mmdb.py).

Uses MaxMind's official test databases (tests/data/*.mmdb) so the parser is
checked against known-good fixtures with documented expected values.
"""
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import mmdb  # noqa: E402

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CITY_DB = os.path.join(DATA, "GeoIP2-City-Test.mmdb")
ASN_DB = os.path.join(DATA, "GeoLite2-ASN-Test.mmdb")

pytestmark = pytest.mark.skipif(
    not (os.path.exists(CITY_DB) and os.path.exists(ASN_DB)),
    reason="MaxMind test databases not present",
)


def test_city_lookup_known_ip():
    # 81.2.69.160 is a documented London, GB record in the City test DB
    rec = mmdb.reader(CITY_DB).get("81.2.69.160")
    assert rec is not None
    assert rec["country"]["iso_code"] == "GB"
    assert rec["city"]["names"]["en"] == "London"


def test_asn_lookup_known_ip():
    # 1.128.0.0 is Telstra (AS1221) in the ASN test DB
    rec = mmdb.reader(ASN_DB).get("1.128.0.0")
    assert rec is not None
    assert rec["autonomous_system_number"] == 1221


def test_private_ip_returns_none_or_empty():
    # a private address is not in the public test DB
    assert mmdb.reader(CITY_DB).get("10.0.0.1") is None


def test_reader_is_cached():
    a = mmdb.reader(CITY_DB)
    b = mmdb.reader(CITY_DB)
    assert a is b  # same path returns the cached reader


def test_record_size_handling():
    # the City test DB exercises the 28-bit record path; a successful lookup
    # proves the node reader handles it
    rec = mmdb.reader(CITY_DB).get("2.125.160.216")  # Boxford, GB
    assert rec is not None
    assert rec["country"]["iso_code"] == "GB"
