import sys
sys.path.insert(0, ".")

from app.backend.batch import parse_csv, parse_json


def test_parse_csv_simple():
    iocs = parse_csv("8.8.8.8\ngoogle.com\n1.1.1.1")
    assert len(iocs) == 3
    assert "8.8.8.8" in iocs
    assert "google.com" in iocs


def test_parse_csv_with_commas():
    iocs = parse_csv("8.8.8.8,google.com,1.1.1.1")
    assert len(iocs) == 3


def test_parse_csv_empty():
    iocs = parse_csv("")
    assert iocs == []


def test_parse_csv_whitespace():
    iocs = parse_csv("  8.8.8.8  \n  google.com  ")
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_json_array():
    iocs = parse_json('["8.8.8.8", "google.com", "1.1.1.1"]')
    assert len(iocs) == 3


def test_parse_json_object_with_iocs_key():
    iocs = parse_json('{"iocs": ["8.8.8.8", "google.com"]}')
    assert len(iocs) == 2


def test_parse_json_empty_array():
    iocs = parse_json("[]")
    assert iocs == []


def test_parse_json_indicators_key():
    iocs = parse_json('{"indicators": ["8.8.8.8"]}')
    assert iocs == ["8.8.8.8"]


def test_parse_json_mixed_whitespace():
    iocs = parse_json('["  8.8.8.8  ", "google.com"]')
    assert "8.8.8.8" in iocs
    assert "google.com" in iocs
