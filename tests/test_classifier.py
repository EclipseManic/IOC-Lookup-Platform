import sys
sys.path.insert(0, ".")

from app.backend.classifier import classify_ioc, refang, defang


def test_refang_hxxp():
    assert refang("hxxp://evil.com") == "http://evil.com"


def test_refang_hxxps():
    assert refang("hxxps://evil.com") == "https://evil.com"


def test_refang_bracket_dot():
    assert refang("evil[.]com") == "evil.com"


def test_refang_bracket_colon():
    assert refang("http[:]//evil.com") == "http://evil.com"


def test_refang_backslash_dot():
    assert refang(r"evil\.com") == "evil.com"


def test_classify_ipv4():
    assert classify_ioc("8.8.8.8") == "ipv4"


def test_classify_domain():
    assert classify_ioc("google.com") == "domain"


def test_classify_url():
    assert classify_ioc("https://evil.com/path") == "url"


def test_classify_md5():
    assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "md5"


def test_classify_sha1():
    h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert classify_ioc(h) == "sha1"


def test_classify_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert classify_ioc(h) == "sha256"


def test_classify_email():
    assert classify_ioc("user@evil.com") == "email"


def test_classify_cve():
    assert classify_ioc("CVE-2024-1234") == "cve"


def test_classify_ipv6():
    assert classify_ioc("fe80:0000:0000:0000:0000:0000:0000:0001") == "ipv6"


def test_classify_unknown():
    assert classify_ioc("not an ioc at all!") == "unknown"


def test_defang():
    assert defang("http://evil.com") == "hxxp://evil[.]com"


def test_defang_https():
    assert defang("https://evil.com") == "hxxps://evil[.]com"


def test_refang_and_classify():
    v = refang("hxxps://evil[.]com/path")
    assert v == "https://evil.com/path"
    assert classify_ioc(v) == "url"


def test_empty_input():
    assert classify_ioc("") == "unknown"


def test_md5_vs_sha1_length():
    assert classify_ioc("a" * 32) == "md5"
    assert classify_ioc("a" * 40) == "sha1"
    assert classify_ioc("a" * 64) == "sha256"


def test_asn():
    assert classify_ioc("AS12345") == "asn"
