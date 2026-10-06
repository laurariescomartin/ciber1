import pytest

from app.security.url_validator import validate_url


def test_https_url_is_allowed():
    result = validate_url("https://example.com")

    assert result == "https://example.com"


def test_http_url_is_allowed():
    result = validate_url("http://example.com")

    assert result == "http://example.com"


def test_ftp_url_is_rejected():
    with pytest.raises(ValueError):
        validate_url("ftp://example.com")


def test_localhost_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://localhost:8000")


def test_loopback_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://127.0.0.1:8000")


def test_private_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://192.168.1.10")


def test_missing_hostname_is_rejected():
    with pytest.raises(ValueError):
        validate_url("https://")


def test_unspecified_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://0.0.0.0")


def test_link_local_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://169.254.1.1")


def test_multicast_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://224.0.0.1")