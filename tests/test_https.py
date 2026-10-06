import httpx

from app.scanners.context import ScanContext
from app.scanners.https import scan_https


def create_context(initial_url, final_url):
    response = httpx.Response(
        200,
        request=httpx.Request(
            "GET",
            final_url
        ),
    )

    return ScanContext(
        initial_url=initial_url,
        response=response,
    )


def test_https_url_is_secure():
    context = create_context(
        "https://test.local",
        "https://test.local"
    )

    result = scan_https(context)

    assert result["https_enabled"] is True
    assert result["findings"] == []


def test_http_url_generates_security_finding():
    context = create_context(
        "http://test.local",
        "http://test.local"
    )

    result = scan_https(context)

    finding_ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert "SEC-006" in finding_ids
    assert result["https_enabled"] is False


def test_http_redirecting_to_https():
    context = create_context(
        "http://test.local",
        "https://test.local"
    )

    result = scan_https(context)

    finding_ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert "SEC-006" in finding_ids
    assert "SEC-007" not in finding_ids
    assert result["https_enabled"] is True