import httpx

from app.scanners.context import ScanContext
from app.scanners.headers import scan_security_headers


def test_missing_security_headers():
    response = httpx.Response(
        200,
        headers={
            "Content-Type": "text/html"
        },
        request=httpx.Request(
            "GET",
            "https://test.local"
        ),
    )

    context = ScanContext(
        initial_url="https://test.local",
        response=response,
    )

    result = scan_security_headers(context)

    finding_ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert "SEC-001" in finding_ids
    assert "SEC-002" in finding_ids
    assert "SEC-003" in finding_ids
    assert "SEC-004" in finding_ids
    assert "SEC-005" in finding_ids


def test_security_headers_are_not_reported_when_present():
    response = httpx.Response(
        200,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        },
        request=httpx.Request(
            "GET",
            "https://test.local"
        ),
    )

    context = ScanContext(
        initial_url="https://test.local",
        response=response,
    )

    result = scan_security_headers(context)

    assert result["findings"] == []