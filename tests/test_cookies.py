import httpx

from app.scanners.context import ScanContext
from app.scanners.cookies import scan_cookies


def create_context(set_cookie=None):
    headers = {}

    if set_cookie:
        headers["Set-Cookie"] = set_cookie

    response = httpx.Response(
        200,
        headers=headers,
        request=httpx.Request(
            "GET",
            "https://test.local"
        ),
    )

    return ScanContext(
        initial_url="https://test.local",
        response=response,
    )


def test_cookie_without_security_attributes():
    context = create_context(
        "session=abc123; Path=/"
    )

    result = scan_cookies(context)

    finding_ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert any(
        "Secure" in finding_id
        for finding_id in finding_ids
    )

    assert any(
        "HttpOnly" in finding_id
        for finding_id in finding_ids
    )

    assert any(
        "SameSite" in finding_id
        for finding_id in finding_ids
    )


def test_secure_cookie_configuration():
    context = create_context(
        "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
    )

    result = scan_cookies(context)

    assert result["findings"] == []


def test_cookie_count():
    context = create_context(
        "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
    )

    result = scan_cookies(context)

    assert result["cookies_found"] == 1