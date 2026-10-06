import httpx

from app.scanners.context import ScanContext
from app.scanners.server import scan_server_information


def create_context(headers):
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


def test_server_headers_are_detected():
    context = create_context(
        {
            "Server": "Apache",
            "X-Powered-By": "PHP",
        }
    )

    result = scan_server_information(context)

    finding_ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert "SEC-008" in finding_ids
    assert "SEC-009" in finding_ids


def test_server_headers_are_not_reported_when_absent():
    context = create_context(
        {
            "Content-Type": "text/html",
        }
    )

    result = scan_server_information(context)

    assert result["findings"] == []


def test_disclosed_headers_are_returned():
    context = create_context(
        {
            "Server": "Apache",
            "X-Powered-By": "PHP",
        }
    )

    result = scan_server_information(context)

    assert result["disclosed_headers"]["Server"] == "Apache"
    assert result["disclosed_headers"]["X-Powered-By"] == "PHP"