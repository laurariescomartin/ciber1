import httpx

from app.scanners.context import ScanContext
from app.scanners.forms import scan_forms


def create_context(html):
    response = httpx.Response(
        200,
        headers={
            "Content-Type": "text/html",
        },
        content=html.encode("utf-8"),
        request=httpx.Request(
            "GET",
            "https://test.local",
        ),
    )

    return ScanContext(
        initial_url="https://test.local",
        response=response,
    )


def test_form_using_https_is_secure():
    html = """
    <html>
        <body>
            <form method="post" action="https://test.local/login">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        </body>
    </html>
    """

    context = create_context(html)

    result = scan_forms(context)

    assert result["forms_found"] == 1
    assert result["findings"] == []


def test_form_submitting_over_http_generates_finding():
    html = """
    <html>
        <body>
            <form method="post" action="http://test.local/login">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        </body>
    </html>
    """

    context = create_context(html)

    result = scan_forms(context)

    finding_ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert "SEC-012-1" in finding_ids


def test_form_submitting_to_external_origin_generates_finding():
    html = """
    <html>
        <body>
            <form method="post" action="https://external.test/login">
                <input type="text" name="username">
            </form>
        </body>
    </html>
    """

    context = create_context(html)

    result = scan_forms(context)

    finding_ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert "SEC-013-1" in finding_ids


def test_form_without_action_uses_current_url():
    html = """
    <html>
        <body>
            <form method="post">
                <input type="text" name="username">
            </form>
        </body>
    </html>
    """

    context = create_context(html)

    result = scan_forms(context)

    assert result["forms_found"] == 1
    assert result["forms"][0]["action"] == "https://test.local"
    assert result["findings"] == []