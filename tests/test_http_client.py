import httpx
import pytest
import respx

from app.http.client import (
    MAX_RESPONSE_SIZE,
    fetch_url,
)


@respx.mock
@pytest.mark.asyncio
async def test_fetch_url_uses_safe_user_agent():
    route = respx.get(
        "https://example.com"
    ).mock(
        return_value=httpx.Response(
            200,
            text="Hello",
        )
    )

    response = await fetch_url(
        "https://example.com"
    )

    assert response.status_code == 200

    request = route.calls[0].request

    assert (
        request.headers["user-agent"]
        == "CyberSentinel/0.1 "
        "(defensive web security scanner)"
    )


@respx.mock
@pytest.mark.asyncio
async def test_fetch_url_follows_safe_redirect():
    respx.get(
        "https://example.com"
    ).mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": "https://example.org"
            },
        )
    )

    respx.get(
        "https://example.org"
    ).mock(
        return_value=httpx.Response(
            200,
            text="Hello",
        )
    )

    response = await fetch_url(
        "https://example.com"
    )

    assert response.status_code == 200


@respx.mock
@pytest.mark.asyncio
async def test_fetch_url_rejects_large_response():
    respx.get(
        "https://example.com"
    ).mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Length": str(
                    MAX_RESPONSE_SIZE + 1
                )
            },
        )
    )

    with pytest.raises(ValueError):
        await fetch_url(
            "https://example.com"
        )


@respx.mock
@pytest.mark.asyncio
async def test_fetch_url_rejects_too_many_redirects():
    for index in range(5):
        current_url = (
            "https://example.com"
            if index == 0
            else f"https://example.com/{index}"
        )

        next_url = (
            f"https://example.com/{index + 1}"
        )

        respx.get(
            current_url
        ).mock(
            return_value=httpx.Response(
                302,
                headers={
                    "Location": next_url
                },
            )
        )

    with pytest.raises(ValueError):
        await fetch_url(
            "https://example.com"
        )


@respx.mock
@pytest.mark.asyncio
async def test_fetch_url_rejects_redirect_to_private_ip():
    respx.get(
        "https://example.com"
    ).mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": "http://127.0.0.1"
            },
        )
    )

    with pytest.raises(ValueError):
        await fetch_url(
            "https://example.com"
        )