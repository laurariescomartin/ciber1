from urllib.parse import urljoin

import httpx

from app.security.url_validator import validate_url


REQUEST_TIMEOUT = httpx.Timeout(
    connect=5.0,
    read=10.0,
    write=5.0,
    pool=5.0,
)

MAX_RESPONSE_SIZE = 2 * 1024 * 1024

USER_AGENT = (
    "CyberSentinel/0.1 "
    "(defensive web security scanner)"
)


def create_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        follow_redirects=False,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
        },
    )


async def fetch_url(url: str) -> httpx.Response:
    current_url = validate_url(url)

    async with create_http_client() as client:
        for _ in range(5):
            response = await client.get(
                current_url,
            )

            content_length = response.headers.get(
                "content-length"
            )

            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = 0

                if declared_size > MAX_RESPONSE_SIZE:
                    raise ValueError(
                        "The response is too large to process."
                    )

            if response.is_redirect:
                location = response.headers.get("location")

                if not location:
                    raise ValueError(
                        "The server returned a redirect without a location."
                    )

                next_url = urljoin(
                    current_url,
                    location,
                )

                validate_url(next_url)

                current_url = next_url
                continue

            content = response.content

            if len(content) > MAX_RESPONSE_SIZE:
                raise ValueError(
                    "The response is too large to process."
                )

            return response

        raise ValueError(
            "Too many redirects."
        )