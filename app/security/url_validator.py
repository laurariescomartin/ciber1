from ipaddress import ip_address
import socket
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
}


def is_blocked_ip(address: str) -> bool:
    ip = ip_address(address)

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def resolve_hostname(hostname: str) -> list[str]:
    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise ValueError(
            "The hostname could not be resolved."
        ) from error

    resolved_ips = []

    for address in addresses:
        resolved_ip = address[4][0]

        if resolved_ip not in resolved_ips:
            resolved_ips.append(resolved_ip)

    if not resolved_ips:
        raise ValueError(
            "The hostname could not be resolved."
        )

    return resolved_ips


def validate_url(url: str) -> str:
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.hostname:
        raise ValueError(
            "The URL must contain a valid hostname."
        )

    hostname = parsed.hostname.lower()

    if hostname in BLOCKED_HOSTNAMES:
        raise ValueError(
            "Local targets are not allowed."
        )

    try:
        if is_blocked_ip(hostname):
            raise ValueError(
                "Private or local network targets are not allowed."
            )
    except ValueError as error:
        if str(error) == (
            "Private or local network targets are not allowed."
        ):
            raise

    resolved_ips = resolve_hostname(hostname)

    for resolved_ip in resolved_ips:
        if is_blocked_ip(resolved_ip):
            raise ValueError(
                "The hostname resolves to a private or local IP address."
            )

    return url