from urllib.parse import urlparse

from app.models.finding import Finding


def scan_https(context):
    initial_url = context.initial_url
    final_url = context.final_url

    parsed_initial = urlparse(initial_url)
    parsed_final = urlparse(final_url)

    initial_scheme = parsed_initial.scheme.lower()
    final_scheme = parsed_final.scheme.lower()

    findings = []

    # Check the initial URL
    if initial_scheme != "https":
        findings.append(
            Finding(
                id="SEC-006",
                title="Insecure HTTP connection",
                severity="high",
                category="HTTPS",
                evidence=(
                    f"The initial URL uses the '{initial_scheme}' scheme "
                    "instead of HTTPS."
                ),
                recommendation=(
                    "Use HTTPS to protect data transmitted between the client "
                    "and the server."
                ),
            ).model_dump()
        )

    # Check the final URL after redirects
    if initial_scheme != final_scheme and final_scheme != "https":
        findings.append(
            Finding(
                id="SEC-007",
                title="Redirect chain does not end in HTTPS",
                severity="high",
                category="HTTPS",
                evidence=(
                    f"The request started with '{initial_url}' but the final URL "
                    f"after redirects was '{final_url}'."
                ),
                recommendation=(
                    "Ensure that the complete redirect chain ends in HTTPS."
                ),
            ).model_dump()
        )

    return {
        "initial_url": initial_url,
        "final_url": final_url,
        "status_code": context.status_code,
        "https_enabled": final_scheme == "https",
        "findings": findings,
    }