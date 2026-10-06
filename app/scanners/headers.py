from app.models.finding import Finding


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "id": "SEC-001",
        "title": "Missing Content-Security-Policy",
        "severity": "medium",
        "recommendation": (
            "Define a restrictive Content-Security-Policy to reduce "
            "the risk of cross-site scripting and other code injection attacks."
        ),
    },
    "Strict-Transport-Security": {
        "id": "SEC-002",
        "title": "Missing Strict-Transport-Security",
        "severity": "medium",
        "recommendation": (
            "Enable HTTP Strict Transport Security (HSTS) to instruct "
            "browsers to use HTTPS for future connections."
        ),
    },
    "X-Content-Type-Options": {
        "id": "SEC-003",
        "title": "Missing X-Content-Type-Options",
        "severity": "low",
        "recommendation": (
            "Set X-Content-Type-Options to 'nosniff' to prevent "
            "browsers from MIME type sniffing."
        ),
    },
    "X-Frame-Options": {
        "id": "SEC-004",
        "title": "Missing X-Frame-Options",
        "severity": "medium",
        "recommendation": (
            "Configure X-Frame-Options or an appropriate CSP frame-ancestors "
            "policy to reduce clickjacking risk."
        ),
    },
    "Referrer-Policy": {
        "id": "SEC-005",
        "title": "Missing Referrer-Policy",
        "severity": "low",
        "recommendation": (
            "Configure a suitable Referrer-Policy to control how much "
            "referrer information is exposed to other origins."
        ),
    },
}


def scan_security_headers(context):
    response = context.response

    findings = []

    for header, config in SECURITY_HEADERS.items():

        if header not in response.headers:
            finding = Finding(
                id=config["id"],
                title=config["title"],
                severity=config["severity"],
                category="Security Headers",
                evidence=f"The {header} header was not present in the HTTP response.",
                recommendation=config["recommendation"],
            )

            findings.append(finding.model_dump())

    return {
    "url": context.final_url,
    "status_code": context.status_code,
    "findings": findings,   
    }