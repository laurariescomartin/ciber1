from app.models.finding import Finding


DISCLOSURE_HEADERS = {
    "Server": {
        "id": "SEC-008",
        "title": "Server technology disclosure",
    },
    "X-Powered-By": {
        "id": "SEC-009",
        "title": "Technology stack disclosure",
    },
    "X-AspNet-Version": {
        "id": "SEC-010",
        "title": "ASP.NET version disclosure",
    },
    "X-AspNetMvc-Version": {
        "id": "SEC-011",
        "title": "ASP.NET MVC version disclosure",
    },
}


def scan_server_information(context):
    response = context.response
    findings = []

    disclosed_headers = {}

    for header, config in DISCLOSURE_HEADERS.items():
        if header in response.headers:
            value = response.headers[header]

            disclosed_headers[header] = value

            finding = Finding(
                id=config["id"],
                title=config["title"],
                severity="informational",
                category="Information Disclosure",
                evidence=(
                    f"The '{header}' response header exposes: {value}"
                ),
                recommendation=(
                    f"Review whether the '{header}' response header "
                    "needs to be exposed publicly and minimize unnecessary "
                    "technology or version information when possible."
                ),
            )

            findings.append(finding.model_dump())

    return {
        "url": context.final_url,
        "status_code": context.status_code,
        "disclosed_headers": disclosed_headers,
        "findings": findings,
    }
