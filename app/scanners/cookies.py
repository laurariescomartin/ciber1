from app.models.finding import Finding


def create_cookie_finding(
    cookie_name,
    issue,
    severity,
    recommendation,
):
    return Finding(
        id=f"COOKIE-{cookie_name}-{issue}",
        title=f"Cookie '{cookie_name}' {issue}",
        severity=severity,
        category="Cookies",
        evidence=f"The cookie '{cookie_name}' {issue}.",
        recommendation=recommendation,
    )


def scan_cookies(context):
    response = context.response
    findings = []

    set_cookie_headers = response.headers.get_list("set-cookie")

    for set_cookie in set_cookie_headers:
        cookie_parts = [
            part.strip()
            for part in set_cookie.split(";")
        ]

        if not cookie_parts:
            continue

        cookie_name = cookie_parts[0].split("=", 1)[0].strip()

        attributes = {}

        for part in cookie_parts[1:]:
            key, separator, value = part.partition("=")

            key = key.strip().lower()
            value = value.strip() if separator else None

            attributes[key] = value

        if "secure" not in attributes:
            findings.append(
                create_cookie_finding(
                    cookie_name,
                    "is missing the Secure attribute",
                    "medium",
                    (
                        "Add the Secure attribute so the cookie "
                        "is only sent over HTTPS connections."
                    ),
                ).model_dump()
            )

        if "httponly" not in attributes:
            findings.append(
                create_cookie_finding(
                    cookie_name,
                    "is missing the HttpOnly attribute",
                    "medium",
                    (
                        "Add the HttpOnly attribute when the cookie "
                        "does not need to be accessed by client-side JavaScript."
                    ),
                ).model_dump()
            )

        same_site = attributes.get("samesite")

        if same_site is None:
            findings.append(
                create_cookie_finding(
                    cookie_name,
                    "is missing the SameSite attribute",
                    "low",
                    (
                        "Configure an appropriate SameSite policy "
                        "such as Lax or Strict depending on the "
                        "application's requirements."
                    ),
                ).model_dump()
            )

        elif same_site.lower() not in {"lax", "strict", "none"}:
            findings.append(
                create_cookie_finding(
                    cookie_name,
                    "has an invalid SameSite value",
                    "low",
                    (
                        "Use a valid SameSite value such as "
                        "Lax, Strict, or None."
                    ),
                ).model_dump()
            )

        elif same_site.lower() == "none" and "secure" not in attributes:
            findings.append(
                create_cookie_finding(
                    cookie_name,
                    "uses SameSite=None without Secure",
                    "medium",
                    (
                        "Cookies using SameSite=None should also "
                        "include the Secure attribute."
                    ),
                ).model_dump()
            )

    return {
        "url": context.final_url,
        "status_code": context.status_code,
        "cookies_found": len(set_cookie_headers),
        "findings": findings,
    }
