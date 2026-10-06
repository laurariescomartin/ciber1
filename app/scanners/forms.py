from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.models.finding import Finding


def scan_forms(context):
    response = context.response
    final_url = context.final_url

    soup = BeautifulSoup(
        context.html,
        "html.parser",
    )

    forms = []
    findings = []

    for index, form in enumerate(soup.find_all("form"), start=1):
        method = form.get("method", "get").upper()
        action = form.get("action", "")

        target_url = urljoin(final_url, action) if action else final_url
        target_scheme = urlparse(target_url).scheme.lower()

        form_data = {
            "id": index,
            "method": method,
            "action": target_url,
        }

        forms.append(form_data)

        if target_scheme != "https":
            findings.append(
                Finding(
                    id=f"SEC-012-{index}",
                    title="Form submitted over insecure HTTP",
                    severity="high",
                    category="Forms",
                    evidence=(
                        f"Form {index} submits data to '{target_url}', "
                        "which does not use HTTPS."
                    ),
                    recommendation=(
                        "Ensure forms submit sensitive information only over HTTPS."
                    ),
                ).model_dump()
            )

        page_host = urlparse(final_url).netloc
        target_host = urlparse(target_url).netloc

        if target_host and target_host != page_host:
            findings.append(
                Finding(
                    id=f"SEC-013-{index}",
                    title="Form submits data to an external origin",
                    severity="medium",
                    category="Forms",
                    evidence=(
                        f"Form {index} submits data to external origin "
                        f"'{target_host}'."
                    ),
                    recommendation=(
                        "Verify that external form destinations are intentional and trusted."
                    ),
                ).model_dump()
            )

    return {
        "url": final_url,
        "status_code": response.status_code,
        "forms_found": len(forms),
        "forms": forms,
        "findings": findings,
    }