import httpx

from app.scanners.context import ScanContext
from app.scanners.headers import scan_security_headers
from app.scanners.cookies import scan_cookies
from app.scanners.https import scan_https
from app.scanners.server import scan_server_information
from app.scanners.forms import scan_forms
from app.security.risk import (
    assess_findings,
    build_overall_risk,
    build_risk_summary,
)
from app.http.client import fetch_url

async def run_full_scan(url: str):
    response = await fetch_url(url)

    context = ScanContext(
        initial_url=url,
        response=response,
    )

    headers_result = scan_security_headers(context)
    cookies_result = scan_cookies(context)
    https_result = scan_https(context)
    server_result = scan_server_information(context)
    forms_result = scan_forms(context)

    findings = (
        headers_result["findings"]
        + cookies_result["findings"]
        + https_result["findings"]
        + server_result["findings"]
        + forms_result["findings"]
    )

    findings = assess_findings(findings)

    risk_summary = build_risk_summary(findings)
    overall_risk = build_overall_risk(findings)

    return {
        "url": url,
        "status_code": response.status_code,
        "risk_summary": risk_summary,
        "overall_risk": overall_risk,
        "total_findings": len(findings),
        "findings": findings,
    }