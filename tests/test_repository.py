from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import Finding, Scan
from app.database.repository import save_scan


def test_save_scan():
    scan_result = {
        "url": "https://test.local",
        "status_code": 200,
        "total_findings": 2,
        "findings": [
            {
                "id": "SEC-001",
                "title": "Missing CSP",
                "severity": "medium",
                "category": "Security Headers",
                "evidence": "CSP header missing.",
                "recommendation": "Add a Content-Security-Policy header.",
                "likelihood": 3,
                "impact": 3,
                "risk_score": 9,
                "risk_level": "medium",
            },
            {
                "id": "SEC-002",
                "title": "Missing HSTS",
                "severity": "medium",
                "category": "Security Headers",
                "evidence": "HSTS header missing.",
                "recommendation": "Enable HSTS.",
                "likelihood": 3,
                "impact": 3,
                "risk_score": 9,
                "risk_level": "medium",
            },
        ],
    }

    scan_id = save_scan(scan_result)

    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)

        assert scan is not None
        assert scan.url == "https://test.local"
        assert scan.total_findings == 2
        assert scan.status_code == 200

        findings = session.scalars(
            select(Finding).where(Finding.scan_id == scan_id)
        ).all()

        assert len(findings) == 2