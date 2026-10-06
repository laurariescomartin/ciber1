import httpx
import pytest
from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import Scan
from app.main import app


@pytest.mark.asyncio
async def test_scan_is_persisted(monkeypatch):
    async def fake_run_full_scan(url):
        return {
            "url": url,
            "status_code": 200,
            "risk_summary": {
                "very_low": 0,
                "low": 0,
                "medium": 1,
                "high": 0,
                "very_high": 0,
                "critical": 0,
            },
            "overall_risk": {
                "score": 9,
                "level": "medium",
            },
            "total_findings": 1,
            "findings": [
                {
                    "id": "SEC-001",
                    "title": "Missing CSP",
                    "severity": "medium",
                    "category": "Security Headers",
                    "evidence": "CSP header missing.",
                    "recommendation": "Add CSP.",
                    "likelihood": 3,
                    "impact": 3,
                    "risk_score": 9,
                    "risk_level": "medium",
                }
            ],
        }

    monkeypatch.setattr(
        "app.main.validate_url",
        lambda url: url,
    )

    monkeypatch.setattr(
        "app.main.run_full_scan",
        fake_run_full_scan,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/scan",
            json={"url": "https://example.com"},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["total_findings"] == 1

    with SessionLocal() as session:
        scan = session.scalars(
            select(Scan)
            .where(Scan.url == "https://example.com")
            .order_by(Scan.id.desc())
        ).first()

        assert scan is not None
        assert scan.total_findings == 1
        assert len(scan.findings) == 1

        saved_finding = scan.findings[0]

        assert saved_finding.finding_id == "SEC-001"
        assert saved_finding.likelihood == 3
        assert saved_finding.impact == 3
        assert saved_finding.risk_score == 9
        assert saved_finding.risk_level == "medium"