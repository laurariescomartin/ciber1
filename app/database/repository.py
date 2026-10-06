from app.database.connection import SessionLocal
from app.database.models import Finding, Scan


def save_scan(scan_result):
    findings = scan_result["findings"]

    with SessionLocal() as session:
        scan = Scan(
            url=scan_result["url"],
            status_code=scan_result["status_code"],
            total_findings=scan_result["total_findings"],
        )

        session.add(scan)
        session.flush()

        for finding in findings:
            database_finding = Finding(
                scan_id=scan.id,
                finding_id=finding["id"],
                title=finding["title"],
                severity=finding["severity"],
                category=finding["category"],
                evidence=finding["evidence"],
                recommendation=finding["recommendation"],
                likelihood=finding["likelihood"],
                impact=finding["impact"],
                risk_score=finding["risk_score"],
                risk_level=finding["risk_level"],
            )

            session.add(database_finding)

        session.commit()

        return scan.id