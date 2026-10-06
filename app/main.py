from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select

from httpx import (
    ConnectError,
    ConnectTimeout,
    ReadTimeout,
    RemoteProtocolError,
)

from app.assistant.assistant import SecurityAssistant
from app.database.connection import SessionLocal
from app.database.models import Finding, Scan
from app.database.repository import save_scan
from app.models.scan import (
    ScanResponse,
    ScanSummaryResponse,
)
from app.scanners.scan import run_full_scan
from app.security.url_validator import validate_url


app = FastAPI(
    title="CyberSentinel",
    description="Web application security analysis platform",
    version="0.1.0",
)

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)

assistant = SecurityAssistant()


class ScanRequest(BaseModel):
    url: str


class AssistantRequest(BaseModel):
    question: str
    top_k: int = 3


@app.get("/")
async def dashboard():
    return FileResponse("app/templates/index.html")


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
    }


@app.post("/scan")
async def full_scan(request: ScanRequest):
    try:
        validated_url = validate_url(request.url)

        result = await run_full_scan(validated_url)

        save_scan(result)

        return result

    except (ConnectTimeout, ReadTimeout):
        raise HTTPException(
            status_code=504,
            detail="The target server did not respond within the timeout.",
        )

    except ConnectError:
        raise HTTPException(
            status_code=502,
            detail="Could not connect to the target server.",
        )

    except RemoteProtocolError:
        raise HTTPException(
            status_code=502,
            detail="The target server returned an invalid HTTP response.",
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@app.get(
    "/scans",
    response_model=list[ScanSummaryResponse],
)
async def get_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status_code: int | None = Query(
        default=None,
        ge=100,
        le=599,
    ),
):
    with SessionLocal() as session:
        query = select(Scan)

        if status_code is not None:
            query = query.where(
                Scan.status_code == status_code
            )

        query = (
            query
            .order_by(Scan.created_at.desc())
            .offset(offset)
            .limit(limit)
        )

        scans = session.scalars(query).all()

        return [
            {
                "id": scan.id,
                "url": scan.url,
                "status_code": scan.status_code,
                "total_findings": scan.total_findings,
                "created_at": scan.created_at,
            }
            for scan in scans
        ]


@app.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
)
async def get_scan(scan_id: int):
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)

        if scan is None:
            raise HTTPException(
                status_code=404,
                detail="Scan not found",
            )

        return {
            "id": scan.id,
            "url": scan.url,
            "status_code": scan.status_code,
            "total_findings": scan.total_findings,
            "created_at": scan.created_at,
            "findings": [
                {
                    "id": finding.id,
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "category": finding.category,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                    "likelihood": finding.likelihood,
                    "impact": finding.impact,
                    "risk_score": finding.risk_score,
                    "risk_level": finding.risk_level,
                }
                for finding in scan.findings
            ],
        }


@app.get("/stats")
async def get_stats():
    with SessionLocal() as session:
        total_scans = session.scalar(
            select(func.count(Scan.id))
        ) or 0

        total_findings = session.scalar(
            select(func.count(Finding.id))
        ) or 0

        risk_distribution = {
            "very_low": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "very_high": 0,
            "critical": 0,
        }

        results = session.execute(
            select(
                Finding.risk_level,
                func.count(Finding.id),
            ).group_by(Finding.risk_level)
        ).all()

        for risk_level, count in results:
            if risk_level in risk_distribution:
                risk_distribution[risk_level] = count

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "risk_distribution": risk_distribution,
        }


@app.post("/assistant")
async def security_assistant(
    request: AssistantRequest,
):
    try:
        return assistant.answer(
            question=request.question,
            top_k=request.top_k,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )