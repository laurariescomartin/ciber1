from datetime import datetime

from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: int
    finding_id: str
    title: str
    severity: str
    category: str
    evidence: str
    recommendation: str

    likelihood: int
    impact: int
    risk_score: int
    risk_level: str


class ScanSummaryResponse(BaseModel):
    id: int
    url: str
    status_code: int
    total_findings: int
    created_at: datetime


class ScanResponse(ScanSummaryResponse):
    findings: list[FindingResponse]