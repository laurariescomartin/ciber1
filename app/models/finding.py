from typing import Literal

from pydantic import BaseModel


Severity = Literal[
    "high",
    "medium",
    "low",
    "informational",
]


RiskLevel = Literal[
    "very_low",
    "low",
    "medium",
    "high",
    "very_high",
    "critical",
]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    evidence: str
    recommendation: str

    likelihood: int = 0
    impact: int = 0
    risk_score: int = 0
    risk_level: RiskLevel = "very_low"