from typing import Literal


RiskLevel = Literal[
    "very_low",
    "low",
    "medium",
    "high",
    "very_high",
    "critical",
]


RISK_PROFILES = {
    # Security headers
    "SEC-001": {"likelihood": 3, "impact": 3},  # CSP
    "SEC-002": {"likelihood": 3, "impact": 3},  # HSTS
    "SEC-003": {"likelihood": 2, "impact": 2},  # nosniff
    "SEC-004": {"likelihood": 3, "impact": 3},  # clickjacking
    "SEC-005": {"likelihood": 2, "impact": 2},  # referrer policy

    # HTTPS
    "SEC-006": {"likelihood": 4, "impact": 5},
    "SEC-007": {"likelihood": 4, "impact": 5},

    # Server disclosure
    "SEC-008": {"likelihood": 1, "impact": 1},
    "SEC-009": {"likelihood": 1, "impact": 1},
    "SEC-010": {"likelihood": 1, "impact": 1},
    "SEC-011": {"likelihood": 1, "impact": 1},

    # Forms
    "SEC-012": {"likelihood": 4, "impact": 5},
    "SEC-013": {"likelihood": 2, "impact": 4},
}


def get_risk_level(score: int) -> RiskLevel:
    if score <= 2:
        return "very_low"

    if score <= 4:
        return "low"

    if score <= 9:
        return "medium"

    if score <= 12:
        return "high"

    if score <= 16:
        return "very_high"

    return "critical"


def calculate_risk_score(
    likelihood: int,
    impact: int,
) -> int:
    if not 1 <= likelihood <= 5:
        raise ValueError("Likelihood must be between 1 and 5.")

    if not 1 <= impact <= 5:
        raise ValueError("Impact must be between 1 and 5.")

    return likelihood * impact


def assess_finding(finding: dict) -> dict:
    finding_id = finding["id"]

    profile = RISK_PROFILES.get(finding_id)

    if profile is None:
        if finding["severity"] == "informational":
            likelihood = 0
            impact = 0
            score = 0
            risk_level = "very_low"
        else:
            likelihood = 3
            impact = 3
            score = calculate_risk_score(
                likelihood,
                impact,
            )
            risk_level = get_risk_level(score)

    else:
        likelihood = profile["likelihood"]
        impact = profile["impact"]

        score = calculate_risk_score(
            likelihood,
            impact,
        )

        risk_level = get_risk_level(score)

    return {
        **finding,
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": score,
        "risk_level": risk_level,
    }


def assess_findings(findings: list[dict]) -> list[dict]:
    return [
        assess_finding(finding)
        for finding in findings
    ]


def build_risk_summary(findings: list[dict]) -> dict:
    summary = {
        "very_low": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "very_high": 0,
        "critical": 0,
    }

    for finding in findings:
        risk_level = finding["risk_level"]

        if risk_level in summary:
            summary[risk_level] += 1

    return summary


def calculate_overall_risk_score(
    findings: list[dict],
) -> int:
    if not findings:
        return 0

    scores = [
        finding["risk_score"]
        for finding in findings
        if finding["risk_score"] > 0
    ]

    if not scores:
        return 0

    return max(scores)


def build_overall_risk(findings: list[dict]) -> dict:
    score = calculate_overall_risk_score(findings)

    return {
        "score": score,
        "level": get_risk_level(score) if score > 0 else "very_low",
    }