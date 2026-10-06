import pytest

from app.security.risk import (
    assess_finding,
    assess_findings,
    build_overall_risk,
    build_risk_summary,
    calculate_overall_risk_score,
    calculate_risk_score,
    get_risk_level,
)


def test_calculate_risk_score():
    assert calculate_risk_score(3, 4) == 12


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (1, "very_low"),
        (2, "very_low"),
        (3, "low"),
        (4, "low"),
        (5, "medium"),
        (9, "medium"),
        (10, "high"),
        (12, "high"),
        (13, "very_high"),
        (16, "very_high"),
        (17, "critical"),
        (25, "critical"),
    ],
)
def test_get_risk_level(score, expected):
    assert get_risk_level(score) == expected


def test_invalid_likelihood():
    with pytest.raises(ValueError):
        calculate_risk_score(0, 3)


def test_invalid_impact():
    with pytest.raises(ValueError):
        calculate_risk_score(3, 6)


def test_assess_known_finding():
    finding = {
        "id": "SEC-006",
        "title": "Insecure HTTP connection",
        "severity": "high",
        "category": "HTTPS",
        "evidence": "HTTP is used.",
        "recommendation": "Use HTTPS.",
    }

    result = assess_finding(finding)

    assert result["likelihood"] == 4
    assert result["impact"] == 5
    assert result["risk_score"] == 20
    assert result["risk_level"] == "critical"


def test_assess_informational_finding():
    finding = {
        "id": "SEC-008",
        "title": "Server technology disclosure",
        "severity": "informational",
        "category": "Information Disclosure",
        "evidence": "Server header exposed.",
        "recommendation": "Review the header.",
    }

    result = assess_finding(finding)

    assert result["likelihood"] == 1
    assert result["impact"] == 1
    assert result["risk_score"] == 1
    assert result["risk_level"] == "very_low"


def test_assess_findings():
    findings = [
        {
            "id": "SEC-001",
            "title": "Missing CSP",
            "severity": "medium",
            "category": "Security Headers",
            "evidence": "Missing.",
            "recommendation": "Add CSP.",
        },
        {
            "id": "SEC-006",
            "title": "HTTP",
            "severity": "high",
            "category": "HTTPS",
            "evidence": "HTTP.",
            "recommendation": "Use HTTPS.",
        },
    ]

    result = assess_findings(findings)

    assert len(result) == 2
    assert result[0]["risk_score"] == 9
    assert result[1]["risk_score"] == 20


def test_build_risk_summary():
    findings = [
        {
            "risk_level": "medium",
            "risk_score": 9,
        },
        {
            "risk_level": "high",
            "risk_score": 12,
        },
        {
            "risk_level": "critical",
            "risk_score": 20,
        },
    ]

    summary = build_risk_summary(findings)

    assert summary["medium"] == 1
    assert summary["high"] == 1
    assert summary["critical"] == 1
    assert summary["low"] == 0


def test_calculate_overall_risk_score():
    findings = [
        {"risk_score": 4},
        {"risk_score": 9},
        {"risk_score": 20},
    ]

    assert calculate_overall_risk_score(findings) == 20


def test_build_overall_risk():
    findings = [
        {"risk_score": 9},
        {"risk_score": 20},
    ]

    result = build_overall_risk(findings)

    assert result["score"] == 20
    assert result["level"] == "critical"


def test_empty_findings():
    assert calculate_overall_risk_score([]) == 0

    result = build_overall_risk([])

    assert result["score"] == 0
    assert result["level"] == "very_low"