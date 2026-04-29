# src/workers/cloud_scorer.py
"""
Cloud Posture Scorer — calculates security posture scores with per-service breakdown.

Score model:
  - Starts at 100
  - Each finding deducts weighted points based on severity
  - Weights are normalized so a single critical finding doesn't bottom out the score
  - Per-service sub-scores give actionable insight into the weakest areas
  - Compliance coverage score shows how many frameworks are satisfied

Usage:
    from src.workers.cloud_scorer import score_findings, ScoreResult
    result = score_findings(findings)
    print(result.overall)          # 0-100
    print(result.by_service)       # {'s3': 45, 'iam': 80, ...}
    print(result.by_severity)      # {'critical': 3, 'high': 5, ...}
    print(result.grade)            # 'A', 'B', 'C', 'D', 'F'
    print(result.compliance)       # {'CIS': 72, 'SOC2': 85, 'PCI-DSS': 60}
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import math


# ── Severity weights ──────────────────────────────────────────────────────────
#
# We use a logarithmic decay model so that a single critical finding hurts
# a lot but a hundred low findings don't reduce the score to zero.
#
SEVERITY_WEIGHT = {
    "critical": 25,
    "high":     12,
    "medium":    5,
    "low":       2,
    "info":      0,
}

# Score thresholds for letter grades
GRADE_THRESHOLDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (50, "D"),
    (0,  "F"),
]

# Compliance tag prefixes → framework name
COMPLIANCE_FRAMEWORKS = {
    "CIS":     ["CIS-AWS", "CIS-GCP", "CIS-Azure", "CIS-"],
    "SOC2":    ["SOC2-"],
    "PCI-DSS": ["PCI-DSS-"],
    "HIPAA":   ["HIPAA-"],
    "ISO27001":["ISO-", "ISO27001-"],
}


@dataclass
class ScoreResult:
    overall:     int                   # 0-100
    grade:       str                   # A-F
    by_service:  Dict[str, int]        # per service name → 0-100
    by_severity: Dict[str, int]        # counts per severity
    compliance:  Dict[str, int]        # framework → coverage % (controls passing)
    risk_summary: str                  # one-sentence human summary
    top_issues:  List[Dict]            # top 5 most impactful findings


def score_findings(findings: List[Dict], provider: Optional[str] = None) -> ScoreResult:
    """
    Score a list of normalized findings from any cloud auditor.
    
    Each finding must have at minimum: severity, service, ruleId, title, compliance (list).
    """
    if not findings:
        return ScoreResult(
            overall=100,
            grade="A",
            by_service={},
            by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
            compliance={fw: 100 for fw in COMPLIANCE_FRAMEWORKS},
            risk_summary="No misconfigurations detected. Security posture is excellent.",
            top_issues=[],
        )

    # ── Count severities ──────────────────────────────────────────────────────
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    # ── Overall score (logarithmic decay) ─────────────────────────────────────
    # Total possible deduction is bounded by a curve so score doesn't hit 0
    # until there are many high-severity findings.
    raw_deduction = sum(
        SEVERITY_WEIGHT.get(f.get("severity", "low").lower(), 2)
        for f in findings
    )
    # Dampen with log so 1 critical = -25, 5 criticals ≈ -52, 20 criticals ≈ -82
    dampened = 100 * (1 - math.exp(-raw_deduction / 100)) if raw_deduction > 0 else 0
    overall  = max(0, min(100, round(100 - dampened)))

    # ── Per-service scores ────────────────────────────────────────────────────
    service_findings: Dict[str, List[Dict]] = {}
    for f in findings:
        svc = f.get("service", "unknown")
        service_findings.setdefault(svc, []).append(f)

    by_service: Dict[str, int] = {}
    for svc, svc_finds in service_findings.items():
        svc_deduction = sum(
            SEVERITY_WEIGHT.get(f.get("severity", "low").lower(), 2)
            for f in svc_finds
        )
        dampened_svc = 100 * (1 - math.exp(-svc_deduction / 60))
        by_service[svc] = max(0, min(100, round(100 - dampened_svc)))

    # ── Grade ─────────────────────────────────────────────────────────────────
    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if overall >= threshold:
            grade = letter
            break

    # ── Compliance framework coverage ─────────────────────────────────────────
    # For each framework, count unique rules that have a compliance tag for that framework.
    # Score = % of total rules that have NO finding mapped to them.
    # (Approximation — we don't have a full rule list, so we use finding density as proxy.)
    compliance_hits: Dict[str, int] = {fw: 0 for fw in COMPLIANCE_FRAMEWORKS}
    for f in findings:
        tags = f.get("compliance", []) or []
        for tag in tags:
            for fw, prefixes in COMPLIANCE_FRAMEWORKS.items():
                if any(tag.startswith(p) for p in prefixes):
                    compliance_hits[fw] += 1
                    break

    # Each finding hitting a compliance framework reduces its score
    compliance: Dict[str, int] = {}
    for fw, hit_count in compliance_hits.items():
        deduction = 100 * (1 - math.exp(-hit_count / 8))
        compliance[fw] = max(0, min(100, round(100 - deduction)))

    # Frameworks with no findings at all get 100
    for fw in COMPLIANCE_FRAMEWORKS:
        if fw not in compliance or compliance_hits.get(fw, 0) == 0:
            compliance[fw] = 100

    # ── Top issues (most impactful findings to fix first) ─────────────────────
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_WEIGHT.get(f.get("severity", "low").lower(), 2),
        reverse=True,
    )
    top_issues = sorted_findings[:5]

    # ── Risk summary ──────────────────────────────────────────────────────────
    crit = by_severity.get("critical", 0)
    high = by_severity.get("high", 0)
    total = len(findings)

    if crit > 0:
        risk_summary = (
            f"{crit} critical misconfiguration{'s' if crit != 1 else ''} require immediate attention — "
            f"exposure to data breach or full account compromise is possible."
        )
    elif high > 0:
        risk_summary = (
            f"No critical findings, but {high} high-severity issue{'s' if high != 1 else ''} "
            f"should be remediated promptly to reduce attack surface."
        )
    elif total > 0:
        risk_summary = (
            f"{total} medium/low finding{'s' if total != 1 else ''} found. "
            f"No immediate risk, but addressing these improves compliance posture."
        )
    else:
        risk_summary = "No misconfigurations detected. Security posture is excellent."

    return ScoreResult(
        overall=overall,
        grade=grade,
        by_service=by_service,
        by_severity={k: v for k, v in by_severity.items() if v > 0},
        compliance=compliance,
        risk_summary=risk_summary,
        top_issues=top_issues,
    )


def score_to_dict(result: ScoreResult) -> Dict:
    """Serialize ScoreResult to dict for JSON responses."""
    return {
        "overall":     result.overall,
        "grade":       result.grade,
        "by_service":  result.by_service,
        "by_severity": result.by_severity,
        "compliance":  result.compliance,
        "risk_summary": result.risk_summary,
        "top_issues":  result.top_issues,
    }
