"""Transparent prioritisation: every factor is returned alongside the final score."""

from __future__ import annotations

from vulnscope.models import Finding, ScoreBreakdown, Severity
from vulnscope.reachability import Reachability

SEVERITY_BASE = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}
REACHABILITY_FACTOR = {
    Reachability.REACHABLE: 1.0,
    Reachability.UNKNOWN: 0.8,
    Reachability.UNREACHABLE: 0.4,
}
EXPLOIT_BONUS = 2.0
PRIORITY_BANDS = ((8.0, "P1"), (6.0, "P2"), (3.5, "P3"))


def priority_for(score: float) -> str:
    return next((label for floor, label in PRIORITY_BANDS if score >= floor), "P4")


def score_finding(
    finding: Finding, reachability: Reachability, known_exploited: frozenset[str] = frozenset()
) -> ScoreBreakdown:
    """final = min(10, base * reachability_factor + exploit_bonus).

    ``base`` is the CVSS score when the tool provided one, otherwise a fixed value per
    severity band. ``exploit_bonus`` applies when any advisory id appears in the
    caller-supplied known-exploited list.
    """
    if finding.cvss is not None:
        base, base_reason = finding.cvss, f"CVSS {finding.cvss:.1f} reported by the tool"
    else:
        base, base_reason = SEVERITY_BASE[finding.severity], f"{finding.severity} severity band"
    factor = REACHABILITY_FACTOR[reachability]
    exploited = bool(known_exploited & {finding.rule_id, *finding.advisory_ids})
    bonus = EXPLOIT_BONUS if exploited else 0.0
    final = round(min(10.0, base * factor + bonus), 2)
    reasons = [
        f"base {base:.1f}: {base_reason}",
        f"reachability {reachability}: x{factor}",
    ]
    if exploited:
        reasons.append(f"listed as known exploited: +{EXPLOIT_BONUS}")
    return ScoreBreakdown(
        base=base,
        reachability=str(reachability),
        reachability_factor=factor,
        exploit_bonus=bonus,
        final=final,
        priority=priority_for(final),
        reasons=reasons,
    )
