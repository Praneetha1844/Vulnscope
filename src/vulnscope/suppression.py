"""Learn suppression rules from reviewer decisions, without ever adopting one silently.

A rule is *proposed* when reviewers marked the same rule as a false positive at least
``min_count`` times inside one directory and never marked it a true positive there.
Proposals only become active when a person adopts them with a written reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from vulnscope.models import Finding, FindingKind
from vulnscope.store import ReviewStore


@dataclass(frozen=True)
class SuppressionProposal:
    rule_id: str
    path_glob: str
    false_positives: int


def propose(store: ReviewStore, min_count: int = 3) -> list[SuppressionProposal]:
    if min_count < 1:
        raise ValueError("min_count must be at least 1")
    return [
        SuppressionProposal(rule, f"{directory}/*" if directory else "*", fp)
        for rule, directory, fp, tp in store.decision_counts()
        if fp >= min_count and tp == 0
    ]


def apply_suppressions(
    findings: list[Finding], rules: list[tuple[str, str]]
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (kept, suppressed). Only located SAST findings can be suppressed."""
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        hit = (
            finding.kind is FindingKind.SAST
            and finding.location is not None
            and any(
                finding.rule_id == rule and fnmatchcase(finding.location.path, glob)
                for rule, glob in rules
            )
        )
        (suppressed if hit else kept).append(finding)
    return kept, suppressed
