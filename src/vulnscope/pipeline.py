"""The scan pipeline: parse, merge, fingerprint, suppress, add context, score, rank."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from vulnscope.context import read_snippet
from vulnscope.dedupe import assign_fingerprints, merge_duplicates
from vulnscope.models import Finding, FindingKind, ScoredFinding
from vulnscope.parsers import load_findings
from vulnscope.reachability import ImportIndex, assess
from vulnscope.scoring import score_finding
from vulnscope.suppression import apply_suppressions


def load_known_exploited(path: Path | None) -> frozenset[str]:
    """Read advisory ids, one per line; blank lines and ``#`` comments are ignored."""
    if path is None:
        return frozenset()
    lines = path.read_text(encoding="utf-8").splitlines()
    return frozenset(
        line.split("#")[0].strip() for line in lines if line.split("#")[0].strip()
    )


def _relativise(finding: Finding, root: Path) -> Finding:
    """Turn an absolute report path into one relative to the scan root.

    Reports from some tools use absolute paths, others use a leading slash to mean the
    repository root. A path outside the root is treated as the latter; later file access
    is confined to the root either way.
    """
    location = finding.location
    if location is None or not location.path.startswith("/"):
        return finding
    path = PurePosixPath(location.path)
    try:
        relative = path.relative_to(PurePosixPath(root.resolve().as_posix()))
    except ValueError:
        relative = PurePosixPath(location.path.lstrip("/"))
    moved = location.model_copy(update={"path": relative.as_posix()})
    return finding.model_copy(update={"location": moved})


def scan(
    inputs: Iterable[Path],
    root: Path,
    known_exploited: frozenset[str] = frozenset(),
    suppression_rules: list[tuple[str, str]] | None = None,
) -> tuple[list[ScoredFinding], list[Finding]]:
    """Return (ranked findings, suppressed findings)."""
    raw: list[Finding] = []
    for path in inputs:
        raw.extend(_relativise(f, root) for f in load_findings(path))
    findings, suppressed = apply_suppressions(
        assign_fingerprints(merge_duplicates(raw)), suppression_rules or []
    )
    index = ImportIndex(root)
    scored = [
        ScoredFinding(
            finding=f,
            score=score_finding(f, assess(index, f), known_exploited),
            snippet=read_snippet(root, f.location)
            if f.kind is FindingKind.SAST and f.location
            else None,
        )
        for f in findings
    ]
    scored.sort(key=lambda s: (-s.score.final, s.finding.fingerprint))
    return scored, suppressed
