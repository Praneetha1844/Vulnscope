"""Merge duplicate findings from several tools and assign stable fingerprints."""

from __future__ import annotations

import hashlib

from vulnscope.models import Finding, FindingKind


def _merge(a: Finding, b: Finding) -> Finding:
    """Combine two findings that describe the same issue; keep the more severe view."""
    merged = a.model_copy(deep=True)
    if b.severity.rank > a.severity.rank:
        merged.severity = b.severity
    merged.source_tools = list(dict.fromkeys([*a.source_tools, *b.source_tools]))
    merged.advisory_ids = sorted({*a.advisory_ids, *b.advisory_ids})
    merged.fix_versions = list(dict.fromkeys([*a.fix_versions, *b.fix_versions]))
    merged.cvss = max((c for c in (a.cvss, b.cvss) if c is not None), default=None)
    merged.message = a.message or b.message
    if len(b.dependency_path) > len(a.dependency_path):
        merged.dependency_path = list(b.dependency_path)
    return merged


def _sast_key(f: Finding) -> tuple[str, str, int] | None:
    if f.kind is FindingKind.SAST and f.location:
        return (f.rule_id, f.location.path, f.location.start_line)
    return None


def _dependency_keys(f: Finding) -> list[tuple[str, str | None, str]]:
    if f.kind is not FindingKind.DEPENDENCY:
        return []
    package = (f.package or "").lower()
    return [(package, f.version, advisory) for advisory in (f.advisory_ids or [f.rule_id])]


def merge_duplicates(findings: list[Finding]) -> list[Finding]:
    """Merge SAST findings with the same rule and position, and dependency findings that
    share any advisory id (so an OSV GHSA id and a pip-audit PYSEC alias collapse when
    the tools list each other as aliases)."""
    merged: list[Finding] = []
    index: dict[tuple[object, ...], int] = {}

    def keys(f: Finding) -> list[tuple[object, ...]]:
        sast = _sast_key(f)
        return [("sast", *sast)] if sast else [("dep", *k) for k in _dependency_keys(f)]

    for finding in findings:
        position = next((index[k] for k in keys(finding) if k in index), None)
        if position is None:
            merged.append(finding.model_copy(deep=True))
            position = len(merged) - 1
        else:
            merged[position] = _merge(merged[position], finding)
        for key in keys(merged[position]):
            index.setdefault(key, position)
    return merged


def assign_fingerprints(findings: list[Finding]) -> list[Finding]:
    """Give every finding a fingerprint that survives line-number drift.

    SAST fingerprints hash the rule, file and message but not the line. Several hits that
    share all three get an ordinal suffix in line order. Dependency fingerprints hash the
    package, version and primary advisory id.
    """

    def order(f: Finding) -> tuple[str, int, str]:
        loc = f.location
        return (loc.path if loc else "", loc.start_line if loc else 0, f.rule_id)

    seen: dict[str, int] = {}
    result: list[Finding] = []
    for finding in sorted(findings, key=order):
        if finding.kind is FindingKind.SAST:
            base = "|".join(
                ["sast", finding.rule_id, finding.location.path if finding.location else "",
                 finding.message]
            )
        else:
            advisory = sorted(finding.advisory_ids)[0] if finding.advisory_ids else finding.rule_id
            package = (finding.package or "").lower()
            base = "|".join(["dep", package, finding.version or "", advisory])
        digest = hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]
        ordinal = seen.get(digest, 0)
        seen[digest] = ordinal + 1
        result.append(finding.model_copy(update={"fingerprint": f"{digest}-{ordinal}"}))
    return result
