"""Markdown and SARIF reports. Unreviewed model output is always labelled as such."""

from __future__ import annotations

import json
import re
from typing import Any

from vulnscope import __version__
from vulnscope.models import ReviewState, ScoredFinding, Severity, Suggestion

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_STATE_LABEL = {
    ReviewState.PENDING: "UNREVIEWED model suggestion - verify before use",
    ReviewState.ACCEPTED: "Accepted by reviewer",
    ReviewState.REJECTED: "Rejected by reviewer",
}


def _fenced(text: str, info: str = "") -> list[str]:
    """Fence ``text`` with more backticks than it contains, so it cannot break out."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return [f"{ticks}{info}", text, ticks]


def _suggestion_block(suggestion: Suggestion) -> list[str]:
    who = f" ({suggestion.reviewer})" if suggestion.reviewer else ""
    lines = [
        f"**{_STATE_LABEL[suggestion.state]}{who}**, model confidence "
        f"{suggestion.payload.confidence:.2f} (self-reported, not calibrated)",
        "",
        suggestion.payload.explanation,
    ]
    if suggestion.payload.patch.strip():
        lines += ["", *_fenced(suggestion.payload.patch.rstrip(), "diff")]
    return lines


def render_markdown(
    items: list[ScoredFinding], suggestions: dict[str, list[Suggestion]] | None = None
) -> str:
    suggestions = suggestions or {}
    counts: dict[str, int] = {}
    for item in items:
        counts[item.score.priority] = counts.get(item.score.priority, 0) + 1
    lines = ["# Vulnscope report", "", f"{len(items)} finding(s).", ""]
    lines += ["| Priority | Count |", "| --- | --- |"]
    lines += [f"| {p} | {counts[p]} |" for p in sorted(counts)]
    lines.append("")
    for item in items:
        f, s = item.finding, item.score
        where = f"`{f.location.path}:{f.location.start_line}`" if f.location else "n/a"
        lines += [
            f"## [{s.priority}] {f.title}",
            "",
            f"- Rule: `{f.rule_id}`  Severity: {f.severity}  Score: {s.final}",
            f"- Location: {where}",
            f"- Tools: {', '.join(f.source_tools)}",
            f"- Fingerprint: `{f.fingerprint}`",
        ]
        if f.package:
            lines.append(f"- Dependency: `{f.package}` {f.version or ''}".rstrip())
        if f.fix_versions:
            lines.append(f"- Fixed in: {', '.join(f.fix_versions)}")
        lines += ["- Why this score:", *[f"  - {r}" for r in s.reasons], ""]
        if item.snippet:
            lines += [*_fenced(item.snippet), ""]
        for suggestion in suggestions.get(f.fingerprint, []):
            lines += [*_suggestion_block(suggestion), ""]
    return "\n".join(lines).rstrip() + "\n"


def render_sarif(
    items: list[ScoredFinding], suggestions: dict[str, list[Suggestion]] | None = None
) -> str:
    suggestions = suggestions or {}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in items:
        f = item.finding
        rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.title}})
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message or f.title},
            "partialFingerprints": {"vulnscope/v1": f.fingerprint},
            "properties": {
                "priority": item.score.priority,
                "score": item.score.final,
                "reachability": item.score.reachability,
                "reviewStates": [s.state.value for s in suggestions.get(f.fingerprint, [])],
            },
        }
        if f.location:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.path},
                        "region": {
                            "startLine": f.location.start_line,
                            "endLine": f.location.end_line,
                        },
                    }
                }
            ]
        results.append(result)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnscope",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
