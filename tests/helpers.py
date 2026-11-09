"""Builders and hand-written sample reports used across the tests.

Every document below is a small, hand-written sample that mimics the shape of the real
tool output. None of it was produced by running a scanner.
"""

from __future__ import annotations

from typing import Any

from vulnscope.models import Finding, FindingKind, Location, ScoredFinding, Severity
from vulnscope.reachability import Reachability
from vulnscope.scoring import score_finding


def make_finding(**overrides: Any) -> Finding:
    data: dict[str, Any] = {
        "kind": FindingKind.SAST,
        "rule_id": "py.hardcoded-secret",
        "title": "Hard-coded secret",
        "message": "A secret is assigned to a variable",
        "severity": Severity.MEDIUM,
        "source_tools": ["semgrep"],
        "location": Location(path="app.py", start_line=2, end_line=2),
        "fingerprint": "fp-0",
    }
    data.update(overrides)
    return Finding(**data)


def make_scored(
    reachability: Reachability = Reachability.UNKNOWN, snippet: str | None = None, **overrides: Any
) -> ScoredFinding:
    finding = make_finding(**overrides)
    return ScoredFinding(
        finding=finding, score=score_finding(finding, reachability), snippet=snippet
    )


SARIF_SAMPLE: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [
                        {
                            "id": "py.sql-injection",
                            "shortDescription": {"text": "SQL built from user input"},
                            "properties": {"security-severity": "8.1"},
                        },
                        {
                            "id": "py.todo",
                            "defaultConfiguration": {"level": "note"},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "py.sql-injection",
                    "level": "error",
                    "message": {"text": "Query concatenates request data"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/db.py"},
                                "region": {"startLine": 12, "endLine": 13},
                            }
                        }
                    ],
                },
                {"ruleId": "py.todo", "message": {"text": "Leftover marker"}},
            ],
        }
    ],
}

OSV_SAMPLE: dict[str, Any] = {
    "results": [
        {
            "source": {"path": "requirements.txt", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-aaaa-bbbb-cccc",
                            "aliases": ["CVE-2020-0001"],
                            "summary": "Header leak on redirect",
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]}
                            ],
                        }
                    ],
                }
            ],
        }
    ]
}

PIP_AUDIT_SAMPLE: dict[str, Any] = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.0.0",
            "vulns": [
                {
                    "id": "CVE-2020-0001",
                    "fix_versions": ["2.31.0"],
                    "aliases": [],
                    "description": "Header leak on redirect",
                }
            ],
        },
        {"name": "click", "version": "8.1.7", "vulns": []},
    ]
}

NPM_SAMPLE: dict[str, Any] = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "minimist": {
            "name": "minimist",
            "severity": "critical",
            "range": "<1.2.6",
            "nodes": ["node_modules/a/node_modules/minimist"],
            "fixAvailable": {"name": "minimist", "version": "1.2.8"},
            "via": [
                {
                    "source": 1179,
                    "name": "minimist",
                    "title": "Prototype Pollution",
                    "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
                    "severity": "critical",
                }
            ],
        }
    },
}

NPM_LEGACY_SAMPLE: dict[str, Any] = {
    "actions": [],
    "advisories": {
        "1179": {
            "id": 1179,
            "module_name": "minimist",
            "title": "Prototype Pollution",
            "severity": "critical",
            "vulnerable_versions": "<0.2.1 || >=1.0.0 <1.2.3",
            "patched_versions": ">=1.2.3",
            "github_advisory_id": "GHSA-vh95-rmgr-6w4m",
            "cves": ["CVE-2020-7598"],
            "findings": [{"version": "1.2.0", "paths": ["a>b>minimist"]}],
        }
    },
}
