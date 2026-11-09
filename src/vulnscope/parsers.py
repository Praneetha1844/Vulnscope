"""Parsers for SARIF 2.1.0, OSV-Scanner, pip-audit and npm audit (v6 and v7+) JSON reports.

Each parser validates the parts of the document it relies on and raises
``ParseError`` instead of silently producing partial results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnscope.models import Finding, FindingKind, Location, Severity


class ParseError(ValueError):
    """Raised when an input file is not a supported or well-formed report."""


_SARIF_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

_TEXT_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def severity_from_score(score: float) -> Severity:
    """Map a 0-10 CVSS-style score to a severity band (CVSS v3 qualitative ranges)."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _as_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if 0.0 <= number <= 10.0 else None


# ---------------------------------------------------------------- SARIF


def parse_sarif(data: dict[str, Any]) -> list[Finding]:
    runs = data.get("runs")
    if not isinstance(runs, list):
        raise ParseError("SARIF document has no 'runs' array")

    findings: list[Finding] = []
    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = str(driver.get("name") or "sarif")
        rules = {r["id"]: r for r in driver.get("rules") or [] if isinstance(r, dict) and "id" in r}
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id")
            if not rule_id:
                raise ParseError("SARIF result without a ruleId")
            rule = rules.get(rule_id, {})
            cvss = _as_float((rule.get("properties") or {}).get("security-severity"))
            if cvss is not None:
                severity = severity_from_score(cvss)
            else:
                level = (
                    result.get("level")
                    or (rule.get("defaultConfiguration") or {}).get("level")
                    or "warning"
                )
                severity = _SARIF_LEVEL.get(str(level), Severity.MEDIUM)
            findings.append(
                Finding(
                    kind=FindingKind.SAST,
                    rule_id=str(rule_id),
                    title=str((rule.get("shortDescription") or {}).get("text") or rule_id),
                    message=str((result.get("message") or {}).get("text") or ""),
                    severity=severity,
                    source_tools=[tool],
                    location=_sarif_location(result),
                    cvss=cvss,
                )
            )
    return findings


def _sarif_location(result: dict[str, Any]) -> Location | None:
    locations = result.get("locations") or []
    if not locations:
        return None
    physical = locations[0].get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri")
    start = (physical.get("region") or {}).get("startLine")
    if not uri or not isinstance(start, int) or start < 1:
        return None
    end = (physical.get("region") or {}).get("endLine")
    return Location(path=uri, start_line=start, end_line=end if isinstance(end, int) else start)


# ---------------------------------------------------------------- OSV-Scanner


def parse_osv(data: dict[str, Any]) -> list[Finding]:
    results = data.get("results")
    if not isinstance(results, list):
        raise ParseError("OSV document has no 'results' array")

    findings: list[Finding] = []
    for result in results:
        manifest = (result.get("source") or {}).get("path")
        for entry in result.get("packages") or []:
            pkg = entry.get("package") or {}
            name, version = pkg.get("name"), pkg.get("version")
            if not name:
                raise ParseError("OSV package entry without a name")
            for vuln in entry.get("vulnerabilities") or []:
                vuln_id = vuln.get("id")
                if not vuln_id:
                    raise ParseError(f"OSV vulnerability for {name} has no id")
                cvss = next(
                    (n for s in vuln.get("severity") or [] if (n := _as_float(s.get("score")))),
                    None,
                )
                text = str((vuln.get("database_specific") or {}).get("severity") or "").lower()
                if cvss is not None:
                    severity = severity_from_score(cvss)
                else:
                    severity = _TEXT_SEVERITY.get(text, Severity.MEDIUM)
                findings.append(
                    Finding(
                        kind=FindingKind.DEPENDENCY,
                        rule_id=str(vuln_id),
                        title=str(vuln.get("summary") or vuln_id),
                        message=str(vuln.get("details") or ""),
                        severity=severity,
                        source_tools=["osv-scanner"],
                        location=Location(path=manifest, start_line=1, end_line=1)
                        if manifest
                        else None,
                        package=str(name),
                        version=str(version) if version else None,
                        advisory_ids=sorted({str(vuln_id), *map(str, vuln.get("aliases") or [])}),
                        fix_versions=_osv_fixed_versions(vuln),
                        cvss=cvss,
                    )
                )
    return findings


def _osv_fixed_versions(vuln: dict[str, Any]) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event and str(event["fixed"]) not in fixed:
                    fixed.append(str(event["fixed"]))
    return fixed


# ---------------------------------------------------------------- pip-audit


def parse_pip_audit(data: dict[str, Any]) -> list[Finding]:
    deps = data.get("dependencies")
    if not isinstance(deps, list):
        raise ParseError("pip-audit document has no 'dependencies' array")

    findings: list[Finding] = []
    for dep in deps:
        for vuln in dep.get("vulns") or []:
            vuln_id = vuln.get("id")
            if not vuln_id or not dep.get("name"):
                raise ParseError("pip-audit entry without a package name or vulnerability id")
            findings.append(
                Finding(
                    kind=FindingKind.DEPENDENCY,
                    rule_id=str(vuln_id),
                    title=f"{dep['name']}: {vuln_id}",
                    message=str(vuln.get("description") or ""),
                    # pip-audit reports no severity; MEDIUM is a neutral default, not a claim.
                    severity=Severity.MEDIUM,
                    source_tools=["pip-audit"],
                    package=str(dep["name"]),
                    version=str(dep["version"]) if dep.get("version") else None,
                    advisory_ids=sorted({str(vuln_id), *map(str, vuln.get("aliases") or [])}),
                    fix_versions=[str(v) for v in vuln.get("fix_versions") or []],
                )
            )
    return findings


# ---------------------------------------------------------------- npm audit


def parse_npm_audit(data: dict[str, Any]) -> list[Finding]:
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, dict):
        raise ParseError("npm audit document has no 'vulnerabilities' object")

    findings: list[Finding] = []
    for name, entry in vulns.items():
        via = [v for v in entry.get("via") or [] if isinstance(v, dict)]
        advisory_ids = sorted({a for v in via if (a := _npm_advisory_id(v))})
        fix = entry.get("fixAvailable")
        fix_versions = [str(fix["version"])] if isinstance(fix, dict) and fix.get("version") else []
        title = str(via[0]["title"]) if via and via[0].get("title") else f"{name} is vulnerable"
        severity = _TEXT_SEVERITY.get(str(entry.get("severity", "")).lower(), Severity.MEDIUM)
        findings.append(
            Finding(
                kind=FindingKind.DEPENDENCY,
                rule_id=advisory_ids[0] if advisory_ids else f"npm:{name}",
                title=title,
                message=f"Affected range: {entry.get('range', 'unknown')}",
                severity=severity,
                source_tools=["npm-audit"],
                package=str(name),
                advisory_ids=advisory_ids,
                fix_versions=fix_versions,
                dependency_path=_npm_path((entry.get("nodes") or [None])[0]),
            )
        )
    return findings


def parse_npm_audit_legacy(data: dict[str, Any]) -> list[Finding]:
    """Parse the npm 6 ``advisories`` shape (``npm audit --json`` before npm 7)."""
    advisories = data.get("advisories")
    if not isinstance(advisories, dict):
        raise ParseError("legacy npm audit document has no 'advisories' object")

    findings: list[Finding] = []
    for key, adv in advisories.items():
        if not isinstance(adv, dict) or not adv.get("module_name"):
            raise ParseError(f"legacy npm advisory {key!r} has no module_name")
        ids = sorted(
            {str(i) for i in [adv.get("github_advisory_id"), *(adv.get("cves") or [])] if i}
        )
        paths = [p for f in adv.get("findings") or [] for p in f.get("paths") or []]
        patched = str(adv.get("patched_versions") or "")
        findings.append(
            Finding(
                kind=FindingKind.DEPENDENCY,
                rule_id=ids[0] if ids else f"npm:{adv.get('id', key)}",
                title=str(adv.get("title") or f"{adv['module_name']} is vulnerable"),
                message=f"Affected range: {adv.get('vulnerable_versions') or 'unknown'}",
                severity=_TEXT_SEVERITY.get(str(adv.get("severity", "")).lower(), Severity.MEDIUM),
                source_tools=["npm-audit"],
                package=str(adv["module_name"]),
                advisory_ids=ids,
                # patched_versions is a semver range such as ">=1.2.6", not a version number.
                fix_versions=[patched] if patched and patched != "<0.0.0" else [],
                dependency_path=paths[0].split(">") if paths else [],
            )
        )
    return findings


def _npm_advisory_id(via: dict[str, Any]) -> str | None:
    url = str(via.get("url") or "")
    if "GHSA-" in url:
        return "GHSA-" + url.rsplit("GHSA-", 1)[1]
    return str(via["source"]) if via.get("source") is not None else None


def _npm_path(node: str | None) -> list[str]:
    if not node:
        return []
    return [part.strip("/") for part in node.split("node_modules/") if part.strip("/")]


# ---------------------------------------------------------------- dispatch


def parse_document(data: Any) -> list[Finding]:
    """Detect the report format from its top-level keys and parse it."""
    if isinstance(data, list) and data and all(isinstance(d, dict) and "vulns" in d for d in data):
        # Older pip-audit releases print a bare list of dependencies.
        return parse_pip_audit({"dependencies": data})
    if not isinstance(data, dict):
        raise ParseError("report must be a JSON object")
    if "runs" in data:
        return parse_sarif(data)
    if "results" in data:
        return parse_osv(data)
    if "dependencies" in data:
        return parse_pip_audit(data)
    if "vulnerabilities" in data:
        return parse_npm_audit(data)
    if "advisories" in data:
        return parse_npm_audit_legacy(data)
    raise ParseError("unrecognised report format (expected SARIF, OSV, pip-audit or npm audit)")


def load_findings(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc
    return parse_document(data)
