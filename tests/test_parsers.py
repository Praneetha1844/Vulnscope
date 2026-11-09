import json
from copy import deepcopy

import pytest
from helpers import NPM_LEGACY_SAMPLE, NPM_SAMPLE, OSV_SAMPLE, PIP_AUDIT_SAMPLE, SARIF_SAMPLE

from vulnscope.models import FindingKind, Severity
from vulnscope.parsers import (
    ParseError,
    load_findings,
    parse_document,
    parse_npm_audit,
    parse_osv,
    parse_pip_audit,
    parse_sarif,
    severity_from_score,
)


@pytest.mark.parametrize(
    ("score", "expected"),
    [(9.8, Severity.CRITICAL), (7.0, Severity.HIGH), (4.0, Severity.MEDIUM),
     (0.1, Severity.LOW), (0.0, Severity.INFO)],
)
def test_severity_bands(score: float, expected: Severity) -> None:
    assert severity_from_score(score) == expected


def test_sarif_uses_security_severity_and_location() -> None:
    sql, todo = parse_sarif(SARIF_SAMPLE)
    assert sql.kind is FindingKind.SAST
    assert sql.severity is Severity.HIGH and sql.cvss == 8.1
    assert sql.location is not None
    loc = sql.location
    assert (loc.path, loc.start_line, loc.end_line) == ("src/db.py", 12, 13)
    assert sql.title == "SQL built from user input"
    assert todo.severity is Severity.LOW and todo.location is None


def test_sarif_result_without_rule_id_is_rejected() -> None:
    bad = deepcopy(SARIF_SAMPLE)
    bad["runs"][0]["results"].append({"message": {"text": "no rule"}})
    with pytest.raises(ParseError):
        parse_sarif(bad)


def test_sarif_requires_runs() -> None:
    with pytest.raises(ParseError):
        parse_sarif({"version": "2.1.0"})


def test_osv_extracts_package_aliases_and_fix() -> None:
    (finding,) = parse_osv(OSV_SAMPLE)
    assert finding.package == "requests" and finding.version == "2.0.0"
    assert finding.severity is Severity.HIGH
    assert finding.advisory_ids == ["CVE-2020-0001", "GHSA-aaaa-bbbb-cccc"]
    assert finding.fix_versions == ["2.31.0"]
    assert finding.location is not None and finding.location.path == "requirements.txt"


def test_pip_audit_skips_clean_packages_and_defaults_severity() -> None:
    (finding,) = parse_pip_audit(PIP_AUDIT_SAMPLE)
    assert finding.package == "requests"
    assert finding.severity is Severity.MEDIUM
    assert finding.fix_versions == ["2.31.0"] and finding.location is None


def test_npm_audit_extracts_advisory_and_dependency_path() -> None:
    (finding,) = parse_npm_audit(NPM_SAMPLE)
    assert finding.severity is Severity.CRITICAL
    assert finding.advisory_ids == ["GHSA-xvch-5gv4-984h"]
    assert finding.dependency_path == ["a", "minimist"]
    assert finding.fix_versions == ["1.2.8"]


@pytest.mark.parametrize(
    ("document", "kind"),
    [(SARIF_SAMPLE, FindingKind.SAST), (OSV_SAMPLE, FindingKind.DEPENDENCY),
     (PIP_AUDIT_SAMPLE, FindingKind.DEPENDENCY), (NPM_SAMPLE, FindingKind.DEPENDENCY)],
)
def test_format_detection(document: dict, kind: FindingKind) -> None:
    assert all(f.kind is kind for f in parse_document(document))


def test_unknown_format_is_rejected() -> None:
    with pytest.raises(ParseError):
        parse_document({"hello": "world"})
    with pytest.raises(ParseError):
        parse_document([1, 2, 3])


def test_load_findings_reports_unreadable_input(tmp_path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ParseError):
        load_findings(broken)
    good = tmp_path / "osv.json"
    good.write_text(json.dumps(OSV_SAMPLE), encoding="utf-8")
    assert len(load_findings(good)) == 1


def test_legacy_npm_audit_shape_is_supported() -> None:
    (finding,) = parse_document(NPM_LEGACY_SAMPLE)
    assert finding.package == "minimist" and finding.severity is Severity.CRITICAL
    assert finding.advisory_ids == ["CVE-2020-7598", "GHSA-vh95-rmgr-6w4m"]
    assert finding.dependency_path == ["a", "b", "minimist"]
    assert finding.fix_versions == [">=1.2.3"]


def test_legacy_npm_advisory_without_module_is_rejected() -> None:
    with pytest.raises(ParseError):
        parse_document({"advisories": {"1": {"title": "no module"}}})


def test_bare_list_from_older_pip_audit_is_supported() -> None:
    (finding,) = parse_document(PIP_AUDIT_SAMPLE["dependencies"])
    assert finding.package == "requests"
    with pytest.raises(ParseError):
        parse_document([])
