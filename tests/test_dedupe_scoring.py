import pytest
from helpers import make_finding

from vulnscope.dedupe import assign_fingerprints, merge_duplicates
from vulnscope.models import FindingKind, Location, Severity
from vulnscope.reachability import Reachability
from vulnscope.scoring import priority_for, score_finding


def test_same_rule_and_position_from_two_tools_merge() -> None:
    a = make_finding(source_tools=["semgrep"], severity=Severity.MEDIUM)
    b = make_finding(source_tools=["codeql"], severity=Severity.HIGH, cvss=7.2)
    (merged,) = merge_duplicates([a, b])
    assert merged.source_tools == ["semgrep", "codeql"]
    assert merged.severity is Severity.HIGH and merged.cvss == 7.2


def test_different_lines_do_not_merge() -> None:
    a = make_finding(location=Location(path="app.py", start_line=2, end_line=2))
    b = make_finding(location=Location(path="app.py", start_line=9, end_line=9))
    assert len(merge_duplicates([a, b])) == 2


def test_dependency_findings_merge_through_shared_alias() -> None:
    osv = make_finding(
        kind=FindingKind.DEPENDENCY, rule_id="GHSA-aaaa", location=None, package="Requests",
        version="2.0.0", advisory_ids=["CVE-2020-0001", "GHSA-aaaa"], source_tools=["osv-scanner"],
    )
    pip = make_finding(
        kind=FindingKind.DEPENDENCY, rule_id="CVE-2020-0001", location=None, package="requests",
        version="2.0.0", advisory_ids=["CVE-2020-0001"], source_tools=["pip-audit"],
    )
    (merged,) = merge_duplicates([osv, pip])
    assert merged.source_tools == ["osv-scanner", "pip-audit"]
    assert merged.advisory_ids == ["CVE-2020-0001", "GHSA-aaaa"]


def test_fingerprint_survives_line_drift() -> None:
    before = assign_fingerprints([make_finding()])[0]
    moved = make_finding(location=Location(path="app.py", start_line=40, end_line=40))
    after = assign_fingerprints([moved])[0]
    assert before.fingerprint == after.fingerprint


def test_identical_hits_in_one_file_get_distinct_ordinals() -> None:
    first = make_finding(location=Location(path="app.py", start_line=3, end_line=3))
    second = make_finding(location=Location(path="app.py", start_line=30, end_line=30))
    fingerprints = [f.fingerprint for f in assign_fingerprints([second, first])]
    assert fingerprints[0].endswith("-0") and fingerprints[1].endswith("-1")
    assert fingerprints[0].split("-")[0] == fingerprints[1].split("-")[0]


@pytest.mark.parametrize(
    ("severity", "reach", "expected"),
    [
        (Severity.HIGH, Reachability.REACHABLE, 7.5),
        (Severity.MEDIUM, Reachability.UNREACHABLE, 2.0),
        (Severity.LOW, Reachability.UNKNOWN, 2.0),
    ],
)
def test_score_from_severity_band(severity: Severity, reach: Reachability, expected: float) -> None:
    assert score_finding(make_finding(severity=severity), reach).final == expected


def test_cvss_overrides_band_and_exploit_bonus_is_capped() -> None:
    finding = make_finding(severity=Severity.MEDIUM, cvss=9.8, advisory_ids=["CVE-2024-1"])
    plain = score_finding(finding, Reachability.REACHABLE)
    boosted = score_finding(finding, Reachability.REACHABLE, frozenset({"CVE-2024-1"}))
    assert plain.final == 9.8 and plain.priority == "P1"
    assert boosted.final == 10.0 and boosted.exploit_bonus == 2.0
    assert any("known exploited" in reason for reason in boosted.reasons)


@pytest.mark.parametrize(
    ("score", "label"), [(8.0, "P1"), (6.0, "P2"), (3.5, "P3"), (3.49, "P4"), (0.0, "P4")]
)
def test_priority_bands(score: float, label: str) -> None:
    assert priority_for(score) == label
