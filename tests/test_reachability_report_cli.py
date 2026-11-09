import json

import pytest
from helpers import OSV_SAMPLE, SARIF_SAMPLE, make_scored

from vulnscope.cli import main
from vulnscope.models import ReviewState, Suggestion, SuggestionPayload
from vulnscope.reachability import ImportIndex, Reachability
from vulnscope.report import render_markdown, render_sarif


@pytest.fixture
def project(tmp_path):
    pkg = tmp_path / "src" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "main.py").write_text("import yaml\nfrom pkg import core\n", encoding="utf-8")
    (pkg / "core.py").write_text("import requests\n", encoding="utf-8")
    (pkg / "orphan.py").write_text("import flask\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("docs", encoding="utf-8")
    return tmp_path


def test_files_reachable_from_entry_points(project) -> None:
    index = ImportIndex(project)
    assert index.file_reachability("src/pkg/core.py") is Reachability.REACHABLE
    assert index.file_reachability("src/pkg/orphan.py") is Reachability.UNREACHABLE
    assert index.file_reachability("README.md") is Reachability.UNKNOWN


def test_package_reachability_uses_import_names_and_aliases(project) -> None:
    index = ImportIndex(project)
    assert index.package_reachability("PyYAML") is Reachability.REACHABLE
    assert index.package_reachability("requests") is Reachability.REACHABLE
    assert index.package_reachability("flask") is Reachability.UNREACHABLE
    assert index.package_reachability("numpy") is Reachability.UNKNOWN


def test_project_without_entry_points_is_unknown(tmp_path) -> None:
    (tmp_path / "lib.py").write_text("import yaml\n", encoding="utf-8")
    assert ImportIndex(tmp_path).package_reachability("pyyaml") is Reachability.UNKNOWN


def test_markdown_labels_unreviewed_output() -> None:
    item = make_scored(snippet="    2 | password = 'x'")
    pending = Suggestion(
        fingerprint="fp-0",
        payload=SuggestionPayload(explanation="Use an environment variable.", confidence=0.4),
    )
    accepted = pending.model_copy(update={"state": ReviewState.ACCEPTED, "reviewer": "praneetha"})
    text = render_markdown([item], {"fp-0": [pending, accepted]})
    assert "UNREVIEWED model suggestion" in text
    assert "Accepted by reviewer (praneetha)" in text
    assert "not calibrated" in text and "password = 'x'" in text


def test_sarif_output_is_valid_json_with_fingerprints() -> None:
    document = json.loads(render_sarif([make_scored(severity="critical")]))
    result = document["runs"][0]["results"][0]
    assert document["version"] == "2.1.0" and result["level"] == "error"
    assert result["partialFingerprints"]["vulnscope/v1"] == "fp-0"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 2


def test_cli_scan_review_and_report_flow(project, tmp_path, capsys) -> None:
    sarif = tmp_path / "semgrep.json"
    sarif.write_text(json.dumps(SARIF_SAMPLE), encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text(json.dumps(OSV_SAMPLE), encoding="utf-8")
    db = str(tmp_path / "triage.db")

    assert main(["--db", db, "scan", str(sarif), str(osv), "--root", str(project)]) == 0
    assert "3 finding(s) stored" in capsys.readouterr().out

    assert main(["--db", db, "review", "list"]) == 0
    assert capsys.readouterr().out == ""

    out_file = tmp_path / "report.md"
    assert main(["--db", db, "report", "--output", str(out_file)]) == 0
    assert "Vulnscope report" in out_file.read_text(encoding="utf-8")


def test_cli_reports_bad_input_with_exit_code_one(tmp_path, capsys) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    assert main(["--db", str(tmp_path / "x.db"), "scan", str(bad)]) == 1
    assert "error:" in capsys.readouterr().err


def test_remote_provider_requires_explicit_consent(tmp_path, capsys) -> None:
    db = str(tmp_path / "x.db")
    assert main(["--db", db, "triage", "--provider", "openai", "--model", "m"]) == 1
    assert "--allow-remote" in capsys.readouterr().err


def test_markdown_fences_grow_around_embedded_backticks() -> None:
    item = make_scored(snippet="    1 | x = '''```'''")
    text = render_markdown([item])
    assert "````" in text
    pending = Suggestion(
        fingerprint="fp-0",
        payload=SuggestionPayload(
            explanation="Quote handling.", patch="--- a/a.py\n+++ b/a.py\n+```\n", confidence=0.5
        ),
    )
    assert "````diff" in render_markdown([make_scored()], {"fp-0": [pending]})


def test_absolute_report_paths_are_made_relative_to_the_scan_root(tmp_path) -> None:
    from copy import deepcopy

    from vulnscope.pipeline import scan

    source = tmp_path / "src" / "db.py"
    source.parent.mkdir()
    source.write_text("a = 1\n" * 14, encoding="utf-8")
    if not source.as_posix().startswith("/"):
        pytest.skip("absolute POSIX paths only")
    document = deepcopy(SARIF_SAMPLE)
    uri = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    uri["uri"] = f"file://{source.as_posix()}"
    report = tmp_path / "report.sarif"
    report.write_text(json.dumps(document), encoding="utf-8")
    scored, _ = scan([report], tmp_path)
    located = next(s for s in scored if s.finding.location)
    assert located.finding.location.path == "src/db.py"
    assert located.snippet is not None
