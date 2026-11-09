import pytest

from vulnscope.patch_check import MAX_PATCH_LINES, apply_hunks, check_patch

SOURCE = 'import os\npassword = "x"\nprint(password)\n'

GOOD = """--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
 import os
-password = "x"
+password = os.environ["PASSWORD"]
 print(password)
"""


@pytest.fixture
def root(tmp_path):
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    (tmp_path / "other.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def test_valid_patch_passes(root) -> None:
    assert check_patch(GOOD, "app.py", root) == []


def test_patch_is_never_written_to_disk(root) -> None:
    check_patch(GOOD, "app.py", root)
    assert (root / "app.py").read_text(encoding="utf-8") == SOURCE


def test_wrong_file_is_rejected(root) -> None:
    problems = check_patch(GOOD.replace("app.py", "other.py"), "app.py", root)
    assert any("not the flagged file" in p for p in problems)


def test_two_files_are_rejected(root) -> None:
    second = GOOD.replace("app.py", "other.py")
    assert "exactly one file" in check_patch(GOOD + second, "app.py", root)[0]


def test_context_mismatch_does_not_apply(root) -> None:
    bad = GOOD.replace(" import os", " import sys")
    assert "does not apply cleanly" in check_patch(bad, "app.py", root)[0]


def test_file_creation_is_rejected(root) -> None:
    created = "--- /dev/null\n+++ b/app.py\n@@ -0,0 +1,1 @@\n+print(1)\n"
    assert any("creates or deletes" in p for p in check_patch(created, "app.py", root))


def test_path_traversal_is_rejected(root) -> None:
    diff = "--- a/../evil.py\n+++ b/../evil.py\n@@ -1,1 +1,1 @@\n-x\n+y\n"
    assert "escapes" in check_patch(diff, "../evil.py", root)[0]


def test_missing_file_is_reported(root) -> None:
    diff = GOOD.replace("app.py", "ghost.py")
    assert "does not exist" in check_patch(diff, "ghost.py", root)[0]


def test_empty_and_oversized_patches(root) -> None:
    assert check_patch("  \n", "app.py", root) == ["patch is empty"]
    huge = "\n".join("+x" for _ in range(MAX_PATCH_LINES + 1))
    assert "longer than" in check_patch(huge, "app.py", root)[0]


def test_truncated_hunk_is_rejected(root) -> None:
    cut = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n import os\n-password = \"x\"\n"
    assert "hunk length" in check_patch(cut, "app.py", root)[0]


def test_apply_hunks_handles_pure_insertion() -> None:
    result = apply_hunks(["a", "b"], [(1, 0, [("+", "new")])])
    assert result == ["a", "new", "b"]
