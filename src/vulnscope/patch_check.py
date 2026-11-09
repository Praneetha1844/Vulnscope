"""Guardrail: check that a suggested unified diff is safe to show a reviewer.

A patch passes only if it changes exactly one file, that file is the flagged one, the
path stays inside the project, and every hunk applies cleanly to the current contents.
Nothing here ever writes to disk: patches are never applied automatically.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

MAX_PATCH_LINES = 400
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

Hunk = tuple[int, int, list[tuple[str, str]]]  # old_start, old_len, [(tag, text)]


class PatchError(ValueError):
    """The diff is malformed or does not apply to the given text."""


def _clean_path(raw: str) -> str:
    path = raw.split("\t")[0].strip()
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path


def _parse(diff: str) -> list[tuple[str, str, list[Hunk]]]:
    lines = diff.splitlines()
    files: list[tuple[str, str, list[Hunk]]] = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            old, new = _clean_path(lines[i][4:]), _clean_path(lines[i + 1][4:])
            i += 2
            hunks: list[Hunk] = []
            while i < len(lines) and (match := _HUNK.match(lines[i])):
                old_len = int(match[2]) if match[2] is not None else 1
                new_len = int(match[4]) if match[4] is not None else 1
                i += 1
                body: list[tuple[str, str]] = []
                seen_old = seen_new = 0
                while i < len(lines) and (seen_old < old_len or seen_new < new_len):
                    line = lines[i]
                    i += 1
                    if line.startswith("\\"):
                        continue
                    tag = line[:1] or " "
                    if tag == " ":
                        seen_old, seen_new = seen_old + 1, seen_new + 1
                    elif tag == "-":
                        seen_old += 1
                    elif tag == "+":
                        seen_new += 1
                    else:
                        raise PatchError(f"unexpected line in hunk: {line[:40]!r}")
                    body.append((tag, line[1:]))
                if (seen_old, seen_new) != (old_len, new_len):
                    raise PatchError("hunk length does not match its header")
                hunks.append((int(match[1]), old_len, body))
            files.append((old, new, hunks))
        else:
            i += 1
    return files


def apply_hunks(original: list[str], hunks: list[Hunk]) -> list[str]:
    """Apply hunks to ``original`` lines, verifying every context and removed line."""
    out: list[str] = []
    cursor = 0
    for old_start, old_len, body in hunks:
        index = old_start if old_len == 0 else old_start - 1
        if index < cursor or index > len(original):
            raise PatchError("hunk is out of order or outside the file")
        out.extend(original[cursor:index])
        for tag, text in body:
            if tag in " -":
                if index >= len(original) or original[index] != text:
                    raise PatchError(f"context mismatch at line {index + 1}")
                index += 1
            if tag in " +":
                out.append(text)
        cursor = index
    out.extend(original[cursor:])
    return out


def check_patch(diff: str, flagged_path: str, root: Path) -> list[str]:
    """Return a list of problems; an empty list means the patch passed every check."""
    if not diff.strip():
        return ["patch is empty"]
    if len(diff.splitlines()) > MAX_PATCH_LINES:
        return [f"patch is longer than {MAX_PATCH_LINES} lines"]
    try:
        files = _parse(diff)
    except PatchError as exc:
        return [str(exc)]
    if len(files) != 1:
        return [f"patch must change exactly one file, found {len(files)}"]

    old, new, hunks = files[0]
    expected = PurePosixPath(flagged_path.replace("\\", "/")).as_posix()
    problems: list[str] = []
    for label, path in (("old", old), ("new", new)):
        if path == "/dev/null":
            problems.append("patch creates or deletes a file")
        elif PurePosixPath(path).as_posix() != expected:
            problems.append(f"{label} path {path!r} is not the flagged file {expected!r}")
    if problems:
        return problems

    root = root.resolve()
    target = (root / expected).resolve()
    if ".." in PurePosixPath(expected).parts or not target.is_relative_to(root):
        return ["flagged path escapes the project root"]
    if not target.is_file():
        return [f"flagged file {expected!r} does not exist"]
    if not hunks:
        return ["patch has no hunks"]
    try:
        apply_hunks(target.read_text(encoding="utf-8").splitlines(), hunks)
    except (PatchError, UnicodeDecodeError) as exc:
        return [f"patch does not apply cleanly: {exc}"]
    return []
