"""Read the source lines around a finding without escaping the project root."""

from __future__ import annotations

from pathlib import Path

from vulnscope.models import Location

MAX_FILE_BYTES = 1_000_000


def read_snippet(root: Path, location: Location, radius: int = 3) -> str | None:
    """Return numbered lines around ``location`` or ``None`` if it cannot be read safely."""
    root = root.resolve()
    target = (root / location.path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return None
    try:
        if target.stat().st_size > MAX_FILE_BYTES:
            return None
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if location.start_line > len(lines):
        return None
    start = max(location.start_line - radius, 1)
    end = min(location.end_line + radius, len(lines))
    return "\n".join(f"{n:>5} | {lines[n - 1]}" for n in range(start, end + 1))
