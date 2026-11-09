"""A deliberately simple reachability heuristic for Python projects.

It builds an import graph with ``ast`` and walks it from entry points. It does not
resolve dynamic imports, call graphs or framework wiring, so the result is a signal
that adjusts a score, never proof that code is or is not exploitable.
"""

from __future__ import annotations

import ast
from collections import deque
from enum import StrEnum
from pathlib import Path

from vulnscope.models import Finding, FindingKind

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "site-packages", "build", "dist", "__pycache__"
}
ENTRY_NAMES = {"__main__.py", "main.py", "app.py", "cli.py", "manage.py", "wsgi.py", "asgi.py"}
IMPORT_ALIASES = {
    "pyyaml": "yaml",
    "pillow": "pil",
    "scikit-learn": "sklearn",
    "beautifulsoup4": "bs4",
    "opencv-python": "cv2",
    "python-dateutil": "dateutil",
}


class Reachability(StrEnum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


def _module_name(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imports(tree: ast.AST, module: str, is_package: bool) -> set[str]:
    found: set[str] = set()
    parts = module.split(".") if module else []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                keep = len(parts) - (node.level - 1 if is_package else node.level)
                if keep < 0:
                    continue
                base = ".".join([*parts[:keep], *([node.module] if node.module else [])])
            else:
                base = node.module or ""
            if base:
                found.add(base)
                found.update(f"{base}.{alias.name}" for alias in node.names)
    return found


def _has_main_guard(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            left = node.test.left
            if isinstance(left, ast.Name) and left.id == "__name__":
                return True
    return False


class ImportIndex:
    """Import graph of the Python files under ``root``."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.imports: dict[str, set[str]] = {}
        self.module_to_file: dict[str, str] = {}
        self.entrypoints: set[str] = set()
        for path in sorted(self.root.rglob("*.py")):
            rel = path.relative_to(self.root)
            if SKIP_DIRS & set(rel.parts):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except (SyntaxError, ValueError, OSError):  # ValueError: null bytes in source
                continue
            key = rel.as_posix()
            module = _module_name(rel)
            self.module_to_file[module] = key
            self.imports[key] = _imports(tree, module, path.name == "__init__.py")
            if path.name in ENTRY_NAMES or _has_main_guard(tree):
                self.entrypoints.add(key)
        self.reachable = self._walk()

    def _resolve(self, dotted: str) -> str | None:
        parts = dotted.split(".")
        for end in range(len(parts), 0, -1):
            hit = self.module_to_file.get(".".join(parts[:end]))
            if hit:
                return hit
        return None

    def _walk(self) -> set[str]:
        seen = set(self.entrypoints)
        queue = deque(self.entrypoints)
        while queue:
            for dotted in self.imports.get(queue.popleft(), ()):
                target = self._resolve(dotted)
                if target and target not in seen:
                    seen.add(target)
                    queue.append(target)
        return seen

    def file_reachability(self, rel_path: str) -> Reachability:
        if not rel_path.endswith(".py") or rel_path not in self.imports or not self.entrypoints:
            return Reachability.UNKNOWN
        return Reachability.REACHABLE if rel_path in self.reachable else Reachability.UNREACHABLE

    def package_reachability(self, package: str) -> Reachability:
        name = IMPORT_ALIASES.get(package.lower(), package.lower().replace("-", "_"))
        importers = [
            f
            for f, mods in self.imports.items()
            if any(m.split(".")[0].lower() == name for m in mods)
        ]
        if not importers or not self.entrypoints:
            return Reachability.UNKNOWN  # may be a transitive or non-Python dependency
        if any(f in self.reachable for f in importers):
            return Reachability.REACHABLE
        return Reachability.UNREACHABLE


def assess(index: ImportIndex, finding: Finding) -> Reachability:
    if finding.kind is FindingKind.SAST and finding.location:
        return index.file_reachability(finding.location.path)
    if finding.kind is FindingKind.DEPENDENCY and finding.package:
        return index.package_reachability(finding.package)
    return Reachability.UNKNOWN
