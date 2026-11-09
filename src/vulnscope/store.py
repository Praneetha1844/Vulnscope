"""SQLite persistence for findings, reviewed suggestions and reviewer decisions."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

from vulnscope.models import ReviewState, ScoredFinding, Suggestion, SuggestionPayload
from vulnscope.review import transition

VERDICTS = ("false_positive", "true_positive")

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    score       REAL NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS suggestions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL REFERENCES findings(fingerprint),
    payload     TEXT NOT NULL,
    state       TEXT NOT NULL,
    reviewer    TEXT,
    note        TEXT,
    created     TEXT NOT NULL,
    updated     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    directory   TEXT NOT NULL,
    verdict     TEXT NOT NULL CHECK (verdict IN ('false_positive', 'true_positive')),
    reviewer    TEXT NOT NULL,
    created     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS suppressions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id   TEXT NOT NULL,
    path_glob TEXT NOT NULL,
    reason    TEXT NOT NULL,
    created   TEXT NOT NULL,
    UNIQUE (rule_id, path_glob)
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class ReviewStore:
    """All SQL is parameterised; reviewer identity is required for every state change."""

    def __init__(self, path: Path | str = ":memory:"):
        self._db = sqlite3.connect(str(path))
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)

    def __enter__(self) -> ReviewStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    # ---- findings

    def upsert_finding(self, item: ScoredFinding) -> None:
        now = _now()
        with self._db:
            self._db.execute(
                "INSERT INTO findings (fingerprint, data, score, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET "
                "data = excluded.data, score = excluded.score, last_seen = excluded.last_seen",
                (item.finding.fingerprint, item.model_dump_json(), item.score.final, now, now),
            )

    def get_finding(self, fingerprint: str) -> ScoredFinding | None:
        row = self._db.execute(
            "SELECT data FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return ScoredFinding.model_validate_json(row["data"]) if row else None

    def list_findings(self, limit: int | None = None) -> list[ScoredFinding]:
        sql = "SELECT data FROM findings ORDER BY score DESC, fingerprint"
        rows = self._db.execute(sql + (" LIMIT ?" if limit else ""), (limit,) if limit else ())
        return [ScoredFinding.model_validate_json(r["data"]) for r in rows]

    # ---- suggestions

    def add_suggestion(self, fingerprint: str, payload: SuggestionPayload) -> int:
        if self.get_finding(fingerprint) is None:
            raise KeyError(f"unknown finding {fingerprint}")
        now = _now()
        with self._db:
            cursor = self._db.execute(
                "INSERT INTO suggestions (fingerprint, payload, state, created, updated) "
                "VALUES (?, ?, ?, ?, ?)",
                (fingerprint, payload.model_dump_json(), ReviewState.PENDING.value, now, now),
            )
        return int(cursor.lastrowid or 0)

    def has_open_suggestion(self, fingerprint: str) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM suggestions WHERE fingerprint = ? AND state IN (?, ?) LIMIT 1",
            (fingerprint, ReviewState.PENDING.value, ReviewState.ACCEPTED.value),
        ).fetchone()
        return row is not None

    def list_suggestions(
        self, fingerprint: str | None = None, state: ReviewState | None = None
    ) -> list[tuple[int, Suggestion]]:
        clauses: list[str] = []
        params: list[str] = []
        if fingerprint:
            clauses.append("fingerprint = ?")
            params.append(fingerprint)
        if state:
            clauses.append("state = ?")
            params.append(state.value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._db.execute(f"SELECT * FROM suggestions{where} ORDER BY id", params)
        return [
            (
                r["id"],
                Suggestion(
                    fingerprint=r["fingerprint"],
                    payload=SuggestionPayload.model_validate_json(r["payload"]),
                    state=ReviewState(r["state"]),
                    reviewer=r["reviewer"],
                    note=r["note"],
                ),
            )
            for r in rows
        ]

    def set_state(
        self, suggestion_id: int, target: ReviewState, reviewer: str, note: str | None = None
    ) -> None:
        if not reviewer.strip():
            raise ValueError("a reviewer name is required")
        row = self._db.execute(
            "SELECT state FROM suggestions WHERE id = ?", (suggestion_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown suggestion {suggestion_id}")
        current = ReviewState(row["state"])
        new_state = transition(current, target)
        with self._db:
            # Matching on the state we validated against keeps two reviewers from
            # overwriting each other's decision.
            cursor = self._db.execute(
                "UPDATE suggestions SET state = ?, reviewer = ?, note = ?, updated = ? "
                "WHERE id = ? AND state = ?",
                (new_state.value, reviewer.strip(), note, _now(), suggestion_id, current.value),
            )
        if cursor.rowcount != 1:
            raise ValueError(f"suggestion {suggestion_id} changed state while being updated")

    # ---- reviewer decisions and suppression rules

    def record_decision(self, fingerprint: str, verdict: str, reviewer: str) -> None:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        if not reviewer.strip():
            raise ValueError("a reviewer name is required")
        item = self.get_finding(fingerprint)
        if item is None or item.finding.location is None:
            raise KeyError("decisions can only be recorded for located findings that exist")
        directory = item.finding.location.path.rpartition("/")[0]
        with self._db:
            self._db.execute(
                "INSERT INTO decisions "
                "(fingerprint, rule_id, directory, verdict, reviewer, created) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (fingerprint, item.finding.rule_id, directory, verdict, reviewer.strip(), _now()),
            )

    def decision_counts(self) -> list[tuple[str, str, int, int]]:
        """Return (rule_id, directory, false_positive_count, true_positive_count)."""
        rows = self._db.execute(
            "SELECT rule_id, directory, "
            "SUM(verdict = 'false_positive') AS fp, SUM(verdict = 'true_positive') AS tp "
            "FROM decisions GROUP BY rule_id, directory ORDER BY rule_id, directory"
        )
        return [(r["rule_id"], r["directory"], int(r["fp"]), int(r["tp"])) for r in rows]

    def add_suppression(self, rule_id: str, path_glob: str, reason: str) -> None:
        if not reason.strip():
            raise ValueError("a reason is required to adopt a suppression rule")
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO suppressions (rule_id, path_glob, reason, created) "
                "VALUES (?, ?, ?, ?)",
                (rule_id, path_glob, reason.strip(), _now()),
            )

    def list_suppressions(self) -> list[tuple[str, str]]:
        rows = self._db.execute("SELECT rule_id, path_glob FROM suppressions ORDER BY id")
        return [(r["rule_id"], r["path_glob"]) for r in rows]
