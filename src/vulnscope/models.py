"""Normalised data model shared by every stage of the pipeline."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingKind(StrEnum):
    SAST = "sast"
    DEPENDENCY = "dependency"


class ReviewState(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class Location(BaseModel):
    """A file position, always relative to the scanned project root."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @field_validator("path")
    @classmethod
    def _relative_posix(cls, value: str) -> str:
        cleaned = value.replace("\\", "/")
        # Absolute paths are kept as given; the pipeline makes them relative to the scan root.
        return cleaned.removeprefix("file://")


class Finding(BaseModel):
    """One normalised finding, independent of the tool that reported it."""

    kind: FindingKind
    rule_id: str = Field(min_length=1)
    title: str
    message: str = ""
    severity: Severity
    source_tools: list[str] = Field(default_factory=list)
    location: Location | None = None
    package: str | None = None
    version: str | None = None
    advisory_ids: list[str] = Field(default_factory=list)
    fix_versions: list[str] = Field(default_factory=list)
    dependency_path: list[str] = Field(default_factory=list)
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    fingerprint: str = ""


class ScoreBreakdown(BaseModel):
    """Every number that contributed to a score, so the ranking can be audited."""

    base: float
    reachability: str
    reachability_factor: float
    exploit_bonus: float
    final: float
    priority: str
    reasons: list[str]


class ScoredFinding(BaseModel):
    finding: Finding
    score: ScoreBreakdown
    snippet: str | None = None


class SuggestionPayload(BaseModel):
    """The structured output we require from a language model."""

    explanation: str = Field(min_length=10, max_length=4000)
    patch: str = Field(default="", max_length=60_000)
    confidence: float = Field(ge=0.0, le=1.0)


class Suggestion(BaseModel):
    fingerprint: str
    payload: SuggestionPayload
    state: ReviewState = ReviewState.PENDING
    reviewer: str | None = None
    note: str | None = None
