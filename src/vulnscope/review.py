"""Review state machine for suggestions.

pending  -> accepted | rejected
rejected -> pending            (reopen)
accepted -> (terminal)         (kept as an audit record; generate a new suggestion instead)
"""

from __future__ import annotations

from vulnscope.models import ReviewState

ALLOWED: dict[ReviewState, frozenset[ReviewState]] = {
    ReviewState.PENDING: frozenset({ReviewState.ACCEPTED, ReviewState.REJECTED}),
    ReviewState.REJECTED: frozenset({ReviewState.PENDING}),
    ReviewState.ACCEPTED: frozenset(),
}


class InvalidTransition(ValueError):
    """The requested state change is not allowed."""


def transition(current: ReviewState, target: ReviewState) -> ReviewState:
    if target not in ALLOWED[current]:
        raise InvalidTransition(f"cannot move a suggestion from {current} to {target}")
    return target
