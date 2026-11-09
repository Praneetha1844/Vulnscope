import pytest
from helpers import make_scored

from vulnscope.models import Location, ReviewState, SuggestionPayload
from vulnscope.review import ALLOWED, InvalidTransition, transition
from vulnscope.store import ReviewStore
from vulnscope.suppression import apply_suppressions, propose

PAYLOAD = SuggestionPayload(explanation="Use an environment variable.", patch="", confidence=0.5)


@pytest.fixture
def store():
    with ReviewStore() as s:
        s.upsert_finding(make_scored())
        yield s


@pytest.mark.parametrize(
    ("current", "target"),
    [(ReviewState.PENDING, ReviewState.ACCEPTED), (ReviewState.PENDING, ReviewState.REJECTED),
     (ReviewState.REJECTED, ReviewState.PENDING)],
)
def test_allowed_transitions(current: ReviewState, target: ReviewState) -> None:
    assert transition(current, target) is target


def test_accepted_is_terminal_and_pending_cannot_reopen() -> None:
    assert ALLOWED[ReviewState.ACCEPTED] == frozenset()
    for current, target in [(ReviewState.ACCEPTED, ReviewState.REJECTED),
                            (ReviewState.ACCEPTED, ReviewState.PENDING),
                            (ReviewState.PENDING, ReviewState.PENDING)]:
        with pytest.raises(InvalidTransition):
            transition(current, target)


def test_new_suggestions_start_pending(store) -> None:
    suggestion_id = store.add_suggestion("fp-0", PAYLOAD)
    ((found_id, suggestion),) = store.list_suggestions()
    assert found_id == suggestion_id and suggestion.state is ReviewState.PENDING
    assert store.has_open_suggestion("fp-0")


def test_accept_requires_a_reviewer_and_is_final(store) -> None:
    suggestion_id = store.add_suggestion("fp-0", PAYLOAD)
    with pytest.raises(ValueError):
        store.set_state(suggestion_id, ReviewState.ACCEPTED, "  ")
    store.set_state(suggestion_id, ReviewState.ACCEPTED, "praneetha", "looks right")
    with pytest.raises(InvalidTransition):
        store.set_state(suggestion_id, ReviewState.REJECTED, "praneetha")
    _, stored = store.list_suggestions(state=ReviewState.ACCEPTED)[0]
    assert stored.reviewer == "praneetha" and stored.note == "looks right"


def test_rejected_suggestions_can_be_reopened_and_stop_blocking(store) -> None:
    suggestion_id = store.add_suggestion("fp-0", PAYLOAD)
    store.set_state(suggestion_id, ReviewState.REJECTED, "praneetha")
    assert not store.has_open_suggestion("fp-0")
    store.set_state(suggestion_id, ReviewState.PENDING, "praneetha")
    assert store.has_open_suggestion("fp-0")


def test_unknown_ids_raise(store) -> None:
    with pytest.raises(KeyError):
        store.set_state(999, ReviewState.ACCEPTED, "praneetha")
    with pytest.raises(KeyError):
        store.add_suggestion("missing", PAYLOAD)


def test_findings_round_trip_ordered_by_score() -> None:
    with ReviewStore() as s:
        low = make_scored(fingerprint="low", severity="low")
        high = make_scored(fingerprint="high", severity="critical")
        s.upsert_finding(low)
        s.upsert_finding(high)
        assert [i.finding.fingerprint for i in s.list_findings()] == ["high", "low"]
        assert s.get_finding("high") == high


def _located(fingerprint: str, path: str, rule: str = "py.rule"):
    return make_scored(
        fingerprint=fingerprint, rule_id=rule,
        location=Location(path=path, start_line=1, end_line=1),
    )


def test_repeated_false_positives_are_proposed_not_applied() -> None:
    with ReviewStore() as s:
        for n in range(3):
            s.upsert_finding(_located(f"fp-{n}", f"tests/t{n}.py"))
            s.record_decision(f"fp-{n}", "false_positive", "praneetha")
        (proposal,) = propose(s, min_count=3)
        assert (proposal.rule_id, proposal.path_glob) == ("py.rule", "tests/*")
        assert s.list_suppressions() == []


def test_a_true_positive_blocks_the_proposal() -> None:
    with ReviewStore() as s:
        for n in range(3):
            s.upsert_finding(_located(f"fp-{n}", f"tests/t{n}.py"))
            verdict = "true_positive" if n == 0 else "false_positive"
            s.record_decision(f"fp-{n}", verdict, "praneetha")
        assert propose(s, min_count=2) == []


def test_adopted_rules_suppress_only_matching_findings() -> None:
    with ReviewStore() as s:
        with pytest.raises(ValueError):
            s.add_suppression("py.rule", "tests/*", " ")
        s.add_suppression("py.rule", "tests/*", "fixtures contain fake keys")
        findings = [
            _located("a", "tests/a.py").finding,
            _located("b", "src/b.py").finding,
            _located("c", "tests/c.py", rule="py.other").finding,
        ]
        kept, suppressed = apply_suppressions(findings, s.list_suppressions())
        assert [f.fingerprint for f in suppressed] == ["a"]
        assert [f.fingerprint for f in kept] == ["b", "c"]
