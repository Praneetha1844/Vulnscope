"""Command line interface: scan, triage, review, suppress, report."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from vulnscope.llm import LLMError, LLMProvider, OllamaProvider, OpenAICompatProvider
from vulnscope.models import ReviewState, Suggestion
from vulnscope.parsers import ParseError
from vulnscope.pipeline import load_known_exploited, scan
from vulnscope.remediation import Suggester, SuggestionRejected
from vulnscope.report import render_markdown, render_sarif
from vulnscope.store import ReviewStore
from vulnscope.suppression import propose

DEFAULT_DB = "vulnscope.db"


def build_provider(name: str, model: str, allow_remote: bool) -> LLMProvider:
    if name == "ollama":
        return OllamaProvider(model, os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    if not allow_remote:
        raise LLMError(
            "the openai provider sends code excerpts to a remote service; "
            "pass --allow-remote to confirm"
        )
    return OpenAICompatProvider(
        model,
        os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        os.environ.get("OPENAI_API_KEY", ""),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnscope", description=__doc__)
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="parse reports, score and store findings")
    scan_p.add_argument("inputs", nargs="+", type=Path)
    scan_p.add_argument("--root", type=Path, default=Path.cwd())
    scan_p.add_argument("--known-exploited", type=Path)
    scan_p.add_argument("--top", type=int, default=20)

    triage_p = sub.add_parser("triage", help="ask a model for suggestions (stored as pending)")
    triage_p.add_argument("--root", type=Path, default=Path.cwd())
    triage_p.add_argument("--top", type=int, default=5)
    triage_p.add_argument("--provider", choices=["ollama", "openai"], default="ollama")
    triage_p.add_argument("--model", required=True)
    triage_p.add_argument("--allow-remote", action="store_true")

    review_p = sub.add_parser("review", help="inspect and decide on suggestions")
    review_sub = review_p.add_subparsers(dest="action", required=True)
    list_p = review_sub.add_parser("list")
    list_p.add_argument("--state", choices=[s.value for s in ReviewState])
    for action in ("accept", "reject", "reopen"):
        p = review_sub.add_parser(action)
        p.add_argument("suggestion_id", type=int)
        p.add_argument("--reviewer", required=True)
        p.add_argument("--note")
    for verdict in ("false-positive", "true-positive"):
        p = review_sub.add_parser(verdict)
        p.add_argument("fingerprint")
        p.add_argument("--reviewer", required=True)

    suppress_p = sub.add_parser("suppress", help="propose or adopt suppression rules")
    suppress_sub = suppress_p.add_subparsers(dest="action", required=True)
    propose_p = suppress_sub.add_parser("propose")
    propose_p.add_argument("--min-count", type=int, default=3)
    adopt_p = suppress_sub.add_parser("adopt")
    adopt_p.add_argument("rule_id")
    adopt_p.add_argument("path_glob")
    adopt_p.add_argument("--reason", required=True)

    report_p = sub.add_parser("report", help="write a Markdown or SARIF report")
    report_p.add_argument("--format", choices=["markdown", "sarif"], default="markdown")
    report_p.add_argument("--output", type=Path)
    return parser


def _cmd_scan(args: argparse.Namespace, store: ReviewStore) -> int:
    scored, suppressed = scan(
        args.inputs,
        args.root,
        load_known_exploited(args.known_exploited),
        store.list_suppressions(),
    )
    for item in scored:
        store.upsert_finding(item)
    print(f"{len(scored)} finding(s) stored, {len(suppressed)} suppressed by adopted rules")
    for item in scored[: args.top]:
        f = item.finding
        where = f"{f.location.path}:{f.location.start_line}" if f.location else f.package or "-"
        print(f"{item.score.priority}  {item.score.final:>5}  {f.rule_id:<28} {where}")
    return 0


def _cmd_triage(args: argparse.Namespace, store: ReviewStore) -> int:
    suggester = Suggester(build_provider(args.provider, args.model, args.allow_remote), args.root)
    made = 0
    for item in store.list_findings():
        if made >= args.top:
            break
        if store.has_open_suggestion(item.finding.fingerprint):
            continue
        try:
            payload = suggester.suggest(item)
        except (SuggestionRejected, LLMError) as exc:
            print(f"skipped {item.finding.fingerprint}: {exc}", file=sys.stderr)
            continue
        suggestion_id = store.add_suggestion(item.finding.fingerprint, payload)
        print(f"suggestion {suggestion_id} stored as pending for {item.finding.rule_id}")
        made += 1
    return 0


def _cmd_review(args: argparse.Namespace, store: ReviewStore) -> int:
    if args.action == "list":
        state = ReviewState(args.state) if args.state else None
        for suggestion_id, s in store.list_suggestions(state=state):
            print(f"{suggestion_id:>4}  {s.state:<9} {s.fingerprint}  {s.payload.explanation[:70]}")
        return 0
    if args.action in ("false-positive", "true-positive"):
        store.record_decision(args.fingerprint, args.action.replace("-", "_"), args.reviewer)
        print("decision recorded")
        return 0
    target = {
        "accept": ReviewState.ACCEPTED,
        "reject": ReviewState.REJECTED,
        "reopen": ReviewState.PENDING,
    }[args.action]
    store.set_state(args.suggestion_id, target, args.reviewer, args.note)
    print(f"suggestion {args.suggestion_id} is now {target}")
    return 0


def _cmd_suppress(args: argparse.Namespace, store: ReviewStore) -> int:
    if args.action == "propose":
        for p in propose(store, args.min_count):
            print(f"{p.rule_id}  {p.path_glob}  ({p.false_positives} false positives)")
        return 0
    store.add_suppression(args.rule_id, args.path_glob, args.reason)
    print("suppression rule adopted")
    return 0


def _cmd_report(args: argparse.Namespace, store: ReviewStore) -> int:
    items = store.list_findings()
    by_fingerprint: dict[str, list[Suggestion]] = {}
    for _, suggestion in store.list_suggestions():
        by_fingerprint.setdefault(suggestion.fingerprint, []).append(suggestion)
    render = render_sarif if args.format == "sarif" else render_markdown
    text = render(items, by_fingerprint)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text)
    return 0


COMMANDS = {
    "scan": _cmd_scan,
    "triage": _cmd_triage,
    "review": _cmd_review,
    "suppress": _cmd_suppress,
    "report": _cmd_report,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        with ReviewStore(args.db) as store:
            return COMMANDS[args.command](args, store)
    except (ParseError, LLMError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
