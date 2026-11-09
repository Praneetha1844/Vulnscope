# Local development

Requires Python 3.12 or newer.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
make install                       # editable install with dev tools
pre-commit install                 # optional: lint and format on commit
make check                         # ruff, mypy (strict) and pytest with coverage
```

## Layout

- `src/vulnscope/` is the package. The pipeline modules are pure functions; `store.py` is the
  only module that touches the database and `llm.py` the only one that touches the network.
- `tests/` uses hand-written sample reports in `tests/helpers.py`. They imitate the shape of
  real scanner output and were not produced by running a scanner.
- `docs/adr/` holds decision records. Add one when a choice has real trade-offs.

## Conventions

- Type hints everywhere; `mypy --strict` runs on `src`.
- Line length 100, `ruff` for lint and format.
- No new runtime dependency unless the standard library cannot do the job (see ADR 0004).
- Model providers implement `complete(system, prompt) -> str`; use `FakeProvider` in tests.
- Never write a path that came from a report without confining it to the project root.

## Adding a report format

1. Write `parse_<format>(data) -> list[Finding]` in `parsers.py`. Validate what you rely on and
   raise `ParseError` otherwise.
2. Add a detection branch in `parse_document`.
3. Add a small sample to `tests/helpers.py` and tests in `tests/test_parsers.py`.
4. Document the format in `docs/CLI.md`.

## Running against a real project

```bash
semgrep --sarif -o semgrep.sarif .           # your own scanner runs
pip-audit -f json -o pip-audit.json
vulnscope scan semgrep.sarif pip-audit.json --root .
```

Use public code only.
