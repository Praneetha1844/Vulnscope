# ADR 0004: Standard library for HTTP, CLI and storage

Status: accepted

## Context

Vulnscope is meant to run in CI jobs and on developer machines. Every runtime dependency is
something to audit, which is awkward for a security tool.

## Decision

Use `urllib`, `argparse`, `sqlite3` and `ast`, plus a small hand-written unified-diff applier. The only
runtime dependency is `pydantic`, which provides strict validation of untrusted model output.

## Consequences

- A small supply-chain surface and no service to operate.
- Less convenient than `requests` or `click`; retries, streaming and shell completion are absent.
- SQLite suits a single reviewer or a small team. Concurrent multi-user review would need a
  different store.
