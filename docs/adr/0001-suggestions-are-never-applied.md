# ADR 0001: Suggestions are never applied automatically

Status: accepted

## Context

A model can produce a plausible but wrong or unsafe patch. Applying it automatically would turn
a triage tool into a code-modifying tool with an untrusted author.

## Decision

Vulnscope validates and stores suggestions but never writes to the scanned project. Every
suggestion starts as `pending`, is labelled unreviewed in reports, and moves on only when a named
reviewer accepts or rejects it.

## Consequences

- Safer by construction: the worst case of a bad suggestion is a rejected suggestion.
- Slower: a person must read each one. That is intended.
- `accepted` records a decision; applying the patch remains a manual step in the developer's own
  workflow.
- A future "apply" feature would need its own ADR, a dry-run mode and a rollback story.
