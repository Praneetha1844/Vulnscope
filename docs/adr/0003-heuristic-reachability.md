# ADR 0003: Reachability is a heuristic that adjusts a score

Status: accepted

## Context

Whether vulnerable code is reachable is the biggest driver of real risk, but sound reachability
analysis needs a call graph, type information and framework models that differ per language.

## Decision

Use a file-level import graph built with `ast`, walked from entry points (files with a
`__main__` guard or common entry names). The outcome is one of `reachable`, `unreachable` or
`unknown`, and it scales the score by 1.0, 0.4 or 0.8. It never removes a finding.

## Alternatives considered

- **No reachability.** Simplest, but everything in a large dependency tree looks equally urgent.
- **Full call-graph analysis.** More accurate, much larger, and language specific.

## Consequences

- Cheap, explainable and available without running the code.
- Wrong in both directions for dynamic imports, plugins and framework wiring, so the factor for
  `unknown` is deliberately close to neutral.
- Packages that are never imported are `unknown`, not `unreachable`, because they may be
  transitive or used from another language.
