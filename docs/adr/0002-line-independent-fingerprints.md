# ADR 0002: Fingerprints ignore line numbers

Status: accepted

## Context

Review decisions and suggestions are keyed by a finding identity. If that identity included the
line number, any edit above a finding would orphan its review history.

## Decision

SAST fingerprints hash rule id, file path and message. Several findings that share all three
receive an ordinal suffix, assigned in line order. Dependency fingerprints hash the lower-cased
package, version and the smallest advisory id.

## Alternatives considered

- **Include line number.** Precise but unstable across edits.
- **Hash the code excerpt.** Stable across line shifts but changes on any nearby edit, and needs the
  file at fingerprint time.

## Consequences

- Review history survives unrelated edits.
- Two identical hits in one file are told apart only by order; inserting a new identical hit above
  an existing one shifts the ordinals. This is a known limitation.
- Moving a file changes the fingerprint.
