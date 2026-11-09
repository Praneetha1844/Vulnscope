# Threat model

This is a short, honest description of what Vulnscope defends against and what it does not.
It is a design review, not a security audit.

## Assets

- The scanned source code and the excerpts stored in the SQLite file.
- The host file system around the project root.
- API keys for a remote model provider.
- The integrity of reviewer decisions.

## Trust boundaries

| Input | Trust | Handling |
| --- | --- | --- |
| Scanner reports (SARIF, OSV, pip-audit, npm audit) | Untrusted | Validated while parsing; malformed documents raise `ParseError`. File paths are confined to the project root before any read. |
| Source code excerpts | Untrusted as instructions | Sent to a model only inside delimited blocks; the system prompt says to ignore instructions inside them. |
| Model output | Untrusted | Must be one JSON object matching a schema with size limits. Patches must pass `patch_check`. |
| Reviewer input (CLI) | Trusted but recorded | A reviewer name is required for every state change. |

## Threats and mitigations

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Report points at `../../etc/passwd` or an absolute path | Reads resolve the path and refuse anything outside the root | A symlink inside the root pointing out is resolved and refused; hard links are not detected |
| Prompt injection through code, titles or messages | Delimited, truncated, labelled as data; strict JSON schema; no tool use | A hostile payload may still skew the wording of an explanation |
| Model proposes a patch to another file, a new file, or a deletion | `patch_check` requires exactly one file, the flagged one, existing, applying cleanly | A patch can still be wrong or unsafe inside the flagged file; that is what review is for |
| Patch is applied without a person | Nothing in the code applies patches; `accepted` only records a decision | Someone may apply a patch by hand without reading it |
| API key sent in clear text | The key is refused over plain `http` unless the host is `localhost` | Keys can still be leaked through shell history or CI logs |
| Code leaves the machine | `--provider openai` requires `--allow-remote`; the default provider is local | After consent, excerpts go to whichever endpoint is configured |
| Two reviewers overwrite each other | State changes only succeed from the state that was validated | The tool is single-user in practice; there is no authentication |
| Markdown from a model or a report breaks out of a code fence | Fences grow longer than any backtick run in the text | Rendered Markdown viewers may still treat other text as markup |
| SQL injection | All SQL uses bound parameters | None known |

## Out of scope

- Authentication and authorisation. Anyone with access to the SQLite file can change it.
- Resistance to a malicious local user.
- Verifying that a patch is correct, or that a finding is a true vulnerability.
- Scanning the dependencies of Vulnscope itself; run your own dependency audit.

## Reporting a problem

See [SECURITY.md](../SECURITY.md).
