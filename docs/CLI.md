# Command-line reference

```text
vulnscope [--db PATH] <command> [options]
```

`--db` is the SQLite file used by every command (default `vulnscope.db` in the current
directory). Errors are printed as `error: ...` on stderr and the exit status is `1`.

## scan

Parse reports, merge duplicates, fingerprint, apply adopted suppression rules, add context
and reachability, score, and store the result.

```bash
vulnscope scan semgrep.sarif osv.json pip-audit.json npm-audit.json \
    --root . --known-exploited exploited.txt --top 20
```

| Option | Meaning |
| --- | --- |
| `inputs` | One or more report files. The format is detected from the top-level keys. |
| `--root` | Project root used for source excerpts and the import graph (default: current directory). |
| `--known-exploited` | Text file of advisory ids, one per line; `#` starts a comment. |
| `--top` | How many ranked findings to print (default 20). |

Supported formats: SARIF 2.1.0, OSV-Scanner JSON, `pip-audit` JSON (object or older bare list),
and `npm audit` JSON (npm 7+ `vulnerabilities`, npm 6 `advisories`).

Absolute file paths in reports are made relative to `--root` when they are inside it.

## triage

Ask a model for suggestions on the highest-scored findings that have no open suggestion.
Every suggestion is stored as `pending`; nothing is applied to your code.

```bash
vulnscope triage --provider ollama --model <model-name> --top 5
vulnscope triage --provider openai --model <model-name> --allow-remote
```

| Option | Meaning |
| --- | --- |
| `--provider` | `ollama` (default, local) or `openai` (any OpenAI-compatible endpoint). |
| `--model` | Model name understood by the provider. Required. |
| `--top` | Maximum number of new suggestions in this run (default 5). |
| `--allow-remote` | Required for `openai`, because code excerpts leave the machine. |
| `--root` | Project root (default: current directory). |

## review

```bash
vulnscope review list --state pending
vulnscope review accept 3 --reviewer "Your Name" --note "checked against the advisory"
vulnscope review reject 4 --reviewer "Your Name"
vulnscope review reopen 4 --reviewer "Your Name"
vulnscope review false-positive <fingerprint> --reviewer "Your Name"
vulnscope review true-positive  <fingerprint> --reviewer "Your Name"
```

`accept` and `reject` follow the state machine in [ARCHITECTURE.md](ARCHITECTURE.md): an accepted
suggestion is final, a rejected one can be reopened. A reviewer name is required for every change.

## suppress

```bash
vulnscope suppress propose --min-count 3
vulnscope suppress adopt py.hardcoded-secret "tests/*" --reason "fixtures contain fake keys"
```

`propose` lists rules that reviewers marked as false positives at least `--min-count` times in a
directory and never as true positives. `adopt` activates a rule and needs a written reason.
Suppression applies to located SAST findings on later `scan` runs.

## report

```bash
vulnscope report --format markdown --output triage.md
vulnscope report --format sarif --output triage.sarif
```

Without `--output` the report is printed. Model suggestions are labelled with their review
state; unreviewed ones are marked as such. Dependency findings have no source location, so code
scanning services that require one may ignore them in the SARIF output.
