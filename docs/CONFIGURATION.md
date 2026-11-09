# Configuration reference

Vulnscope has no configuration file. Behaviour is set with command-line options and three
environment variables, which are only read when a model provider is used.

| Variable | Default | Used by | Notes |
| --- | --- | --- | --- |
| `OLLAMA_HOST` | `http://localhost:11434` | `--provider ollama` | Address of a local Ollama server. |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | `--provider openai` | Any server exposing `/chat/completions`. Must be `https`, or `http` on `localhost` / `127.0.0.1`. |
| `OPENAI_API_KEY` | none | `--provider openai` | Required for that provider. Never commit it. |

`.env.example` lists the same names with placeholders. Vulnscope does not load `.env` files
itself; export the variables in your shell or CI environment.

## Fixed limits

| Limit | Value | Where |
| --- | --- | --- |
| Source file size read for excerpts | 1,000,000 bytes | `context.py` |
| Excerpt radius | 3 lines either side | `context.py` |
| Patch length | 400 lines | `patch_check.py` |
| Finding title / message sent to a model | 200 / 2,000 characters | `remediation.py` |
| Code excerpt sent to a model | 4,000 characters | `remediation.py` |
| Model explanation / patch accepted | 4,000 / 60,000 characters | `models.py` |
| Attempts per suggestion | 2 | `Suggester(max_attempts=...)` |
| Provider request timeout | 120 seconds | `llm.py` |

## Scoring constants

See `scoring.py`: severity base values, reachability factors, the exploit bonus and the
priority bands. They are a documented starting point, not a calibrated model.

## Data stored on disk

The SQLite file given by `--db` holds findings (including code excerpts), suggestions,
reviewer names and decisions, and adopted suppression rules. Treat it as sensitive if the
scanned code is, and keep it out of version control (`*.db` is in `.gitignore`).
