# Roadmap

Nothing here is promised; it is the order in which gaps would be closed.

## Near term

- Run the test suite and CI in a clean environment and fix whatever it finds.
- Capture real Semgrep, OSV-Scanner, `pip-audit` and `npm audit` output from public
  repositories and replace the hand-written samples where it adds coverage.
- Convert CVSS vector strings to numeric scores.

## Evaluation

- Choose a few public repositories, run the scanners, and record how many findings are merged,
  how many suggestions pass the patch check, and how reviewers judge them. Publish the method
  and the raw results together; until then no figures are claimed.

## Features

- Reachability for JavaScript and Java.
- Optional EPSS and known-exploited feed importers.
- A `triage --dry-run` that prints the prompt without calling a provider.
- Locations for dependency findings (the manifest line) so code-scanning services accept them.

## Packaging

- Release to PyPI and publish a container image.
- Pin and audit the dev tool versions in `pyproject.toml` and `.pre-commit-config.yaml`.
