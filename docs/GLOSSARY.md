# Glossary

| Term | Meaning in Vulnscope |
| --- | --- |
| **SAST** | Static application security testing: tools that read source code and report suspected flaws. |
| **SCA / FOSS findings** | Reports about known-vulnerable open-source dependencies. Called "dependency" findings in the code. |
| **SARIF** | Static Analysis Results Interchange Format (2.1.0), a JSON format for analysis results. |
| **OSV** | Open Source Vulnerabilities, a schema and database of advisories; OSV-Scanner emits it. |
| **Advisory id / alias** | An identifier such as `GHSA-...` or `CVE-...`. Tools often list each other's ids as aliases, which is how duplicates are merged. |
| **CVSS** | Common Vulnerability Scoring System, a 0 to 10 severity score. Only numeric scores are used. |
| **Finding** | One normalised report entry, independent of the tool that produced it. |
| **Fingerprint** | A stable identifier for a finding that survives line-number changes. |
| **Reachability** | A heuristic signal from the Python import graph: *reachable*, *unreachable* or *unknown*. Not proof. |
| **Known exploited** | An advisory id listed in the file passed to `scan --known-exploited`. Adds a score bonus. |
| **Priority (P1 to P4)** | A band derived from the final score; P1 is the most urgent. |
| **Suggestion** | A model-proposed explanation and optional patch, stored with a review state. |
| **Patch check** | The validation that a suggested diff touches only the flagged file and applies cleanly. |
| **Review state** | `pending`, `accepted` or `rejected`. Changing it never changes your code. |
| **Suppression rule** | A rule id plus a path glob that hides future matching SAST findings. Proposed by the tool, adopted by a person. |
| **Prompt injection** | Text inside data that tries to act as an instruction to the model. |
