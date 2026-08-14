# SwarmBench Capstone — SBOM Compliance Audit (canada-ca)

A Harbor-format SwarmBench task package that audits every public repository in the
[Government of Canada GitHub organisation](https://github.com/canada-ca) against
six supply chain security standards and produces a compliance spreadsheet, four
presentation charts, and a senior management briefing note.

---

## Task Overview

| Field | Value |
|---|---|
| Task ID | `a7f3c9e2b1d84f6a0e5c7b2d9f1a3e8c-SWARMBENCH-HIERARCHICAL-SBOM-AUDIT` |
| Domain | `code-swe` |
| Coordination Pattern | Hierarchical (orchestrator → managers → workers) |
| Estimated Sub-Agents | 226 |
| Human Solving Hours | ~28 hours |
| Verifier Type | Executable |

---

## The Six Standards Audited

1. **SBOM present** — a valid SBOM file or dependency manifest exists
2. **Licence declared** — a LICENSE file with a recognised open source licence
3. **Security policy** — a SECURITY.md with substantive responsible-disclosure instructions
4. **Contributing guide** — a CONTRIBUTING.md exists
5. **Actively maintained** — last commit within the past 365 days
6. **Dependency scanning in CI** — GitHub Actions workflow runs dependency auditing

---

## Repository Structure

```
├── high_level_prompt.md        # Short requester brief (~250 words)
├── instruction.md              # Full task contract (standards, columns, output paths)
├── task.toml                   # Task metadata (timeouts, resources, DAG shape)
├── decomposition.yaml          # 3-stage coordination plan
├── environment/
│   ├── Dockerfile              # Agent runtime image (no tests or solution material)
│   └── input_artifacts/        # Static reference files available to the agent
└── tests/
    ├── rubric_manifest.json    # Maps every check to its verify.py function
    ├── verify.py               # Full verifier (static + oracle + reward-hacking checks)
    └── test.sh                 # Entrypoint — calls verify.py
```

---

## Agent Outputs (written to `/logs/agent/`)

| File | Description |
|---|---|
| `compliance_matrix.csv` | One row per public repo, 22 columns |
| `chart_compliance_split.png` | Pie chart — Full / Partial / Non-compliant split |
| `chart_standards_pass_rate.png` | Bar chart — pass rate per standard |
| `chart_worst_repos.png` | Bar chart — 10 worst-performing repos |
| `chart_commit_staleness.png` | Histogram — days since last commit |
| `output.json` | Summary statistics + senior management briefing note |

---

## Scoring

The verifier computes four component scores and averages them into a final reward written to `/logs/verifier/reward.json`:

| Component | What It Measures |
|---|---|
| `static_check_score` | Files exist, parse, correct columns, row count, valid PNG |
| `content_grounding_score` | Spot-checks 15 repos against live GitHub API |
| `cross_artifact_consistency_score` | CSV counts match output.json; derived fields are correct |
| `reward_hacking_resistance_score` | No duplicates, no uniform values, no fabricated Full compliance |

---

## Why Multi-Agent?

A single agent would exhaust the GitHub unauthenticated rate limit (60 req/hour) after ~10 repos. The hierarchical design spawns one manager per repository concurrently, each with two parallel workers, reducing wall-clock time from hours to minutes. See `task.toml` → `why_multi_agent` for the full explanation.

---

## Requester

Treasury Board of Canada Secretariat (TBS) — supply chain security compliance presentation for senior management.
