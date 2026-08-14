# Software Bill of Materials (SBOM) Compliance Audit — canada-ca GitHub Organisation

## Background

The Treasury Board of Canada Secretariat publishes open source software under the **canada-ca** GitHub organisation (<https://github.com/canada-ca>). In preparation for a senior management presentation on supply chain security posture, a compliance audit of every public repository is required.

## What You Must Deliver

Audit **every public repository** in the canada-ca GitHub organisation against the following six supply chain security standards:

1. A valid SBOM or dependency manifest is present.
2. A licence file declaring an open source licence exists.
3. A security policy with real responsible-disclosure instructions exists.
4. A contributing guide exists.
5. The repository has been actively maintained (last commit within 365 days).
6. Dependency scanning runs in CI.

Produce the following output files under `/logs/agent/`:

| File | Description |
|---|---|
| `compliance_matrix.csv` | One row per repository, all columns as specified in `instruction.md` |
| `chart_compliance_split.png` | Pie chart — Full / Partial / Non-compliant split |
| `chart_standards_pass_rate.png` | Bar chart — pass rate for each of the 6 standards |
| `chart_worst_repos.png` | Bar chart — 10 worst-performing repositories by standards_met |
| `chart_commit_staleness.png` | Histogram — distribution of days_since_last_commit |
| `output.json` | Briefing note and summary statistics for senior management |

## Constraints

- Do **not** fabricate any field value. Use exactly `Unknown` when a value cannot be determined.
- All repository data must be fetched live from GitHub at runtime.
- The CSV must contain exactly one row per public repository discovered in the organisation.
- Charts must be generated from the CSV data — not hard-coded.
- The briefing note in `output.json` must name specific high-risk repositories and recommend concrete remediation actions.
