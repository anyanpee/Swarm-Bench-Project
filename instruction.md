# Task Contract — SBOM Compliance Audit of canada-ca GitHub Organisation

## Requester Context

You are acting on behalf of the **Treasury Board of Canada Secretariat (TBS)**. TBS publishes open source software under the GitHub organisation **canada-ca** at <https://github.com/canada-ca>. Senior management requires a compliance audit of every public repository against six supply chain security standards before an upcoming presentation.

---

## Objective

Discover every public repository in the canada-ca GitHub organisation, evaluate each one against the six standards below, and produce a compliance matrix (CSV), four presentation charts (PNG), and a structured briefing note (JSON).

---

## The Six Supply Chain Security Standards

| # | Standard | Pass Condition |
|---|---|---|
| 1 | **SBOM present** | A valid SBOM file exists: `bom.json`, `bom.xml`, `sbom.spdx.json`, `cyclonedx.json`, `sbom.json`, `sbom.xml`, or a recognised dependency manifest (`package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `Gemfile.lock`, `Cargo.lock`, `composer.lock`, `pom.xml`, `build.gradle`, `requirements.txt`). Search root, `.github/`, and `docs/`. |
| 2 | **Licence declared** | A `LICENSE`, `LICENSE.md`, or `LICENCE` file exists containing a recognised open source licence (MIT, Apache-2.0, GPL-*, OGL-Canada-2.0, etc.). |
| 3 | **Security policy** | A `SECURITY.md` exists in root, `.github/`, or `docs/` with substantive responsible-disclosure instructions — not a placeholder or empty file. |
| 4 | **Contributing guide** | A `CONTRIBUTING.md` or `CONTRIBUTING` file exists in root or `.github/`. |
| 5 | **Actively maintained** | The most recent commit to the default branch is within the past **365 days** from the date of the audit. |
| 6 | **Dependency scanning in CI** | A GitHub Actions workflow file (`.github/workflows/*.yml`) or other CI config contains a dependency-auditing step: `npm audit`, `pip-audit`, `safety`, `snyk`, `trivy`, `grype`, `owasp-dependency-check`, `dependabot` alerts enabled, or equivalent. |

---

## Compliance Matrix Columns

Write one row per repository to `/logs/agent/compliance_matrix.csv`.

| Column | Type | Allowed Values / Format |
|---|---|---|
| `repo_name` | string | Exact repository name as returned by GitHub |
| `repo_url` | string | Full HTTPS URL, e.g. `https://github.com/canada-ca/repo-name` |
| `primary_language` | string | Language GitHub reports as primary, or `Unknown` |
| `sbom_exists` | enum | `Yes` / `No` / `Unknown` |
| `sbom_format` | enum | `SPDX` / `CycloneDX` / `Unknown` / `None` |
| `dependency_manifest_exists` | enum | `Yes` / `No` / `Unknown` |
| `readme_exists` | enum | `Yes` / `No` / `Unknown` |
| `licence` | string | Short SPDX identifier (e.g. `MIT`, `Apache-2.0`, `OGL-Canada-2.0`) or `Unknown` |
| `security_policy` | enum | `Present` / `Incomplete` / `Missing` / `Unknown` |
| `contributing_guide` | enum | `Yes` / `No` / `Unknown` |
| `has_dependency_scanning_in_ci` | enum | `Yes` / `No` / `No CI` / `Unknown` |
| `has_tests_in_ci` | enum | `Yes` / `No` / `No CI` / `Unknown` |
| `dependency_update_policy` | enum | `Automated` / `Manual` / `None` / `Unknown` |
| `last_commit_date` | string | `YYYY-MM-DD` or `Unknown` |
| `days_since_last_commit` | integer or string | Integer ≥ 0, or `Unknown` |
| `maintained` | enum | `Yes` / `No` / `Unknown` |
| `open_issues_count` | integer or string | Integer ≥ 0 (exclude PRs), or `Unknown` |
| `open_dependabot_prs` | integer or string | Integer ≥ 0, or `Unknown` |
| `vulnerabilities_known` | integer or string | Integer ≥ 0, or `Unknown` |
| `standards_met` | integer | 0–6 |
| `compliance_status` | enum | `Full` (standards_met = 6) / `Partial` (2–5) / `Non-compliant` (0–1) |
| `gaps` | string | Semicolon-separated list of failing standard names, or `None` |

### Allowed-value enforcement

- `sbom_exists`: only `Yes`, `No`, `Unknown`
- `sbom_format`: only `SPDX`, `CycloneDX`, `Unknown`, `None`
- `dependency_manifest_exists`: only `Yes`, `No`, `Unknown`
- `readme_exists`: only `Yes`, `No`, `Unknown`
- `security_policy`: only `Present`, `Incomplete`, `Missing`, `Unknown`
- `contributing_guide`: only `Yes`, `No`, `Unknown`
- `has_dependency_scanning_in_ci`: only `Yes`, `No`, `No CI`, `Unknown`
- `has_tests_in_ci`: only `Yes`, `No`, `No CI`, `Unknown`
- `dependency_update_policy`: only `Automated`, `Manual`, `None`, `Unknown`
- `maintained`: only `Yes`, `No`, `Unknown`
- `compliance_status`: only `Full`, `Partial`, `Non-compliant`

---

## Standards-Met Calculation

Compute `standards_met` as the count of standards that pass:

1. `sbom_exists == "Yes"` **OR** `dependency_manifest_exists == "Yes"` → Standard 1 passes
2. `licence != "Unknown"` → Standard 2 passes
3. `security_policy == "Present"` → Standard 3 passes
4. `contributing_guide == "Yes"` → Standard 4 passes
5. `maintained == "Yes"` → Standard 5 passes
6. `has_dependency_scanning_in_ci == "Yes"` → Standard 6 passes

---

## Charts

Generate all four charts from the CSV data and save as PNG to `/logs/agent/`:

| File | Chart Type | Data |
|---|---|---|
| `chart_compliance_split.png` | Pie chart | Count of Full / Partial / Non-compliant repos |
| `chart_standards_pass_rate.png` | Horizontal bar chart | Pass rate (%) for each of the 6 standards |
| `chart_worst_repos.png` | Horizontal bar chart | 10 repos with lowest `standards_met` (ties broken by `days_since_last_commit` descending) |
| `chart_commit_staleness.png` | Histogram | Distribution of `days_since_last_commit` (numeric rows only) |

---

## Briefing Note — `/logs/agent/output.json`

```json
{
  "total_repos_audited": <integer>,
  "fully_compliant": <integer>,
  "partially_compliant": <integer>,
  "non_compliant": <integer>,
  "most_common_gap": "<standard name>",
  "highest_risk_repos": [
    {"repo": "<name>", "reason": "<specific reason>"},
    ...
  ],
  "briefing_note": "<2-3 paragraphs for senior management naming specific repos, overall compliance rate, and top 3 recommended actions>"
}
```

- `briefing_note` must be 2–3 paragraphs of prose.
- It must name at least three specific repositories by name.
- It must state the overall compliance rate as a percentage.
- It must recommend exactly three concrete remediation actions.

---

## Data Collection Rules

- Fetch all data live from GitHub at runtime. Do **not** hard-code or fabricate values.
- Use the GitHub REST API (`https://api.github.com/orgs/canada-ca/repos?type=public&per_page=100`) and paginate until all repositories are collected.
- For file existence checks, use the GitHub Contents API or raw file URLs.
- For CI checks, fetch `.github/workflows/` directory listings and read workflow YAML content.
- If a value genuinely cannot be determined (API error, empty repo, etc.), write exactly `Unknown`.
- `open_issues_count` must exclude pull requests (use `open_issues_count` from the repo API response, which already excludes PRs, or subtract PR count explicitly).

---

## Output Paths Summary

```
/logs/agent/compliance_matrix.csv
/logs/agent/chart_compliance_split.png
/logs/agent/chart_standards_pass_rate.png
/logs/agent/chart_worst_repos.png
/logs/agent/chart_commit_staleness.png
/logs/agent/output.json
```

All output directories must be created by the agent if they do not exist.
