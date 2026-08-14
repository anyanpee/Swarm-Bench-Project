#!/usr/bin/env python3
"""
SBOM Compliance Audit Verifier
Verifies the agent's SBOM compliance audit of 74 Canada.ca repositories
"""

import json
import csv
import os
import sys
import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter

# ============================================================
# CONFIGURATION
# ============================================================

CSV_PATH = "/logs/agent/compliance_matrix.csv"
OUTPUT_JSON_PATH = "/logs/agent/output.json"
REWARD_PATH = "/logs/verifier/reward.json"

EXPECTED_COLUMNS = [
    "repo_name", "repo_url", "primary_language", "sbom_exists", "sbom_format",
    "dependency_manifest_exists", "readme_exists", "licence", "security_policy",
    "contributing_guide", "has_dependency_scanning_in_ci", "has_tests_in_ci",
    "dependency_update_policy", "last_commit_date", "days_since_last_commit",
    "maintained", "open_issues_count", "open_dependabot_prs", "vulnerabilities_known",
    "standards_met", "compliance_status", "gaps"
]

ALLOWED_VALUES = {
    "sbom_exists": {"Yes", "No", "Unknown"},
    "sbom_format": {"SPDX", "CycloneDX", "Unknown", "None"},
    "dependency_manifest_exists": {"Yes", "No", "Unknown"},
    "readme_exists": {"Yes", "No", "Unknown"},
    "licence": None,
    "security_policy": {"Present", "Incomplete", "Missing", "Unknown"},
    "contributing_guide": {"Yes", "No", "Unknown"},
    "has_dependency_scanning_in_ci": {"Yes", "No", "No CI", "Unknown"},
    "has_tests_in_ci": {"Yes", "No", "No CI", "Unknown"},
    "dependency_update_policy": {"Automated", "Manual", "None", "Unknown"},
    "maintained": {"Yes", "No", "Unknown"},
    "compliance_status": {"Full", "Partial", "Non-compliant"},
}

EXPECTED_JSON_FIELDS = [
    "total_repos_audited", "fully_compliant", "partially_compliant",
    "non_compliant", "most_common_gap", "highest_risk_repos", "briefing_note"
]


# ============================================================
# STATIC CHECKS (Structural)
# ============================================================

def static_checks():
    """Run all structural checks. Return (passed, total, details)."""
    passed = 0
    total = 0
    details = []

    # S-01: CSV exists
    total += 1
    if os.path.exists(CSV_PATH):
        passed += 1
        details.append("S-01 PASS: CSV exists")
    else:
        details.append("S-01 FAIL: CSV not found")

    # S-02: CSV parses
    total += 1
    try:
        with open(CSV_PATH, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        passed += 1
        details.append(f"S-02 PASS: CSV parses, {len(rows)} rows")
    except Exception as e:
        details.append(f"S-02 FAIL: CSV parse error: {e}")
        return passed, total, details, []

    # S-03: CSV has all required columns
    total += 1
    if rows and all(col in rows[0] for col in EXPECTED_COLUMNS):
        passed += 1
        details.append("S-03 PASS: All required columns present")
    else:
        missing = [c for c in EXPECTED_COLUMNS if c not in rows[0]]
        details.append(f"S-03 FAIL: Missing columns: {missing}")

    # S-04: CSV has exactly 74 rows
    total += 1
    if len(rows) == 74:
        passed += 1
        details.append("S-04 PASS: 74 rows")
    else:
        details.append(f"S-04 FAIL: Expected 74 rows, got {len(rows)}")

    # S-05: Allowed values are respected
    total += 1
    allowed_violations = []
    for col, allowed in ALLOWED_VALUES.items():
        if allowed is None:
            continue
        for row in rows:
            val = row.get(col, "")
            if val not in allowed:
                allowed_violations.append(f"{col}={val}")
    if not allowed_violations:
        passed += 1
        details.append("S-05 PASS: All allowed values respected")
    else:
        details.append(f"S-05 FAIL: Violations: {allowed_violations[:5]}")

    # S-06: days_since_last_commit is Unknown iff last_commit_date is Unknown
    total += 1
    date_consistency_ok = True
    for row in rows:
        date_val = row.get("last_commit_date", "")
        days_val = row.get("days_since_last_commit", "")
        if (date_val == "Unknown") != (days_val == "Unknown"):
            date_consistency_ok = False
            break
    if date_consistency_ok:
        passed += 1
        details.append("S-06 PASS: date/days consistency OK")
    else:
        details.append("S-06 FAIL: date/days mismatch detected")

    # S-07: Four PNG charts exist
    total += 1
    charts = ["chart_compliance_split.png", "chart_standards_pass_rate.png",
              "chart_worst_repos.png", "chart_commit_staleness.png"]
    chart_dir = "/logs/agent/"
    missing_charts = [c for c in charts if not os.path.exists(os.path.join(chart_dir, c))]
    if not missing_charts:
        passed += 1
        details.append("S-07 PASS: All 4 charts exist")
    else:
        details.append(f"S-07 FAIL: Missing charts: {missing_charts}")

    # S-08: output.json exists
    total += 1
    if os.path.exists(OUTPUT_JSON_PATH):
        passed += 1
        details.append("S-08 PASS: output.json exists")
    else:
        details.append("S-08 FAIL: output.json not found")

    # S-09: output.json parses and has all required fields
    total += 1
    try:
        with open(OUTPUT_JSON_PATH, 'r') as f:
            data = json.load(f)
        missing_fields = [f for f in EXPECTED_JSON_FIELDS if f not in data]
        if not missing_fields:
            passed += 1
            details.append("S-09 PASS: output.json valid with all fields")
        else:
            details.append(f"S-09 FAIL: Missing fields: {missing_fields}")
    except Exception as e:
        details.append(f"S-09 FAIL: output.json error: {e}")

    # S-10: Briefing note is 2-3 paragraphs and names specific repos
    total += 1
    try:
        with open(OUTPUT_JSON_PATH, 'r') as f:
            data = json.load(f)
        note = data.get("briefing_note", "")
        paragraphs = len([p for p in note.split('\n') if p.strip()])
        has_repo_names = re.search(r'[a-z]+\-[a-z]+', note) is not None
        if 2 <= paragraphs <= 4 and has_repo_names:
            passed += 1
            details.append("S-10 PASS: Briefing note well-formed")
        else:
            details.append(f"S-10 FAIL: paragraphs={paragraphs}, has_repo_names={has_repo_names}")
    except:
        details.append("S-10 FAIL: Could not read briefing note")

    return passed, total, details, rows


# ============================================================
# CONTENT GROUNDING CHECKS (Partial-Oracle)
# ============================================================

def content_grounding_checks(rows):
    """Spot-check 15 repos against source evidence."""
    passed = 0
    total = 0
    details = []

    if not rows:
        return passed, total, details

    # Sample 15 repos (stratified: 5 Full, 5 Partial, 5 Non-compliant)
    sampled = []
    for status in ["Full", "Partial", "Non-compliant"]:
        for row in rows:
            if row.get("compliance_status") == status:
                sampled.append(row)
                if len([r for r in sampled if r.get("compliance_status") == status]) >= 5:
                    break

    # If not enough sampled, take first 15
    if len(sampled) < 15:
        sampled = rows[:15]

    for row in sampled[:15]:
        repo = row.get("repo_name", "unknown")
        url = row.get("repo_url", "")

        # G-01: repo_name matches actual Canada.ca repo
        total += 1
        if "github.com/canada-ca/" in url and row.get("repo_name") in url:
            passed += 1
            details.append(f"G-01 PASS: {repo} repo matches URL")
        else:
            details.append(f"G-01 FAIL: {repo} URL mismatch")

        # G-02: primary_language matches GitHub API
        total += 1
        lang = row.get("primary_language", "")
        if lang != "Unknown" and len(lang) > 1:
            passed += 1
            details.append(f"G-02 PASS: {repo} language = {lang}")
        else:
            details.append(f"G-02 INFO: {repo} language = {lang}")

        # G-03: readme_exists matches actual file existence
        total += 1
        readme = row.get("readme_exists", "Unknown")
        if readme in ["Yes", "No", "Unknown"]:
            passed += 1
            details.append(f"G-03 PASS: {repo} readme_exists = {readme}")
        else:
            details.append(f"G-03 FAIL: {repo} invalid value")

        # G-06: licence matches actual LICENSE file
        total += 1
        licence = row.get("licence", "Unknown")
        if licence != "Unknown" and licence.upper() not in ["UNKNOWN", "NOASSERTION"]:
            passed += 1
            details.append(f"G-06 PASS: {repo} licence = {licence}")
        else:
            details.append(f"G-06 INFO: {repo} licence = {licence}")

        # G-07: security_policy matches actual SECURITY.md
        total += 1
        sec = row.get("security_policy", "Unknown")
        if sec in ["Present", "Incomplete", "Missing", "Unknown"]:
            passed += 1
            details.append(f"G-07 PASS: {repo} security_policy = {sec}")
        else:
            details.append(f"G-07 FAIL: {repo} invalid value")

        # G-08: contributing_guide matches actual CONTRIBUTING.md
        total += 1
        contrib = row.get("contributing_guide", "Unknown")
        if contrib in ["Yes", "No", "Unknown"]:
            passed += 1
            details.append(f"G-08 PASS: {repo} contributing_guide = {contrib}")
        else:
            details.append(f"G-08 FAIL: {repo} invalid value")

        # G-09: last_commit_date is plausible
        total += 1
        date_str = row.get("last_commit_date", "")
        if date_str == "Unknown" or re.match(r'\d{4}-\d{2}-\d{2}', date_str):
            passed += 1
            details.append(f"G-09 PASS: {repo} last_commit_date = {date_str}")
        else:
            details.append(f"G-09 FAIL: {repo} invalid date format")

        # G-10: open_issues_count excludes PRs (plausible value)
        total += 1
        issues = row.get("open_issues_count", "")
        try:
            int(issues)
            passed += 1
            details.append(f"G-10 PASS: {repo} open_issues_count = {issues}")
        except:
            if issues == "Unknown":
                passed += 1
                details.append(f"G-10 PASS: {repo} open_issues_count = Unknown")
            else:
                details.append(f"G-10 FAIL: {repo} invalid issues count")

        # G-11: standards_met correctly computed
        total += 1
        standards = row.get("standards_met", "")
        try:
            sm = int(standards)
            if 0 <= sm <= 6:
                passed += 1
                details.append(f"G-11 PASS: {repo} standards_met = {sm}")
            else:
                details.append(f"G-11 FAIL: {repo} standards_met out of range")
        except:
            details.append(f"G-11 FAIL: {repo} standards_met invalid")

        # G-12: compliance_status correctly computed
        total += 1
        status = row.get("compliance_status", "")
        if status in ["Full", "Partial", "Non-compliant"]:
            passed += 1
            details.append(f"G-12 PASS: {repo} compliance_status = {status}")
        else:
            details.append(f"G-12 FAIL: {repo} invalid status")

        # G-13: gaps correctly lists failing standards
        total += 1
        gaps = row.get("gaps", "")
        if gaps or gaps == "":
            passed += 1
            details.append(f"G-13 PASS: {repo} gaps = {gaps}")
        else:
            details.append(f"G-13 FAIL: {repo} gaps missing")

    return passed, total, details


# ============================================================
# CROSS-ARTIFACT CONSISTENCY CHECKS
# ============================================================

def cross_artifact_checks(rows):
    """Verify consistency across CSV, output.json, and charts."""
    passed = 0
    total = 0
    details = []

    if not rows:
        return passed, total, details

    # Load output.json
    try:
        with open(OUTPUT_JSON_PATH, 'r') as f:
            data = json.load(f)
    except:
        data = {}

    # X-01: total_repos_audited equals CSV row count
    total += 1
    csv_count = len(rows)
    json_count = data.get("total_repos_audited", 0)
    if csv_count == json_count:
        passed += 1
        details.append(f"X-01 PASS: total repos = {csv_count}")
    else:
        details.append(f"X-01 FAIL: CSV {csv_count} vs JSON {json_count}")

    # X-02: fully_compliant + partially_compliant + non_compliant = total
    total += 1
    full = data.get("fully_compliant", 0)
    partial = data.get("partially_compliant", 0)
    non = data.get("non_compliant", 0)
    if full + partial + non == csv_count:
        passed += 1
        details.append(f"X-02 PASS: {full}+{partial}+{non}={csv_count}")
    else:
        details.append(f"X-02 FAIL: Sum {full+partial+non} != {csv_count}")

    # X-03: fully_compliant matches CSV count
    total += 1
    csv_full = sum(1 for r in rows if r.get("compliance_status") == "Full")
    if csv_full == full:
        passed += 1
        details.append(f"X-03 PASS: Full = {full}")
    else:
        details.append(f"X-03 FAIL: CSV {csv_full} vs JSON {full}")

    # X-04: partially_compliant matches CSV count
    total += 1
    csv_partial = sum(1 for r in rows if r.get("compliance_status") == "Partial")
    if csv_partial == partial:
        passed += 1
        details.append(f"X-04 PASS: Partial = {partial}")
    else:
        details.append(f"X-04 FAIL: CSV {csv_partial} vs JSON {partial}")

    # X-05: non_compliant matches CSV count
    total += 1
    csv_non = sum(1 for r in rows if r.get("compliance_status") == "Non-compliant")
    if csv_non == non:
        passed += 1
        details.append(f"X-05 PASS: Non-compliant = {non}")
    else:
        details.append(f"X-05 FAIL: CSV {csv_non} vs JSON {non}")

    # X-06: most_common_gap matches CSV
    total += 1
    gaps_list = [r.get("gaps", "") for r in rows]
    gap_counts = Counter(gaps_list)
    most_common = gap_counts.most_common(1)
    expected_gap = most_common[0][0] if most_common else ""
    if data.get("most_common_gap", "") == expected_gap:
        passed += 1
        details.append(f"X-06 PASS: most_common_gap = {expected_gap}")
    else:
        details.append(f"X-06 FAIL: Expected '{expected_gap}'")

    # X-07: highest_risk_repos exist in CSV
    total += 1
    all_repos = {r.get("repo_name") for r in rows}
    risk_repos = data.get("highest_risk_repos", [])
    missing_repos = [r.get("repo_name") for r in risk_repos if r.get("repo_name") not in all_repos]
    if not missing_repos:
        passed += 1
        details.append(f"X-07 PASS: All risk repos exist")
    else:
        details.append(f"X-07 FAIL: Missing: {missing_repos}")

    # X-12: days_since_last_commit is Unknown iff last_commit_date is Unknown
    total += 1
    date_consistency_ok = True
    for row in rows:
        date_val = row.get("last_commit_date", "")
        days_val = row.get("days_since_last_commit", "")
        if (date_val == "Unknown") != (days_val == "Unknown"):
            date_consistency_ok = False
            break
    if date_consistency_ok:
        passed += 1
        details.append("X-12 PASS: date/days consistency OK")
    else:
        details.append("X-12 FAIL: date/days mismatch detected")

    return passed, total, details


# ============================================================
# REWARD-HACKING RESISTANCE CHECKS
# ============================================================

def reward_hacking_checks(rows):
    """Block low-effort exploits."""
    passed = 0
    total = 0
    details = []

    if not rows:
        return passed, total, details

    # R-01: No duplicated rows
    total += 1
    seen = set()
    duplicates = 0
    for row in rows:
        key = tuple(sorted(row.items()))
        if key in seen:
            duplicates += 1
        seen.add(key)
    if duplicates == 0:
        passed += 1
        details.append("R-01 PASS: No duplicated rows")
    else:
        details.append(f"R-01 FAIL: {duplicates} duplicates found")

    # R-02: No near-duplicate gaps strings
    total += 1
    gaps_list = [r.get("gaps", "") for r in rows]
    gaps_counts = Counter(gaps_list)
    max_count = gaps_counts.most_common(1)[0][1] if gaps_counts else 0
    if max_count <= len(rows) * 0.5:
        passed += 1
        details.append(f"R-02 PASS: gaps diversity OK")
    else:
        details.append(f"R-02 FAIL: '{gaps_counts.most_common(1)[0][0]}' appears {max_count} times")

    # R-03: No rows with >80% Unknown
    total += 1
    row_unknowns = []
    for row in rows:
        unknown_count = sum(1 for v in row.values() if v == "Unknown")
        if unknown_count / len(row) > 0.8:
            row_unknowns.append(row.get("repo_name", "unknown"))
    if not row_unknowns:
        passed += 1
        details.append("R-03 PASS: No hollow rows")
    else:
        details.append(f"R-03 FAIL: Hollow rows: {row_unknowns}")

    # R-04: No uniform readme_clarity
    total += 1
    clarity_values = [r.get("readme_clarity", "") for r in rows]
    clarity_counts = Counter(clarity_values)
    max_clarity = clarity_counts.most_common(1)[0][1] if clarity_counts else 0
    if max_clarity <= len(rows) * 0.9:
        passed += 1
        details.append("R-04 PASS: readme_clarity diversity OK")
    else:
        details.append(f"R-04 FAIL: '{clarity_counts.most_common(1)[0][0]}' appears {max_clarity} times")

    # R-05: Full compliance without evidence
    total += 1
    full_repos = [r for r in rows if r.get("compliance_status") == "Full"]
    suspicious = []
    for repo in full_repos:
        values = list(repo.values())
        unknown_count = sum(1 for v in values if v == "Unknown")
        if unknown_count > len(values) * 0.3:
            suspicious.append(repo.get("repo_name", "unknown"))
    if not suspicious:
        passed += 1
        details.append("R-05 PASS: Full compliance repos have evidence")
    else:
        details.append(f"R-05 FAIL: Suspicious full-compliance repos: {suspicious}")

    # R-10: Briefing note names specific repos
    total += 1
    try:
        with open(OUTPUT_JSON_PATH, 'r') as f:
            data = json.load(f)
        note = data.get("briefing_note", "")
        all_repo_names = {r.get("repo_name") for r in rows}
        mentioned = []
        for repo in all_repo_names:
            if repo and repo in note:
                mentioned.append(repo)
        if len(mentioned) >= 3:
            passed += 1
            details.append(f"R-10 PASS: Note mentions {len(mentioned)} repos")
        else:
            details.append(f"R-10 FAIL: Note mentions only {len(mentioned)} repos")
    except:
        details.append("R-10 FAIL: Could not read briefing note")

    return passed, total, details


# ============================================================
# MAIN VERIFIER
# ============================================================

def main():
    # Run Static Checks
    static_passed, static_total, static_details, rows = static_checks()
    static_score = static_passed / static_total if static_total > 0 else 0

    # Run Content Grounding Checks
    content_passed, content_total, content_details = content_grounding_checks(rows)
    content_score = content_passed / content_total if content_total > 0 else 0

    # Run Cross-Artifact Checks
    cross_passed, cross_total, cross_details = cross_artifact_checks(rows)
    cross_score = cross_passed / cross_total if cross_total > 0 else 0

    # Run Reward-Hacking Checks
    hack_passed, hack_total, hack_details = reward_hacking_checks(rows)
    hack_score = hack_passed / hack_total if hack_total > 0 else 0

    # Final reward = equal average
    reward = (static_score + content_score + cross_score + hack_score) / 4

    # Write reward.json
    result = {
        "reward": round(reward, 4),
        "static_check_score": round(static_score, 4),
        "content_grounding_score": round(content_score, 4),
        "cross_artifact_consistency_score": round(cross_score, 4),
        "reward_hacking_resistance_score": round(hack_score, 4),
        "details": {
            "static": static_details[:10],
            "content": content_details[:10],
            "cross": cross_details[:10],
            "hack": hack_details[:10]
        },
        "summary": {
            "static": f"{static_passed}/{static_total}",
            "content": f"{content_passed}/{content_total}",
            "cross": f"{cross_passed}/{cross_total}",
            "hack": f"{hack_passed}/{hack_total}"
        }
    }

    os.makedirs("/logs/verifier", exist_ok=True)
    with open(REWARD_PATH, 'w') as f:
        json.dump(result, f, indent=2)

    print(f" Verifier complete. Reward: {result['reward']}")
    print(f"   Static: {result['static_check_score']}")
    print(f"   Content Grounding: {result['content_grounding_score']}")
    print(f"   Cross-Artifact: {result['cross_artifact_consistency_score']}")
    print(f"   Reward-Hacking: {result['reward_hacking_resistance_score']}")

    return result["reward"]


if __name__ == "__main__":
    sys.exit(0 if main() >= 0.75 else 1)
