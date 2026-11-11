from pathlib import Path
from datetime import datetime, timezone
import json
import csv
import sys

ROOT = Path(__file__).resolve().parents[2]

P3 = ROOT / "Project3_Red_Team_AI_Identity_Attacks"
P4 = ROOT / "Project4_Blue_Team_Guardrails_Hardening_Detection"
LOG_DIR = P4 / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def newest(folder, pattern):
    files = list(folder.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No matching file: {folder / pattern}")
    return max(files, key=lambda f: f.stat().st_mtime)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


# -------- Project 3 baseline evidence --------

p1_summary = read_json(newest(
    P3 / "01_Indirect_Prompt_Injection" / "logs",
    "*_summary.json"
))

p2 = read_json(newest(
    P3 / "02_Agent_Identity_Spoofing" / "logs",
    "*_agent_spoofing_chain.json"
))

p3 = read_json(
    P3 / "03_System_Prompt_Extraction" / "logs" /
    "corrected_reanalysis.json"
)

p4 = read_json(newest(
    P3 / "04_RAG_Poisoning_MCP_Abuse" / "logs",
    "*_summary.json"
))

# -------- Project 4 hardened input evidence --------

p4_guardrail = read_json(newest(
    P4 / "logs",
    "*_guardrail_results.json"
))

guardrail_results = {
    item["payload_id"]: item
    for item in p4_guardrail["input_results"]
}

if len(guardrail_results) != 5:
    raise RuntimeError(
        "Expected five Project 4 guardrail results."
    )


# One representative payload per attack category in Project 4.
# Project 3 baseline uses the original recorded attempt counts.

cases = [
    {
        "id": "F-01",
        "attack": "Indirect Prompt Injection",
        "p3_attempts": p1_summary["total_tests"],
        "p3_successes": p1_summary["successful_exposures"],
        "p4_id": "P1",
        "control": "Prompt-override input rule + JWT output redaction",
    },
    {
        "id": "F-02",
        "attack": "Agent Identity Spoofing",
        "p3_attempts": 1,
        "p3_successes": int(
            p2["agent_b_vulnerable_test"]
            ["simulated_privileged_action_executed"]
        ),
        "p4_id": "P2",
        "control": "Sender/action input check + Ed25519 signature verification",
    },
    {
        "id": "F-03",
        "attack": "System Prompt Extraction",
        "p3_attempts": p3["total_tests"],
        "p3_successes": p3["system_prompt_information_exposures"],
        "p4_id": "P3",
        "control": "System-prompt extraction input rule",
    },
    {
        "id": "F-04",
        "attack": "RAG Knowledge-Base Poisoning",
        "p3_attempts": 1,
        "p3_successes": int(p4["poisoned_document_retrieved"]),
        "p4_id": "P4",
        "control": "Poisoned-document marker detection",
    },
    {
        "id": "F-05",
        "attack": "MCP Tool Abuse",
        "p3_attempts": 1,
        "p3_successes": int(
            p4["vulnerable_agent_mock_tool_executed"]
        ),
        "p4_id": "P5",
        "control": "Unauthorized MCP tool-request input rule",
    },
]

rows = []

for case in cases:
    guarded = guardrail_results[case["p4_id"]]

    before_attempts = case["p3_attempts"]
    before_successes = case["p3_successes"]

    after_attempts = 1
    after_successes = (
        0 if guarded["status"] == "BLOCKED" else 1
    )

    before_rate = 100 * before_successes / before_attempts
    after_rate = 100 * after_successes / after_attempts

    reduction = before_rate - after_rate

    relative_reduction = (
        100 * reduction / before_rate
        if before_rate > 0 else 0
    )

    rows.append({
        "Finding_ID": case["id"],
        "Attack_Category": case["attack"],
        "Project3_Attempts": before_attempts,
        "Project3_Successes": before_successes,
        "Project3_Success_Rate": f"{before_rate:.1f}%",
        "Project4_Replay_Attempts": after_attempts,
        "Project4_Successes": after_successes,
        "Project4_Success_Rate": f"{after_rate:.1f}%",
        "Reduction_Percentage_Points": f"{reduction:.1f}",
        "Relative_Reduction_Percent": f"{relative_reduction:.1f}%",
        "Project4_Guardrail_Status": guarded["status"],
        "Project4_Block_Reasons": ", ".join(
            guarded.get("block_reasons", [])
        ),
        "Control_Applied": case["control"]
    })


# Category-level average: each of the five categories has equal weight.
before_category_rate = sum(
    float(row["Project3_Success_Rate"].rstrip("%"))
    for row in rows
) / len(rows)

after_category_rate = sum(
    float(row["Project4_Success_Rate"].rstrip("%"))
    for row in rows
) / len(rows)

overall_reduction = before_category_rate - after_category_rate

relative_overall_reduction = (
    100 * overall_reduction / before_category_rate
    if before_category_rate > 0 else 0
)

# Separate metric for the Project 3 prompt-based admin claim.
admin_claims = p3.get("admin_escalation_claims", "Not recorded")

timestamp = datetime.now(timezone.utc).isoformat()

csv_path = LOG_DIR / "Before_After_Comparison.csv"
md_path = LOG_DIR / "Before_After_Comparison.md"
json_path = LOG_DIR / "Before_After_Comparison.json"

with csv_path.open("w", newline="", encoding="utf-8-sig") as file:
    writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

markdown = [
    "# Project 4 - Before/After Attack Comparison",
    "",
    "| Finding | Attack | Project 3 success | Project 4 success | Reduction |",
    "|---|---|---:|---:|---:|"
]

for row in rows:
    markdown.append(
        f"| {row['Finding_ID']} | {row['Attack_Category']} | "
        f"{row['Project3_Success_Rate']} | "
        f"{row['Project4_Success_Rate']} | "
        f"{row['Relative_Reduction_Percent']} |"
    )

markdown += [
    "",
    "## Overall results",
    f"- Project 3 average category success rate: {before_category_rate:.1f}%",
    f"- Project 4 average category success rate: {after_category_rate:.1f}%",
    f"- Absolute reduction: {overall_reduction:.1f} percentage points",
    f"- Relative reduction: {relative_overall_reduction:.1f}%",
    f"- Prompt-based admin-role escalation claims in Project 3: {admin_claims}",
    "",
    "## Methodology and limitations",
    "Five attack categories were compared, using one representative "
    "Project 4 replay per category. Project 3 retains its original "
    "attempt counts (including three indirect-injection tests and "
    "five system-prompt extraction tests). Project 4 results are "
    "category-level representative replays, not equivalent repeated "
    "sample sizes.",
    "",
    "The Project 4 input guardrail status is measured from the recorded "
    "local NeMo-integrated test harness. Ed25519 signature verification "
    "was separately validated with a legitimate and a one-character "
    "tampered message. The Auth0 refresh-token replay test remains "
    "unverified and is not counted as a successful mitigation here.",
    "",
    "All results are controlled local simulations, not production "
    "attack probabilities. The overall rate is an equal-weighted "
    "average of the five attack-category success rates.",
]

md_path.write_text("\n".join(markdown), encoding="utf-8")

summary = {
    "generated_utc": timestamp,
    "project3_average_category_success_rate": round(before_category_rate, 2),
    "project4_average_category_success_rate": round(after_category_rate, 2),
    "absolute_reduction_percentage_points": round(overall_reduction, 2),
    "relative_overall_reduction_percent": round(
        relative_overall_reduction, 2
    ),
    "admin_role_claims_in_project3": admin_claims,
    "rows": rows,
    "limitation": (
        "Five category-level representative replays; Project 3 and "
        "Project 4 attempt counts differ."
    )
}

json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

print("\n" + "=" * 112)
print("SECURENOVA - PROJECT 4 BEFORE/AFTER COMPARISON")
print("=" * 112)

for row in rows:
    print(
        f"{row['Finding_ID']} | {row['Attack_Category']:<34} | "
        f"P3: {row['Project3_Success_Rate']:>6} | "
        f"P4: {row['Project4_Success_Rate']:>6} | "
        f"Reduction: {row['Relative_Reduction_Percent']:>6} | "
        f"{row['Project4_Guardrail_Status']}"
    )

print("\nOverall category-average results:")
print(f"Project 3: {before_category_rate:.1f}%")
print(f"Project 4: {after_category_rate:.1f}%")
print(f"Absolute reduction: {overall_reduction:.1f} percentage points")
print(f"Relative reduction: {relative_overall_reduction:.1f}%")

print("\nAdmin-role claims in Project 3:", admin_claims)
print("\nFiles saved:")
print(csv_path)
print(md_path)
print(json_path)

if all(row["Project4_Guardrail_Status"] == "BLOCKED" for row in rows):
    print("\nRESULT: ALL FIVE REPRESENTATIVE ATTACKS BLOCKED")
else:
    print("\nRESULT: SOME ATTACKS PASSED - REVIEW REQUIRED")
