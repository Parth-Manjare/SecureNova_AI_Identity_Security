from pathlib import Path
from datetime import datetime, timezone
import json
import csv

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Ten legitimate identity-risk test cases
test_cases = [
    {"id": "LEGIT-01", "risk_score": 0,  "risk_level": "low"},
    {"id": "LEGIT-02", "risk_score": 5,  "risk_level": "low"},
    {"id": "LEGIT-03", "risk_score": 10, "risk_level": "low"},
    {"id": "LEGIT-04", "risk_score": 15, "risk_level": "low"},
    {"id": "LEGIT-05", "risk_score": 20, "risk_level": "low"},
    {"id": "LEGIT-06", "risk_score": 25, "risk_level": "low"},
    {"id": "LEGIT-07", "risk_score": 30, "risk_level": "low"},
    {"id": "LEGIT-08", "risk_score": 40, "risk_level": "medium"},
    {"id": "LEGIT-09", "risk_score": 50, "risk_level": "medium"},
    {"id": "LEGIT-10", "risk_score": 70, "risk_level": "medium"},
]


def evaluate_action(metadata):
    score = metadata.get("risk_score", 0)
    level = str(metadata.get("risk_level", "low")).lower()

    try:
        score = float(score)
    except (ValueError, TypeError):
        return "DENY"

    if score >= 80 or level == "high" or score != score:
        return "DENY"

    return "ALLOW"


results = []

print("=" * 68)
print("SECURENOVA - AUTH0 RISK GUARDRAIL TEST")
print("TEN LEGITIMATE INPUTS")
print("=" * 68)

for case in test_cases:
    actual = evaluate_action(case)
    expected = "ALLOW"

    false_positive = actual == "DENY"

    result = {
        **case,
        "expected": expected,
        "actual": actual,
        "false_positive": false_positive,
        "result": "PASS" if actual == expected else "FAIL"
    }

    results.append(result)

    print(
        f"{case['id']} | Score={case['risk_score']} | "
        f"Level={case['risk_level']} | "
        f"Decision={actual} | {result['result']}"
    )

false_positives = sum(r["false_positive"] for r in results)
total = len(results)
fpr = (false_positives / total) * 100

summary = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "test_type": "Local Auth0 Action policy test",
    "total_legitimate_inputs": total,
    "accepted": total - false_positives,
    "false_positives": false_positives,
    "false_positive_rate_percent": fpr,
    "results": results,
    "limitation": (
        "These are local policy tests, not ten live Auth0 "
        "authentication transactions."
    )
}

timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

json_file = LOG_DIR / f"{timestamp}_false_positive_test.json"
csv_file = LOG_DIR / f"{timestamp}_false_positive_test.csv"

json_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

with csv_file.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=list(results[0].keys())
    )
    writer.writeheader()
    writer.writerows(results)

print("\n" + "=" * 68)
print("FALSE POSITIVE RATE SUMMARY")
print("=" * 68)
print(f"Legitimate inputs: {total}")
print(f"Accepted: {total - false_positives}")
print(f"False positives: {false_positives}")
print(f"False Positive Rate: {fpr:.2f}%")
print("JSON:", json_file)
print("CSV:", csv_file)
