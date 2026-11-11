from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from hashlib import sha256
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
PROJECT3 = ROOT / "Project3_Red_Team_AI_Identity_Attacks"
PROJECT4 = ROOT / "Project4_Blue_Team_Guardrails_Hardening_Detection"
LOG_DIR = PROJECT4 / "logs"

VOLUME_THRESHOLD = 20
WINDOW_SECONDS = 60

class AnomalyDetector:
    def __init__(self):
        self.request_windows = defaultdict(deque)
        self.previous_scopes = {}
        self.token_expiry = {}
        self.volume_alert_active = set()
        self.alerts = []

    def alert(self, timestamp, identity, event_type, details):
        alert = {
            "alert_id": f"ALERT-{len(self.alerts) + 1:03d}",
            "timestamp": timestamp.isoformat(),
            "identity": identity,
            "event_type": event_type,
            "details": details
        }
        self.alerts.append(alert)

        print("\n[ANOMALY ALERT]")
        print("Timestamp:", alert["timestamp"])
        print("Identity:", identity)
        print("Event type:", event_type)
        print("Details:", details)

    def record_request(self, identity, timestamp, scopes, attack_ref):
        scopes = tuple(sorted(set(scopes)))

        # Detection 1: More than 20 requests in a rolling 60-second window.
        window = self.request_windows[identity]
        window.append(timestamp)

        while window and (timestamp - window[0]).total_seconds() > WINDOW_SECONDS:
            window.popleft()

        if len(window) > VOLUME_THRESHOLD:
            if identity not in self.volume_alert_active:
                self.alert(
                    timestamp,
                    identity,
                    "LLM_API_VOLUME_SPIKE",
                    {
                        "requests_in_60_seconds": len(window),
                        "threshold": VOLUME_THRESHOLD,
                        "source_attack": attack_ref
                    }
                )
                self.volume_alert_active.add(identity)
        else:
            self.volume_alert_active.discard(identity)

        # Detection 2: Change in scopes between consecutive requests.
        previous = self.previous_scopes.get(identity)

        if previous is not None and previous != scopes:
            self.alert(
                timestamp,
                identity,
                "SCOPE_CHANGE_BETWEEN_CONSECUTIVE_REQUESTS",
                {
                    "previous_scopes": list(previous),
                    "current_scopes": list(scopes),
                    "source_attack": attack_ref
                }
            )

        self.previous_scopes[identity] = scopes

    def register_token(self, identity, token_id, expires_at):
        # Store only a SHA-256 fingerprint, never a raw token.
        fingerprint = sha256(token_id.encode("utf-8")).hexdigest()

        self.token_expiry[fingerprint] = {
            "identity": identity,
            "expires_at": expires_at
        }

        return fingerprint

    def use_token(self, identity, token_fingerprint, timestamp, attack_ref):
        record = self.token_expiry.get(token_fingerprint)

        if record is None:
            return

        if timestamp > record["expires_at"]:
            self.alert(
                timestamp,
                identity,
                "TOKEN_REUSE_AFTER_EXPIRY",
                {
                    "token_fingerprint_prefix": token_fingerprint[:12],
                    "expired_at": record["expires_at"].isoformat(),
                    "source_attack": attack_ref
                }
            )


def newest_file(folder, pattern):
    if not folder.exists():
        return None

    files = list(folder.glob(pattern))
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


def load_project3_attacks():
    """Load the actual five Project 3 attack artifacts."""

    attacks = []

    # P1 - Indirect prompt injection
    p1 = PROJECT3 / "01_Indirect_Prompt_Injection" / \
         "payloads" / "01_helpdesk_document.txt"

    if p1.exists():
        attacks.append(("P1_INDIRECT_INJECTION", p1.name))

    # P2 - Forged orchestrator message
    task2_logs = PROJECT3 / "02_Agent_Identity_Spoofing" / "logs"
    p2 = newest_file(task2_logs, "*_agent_spoofing_chain.json")

    if p2:
        data = json.loads(p2.read_text(encoding="utf-8-sig"))
        if data.get("forged_message"):
            attacks.append(("P2_AGENT_SPOOFING", p2.name))

    # P3 - System prompt extraction
    task3_logs = PROJECT3 / "03_System_Prompt_Extraction" / "logs"
    p3 = newest_file(task3_logs, "*_test_01.json")

    if p3:
        data = json.loads(p3.read_text(encoding="utf-8-sig"))
        if data.get("attack_prompt"):
            attacks.append(("P3_SYSTEM_PROMPT_EXTRACTION", p3.name))

    # P4 - RAG poisoning
    p4 = PROJECT3 / "04_RAG_Poisoning_MCP_Abuse" / \
         "knowledge_base" / "03_poisoned_identity_audit_notes.txt"

    if p4.exists():
        attacks.append(("P4_RAG_POISONING", p4.name))

    # P5 - MCP tool abuse
    if p4.exists() and "simulated_admin_export" in \
            p4.read_text(encoding="utf-8-sig").lower():
        attacks.append(("P5_MCP_TOOL_ABUSE", p4.name))

    return attacks


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    attacks = load_project3_attacks()

    if len(attacks) != 5:
        raise RuntimeError(
            f"Expected all 5 Project 3 attack artifacts; found {len(attacks)}. "
            "Check that Project 3 files are present."
        )

    print("=" * 72)
    print("SECURENOVA - PROJECT 4 BLUE TEAM")
    print("TASK 4: ANOMALY DETECTION")
    print("=" * 72)

    print("\n[1] PROJECT 3 ATTACK REPLAY")
    for attack_id, source in attacks:
        print(f"Loaded: {attack_id} | Source: {source}")

    print("\nFive Project 3 attack artifacts loaded successfully.")

    detector = AnomalyDetector()
    base = datetime.now(timezone.utc).replace(microsecond=0)

    # Scenario 1: Replay Project 3 attack inputs as a burst of 21
    # controlled LLM API request telemetry events within 21 seconds.
    print("\n[2] DETECTION SCENARIO 1 - API VOLUME SPIKE")

    volume_identity = "agent-project3-redteam"

    for index in range(21):
        attack_id, _ = attacks[index % len(attacks)]

        detector.record_request(
            identity=volume_identity,
            timestamp=base + timedelta(seconds=index),
            scopes=["read:ai-data"],
            attack_ref=attack_id
        )

    print("Replayed requests:", 21)
    print("Detection threshold: more than 20 in 60 seconds.")

    # Scenario 2: Simulate an agent's scope changing after a
    # forged orchestrator instruction from Project 3.
    print("\n[3] DETECTION SCENARIO 2 - SCOPE CHANGE")

    scope_identity = "agent-project3-agent-b"

    detector.record_request(
        identity=scope_identity,
        timestamp=base + timedelta(seconds=100),
        scopes=["read:ai-data"],
        attack_ref="P2_AGENT_SPOOFING"
    )

    detector.record_request(
        identity=scope_identity,
        timestamp=base + timedelta(seconds=101),
        scopes=["read:ai-data", "write:admin"],
        attack_ref="P2_AGENT_SPOOFING"
    )

    print("Previous scope: read:ai-data")
    print("New scope: read:ai-data write:admin")

    # Scenario 3: Simulate a Project 3 MCP request attempting
    # to reuse a token after its expiry.
    print("\n[4] DETECTION SCENARIO 3 - EXPIRED TOKEN REUSE")

    token_identity = "agent-project3-mcp"
    simulated_token_id = "SIMULATED-P3-TOKEN-001"

    issued_at = base
    expires_at = issued_at + timedelta(seconds=300)

    fingerprint = detector.register_token(
        identity=token_identity,
        token_id=simulated_token_id,
        expires_at=expires_at
    )

    reuse_time = expires_at + timedelta(seconds=30)

    detector.use_token(
        identity=token_identity,
        token_fingerprint=fingerprint,
        timestamp=reuse_time,
        attack_ref="P5_MCP_TOOL_ABUSE"
    )

    print("Simulated token lifetime: 300 seconds")
    print("Replay time: 330 seconds after issue.")
    print("Raw token stored: NO")

    # Final results
    print("\n" + "=" * 72)
    print("TASK 4 ANOMALY DETECTION SUMMARY")
    print("=" * 72)

    for alert in detector.alerts:
        print(
            f"{alert['event_type']} | "
            f"{alert['identity']} | "
            f"{alert['timestamp']}"
        )

    event_types = {alert["event_type"] for alert in detector.alerts}

    required = {
        "LLM_API_VOLUME_SPIKE",
        "SCOPE_CHANGE_BETWEEN_CONSECUTIVE_REQUESTS",
        "TOKEN_REUSE_AFTER_EXPIRY"
    }

    fired = len(event_types.intersection(required))

    print(f"\nAlerts generated: {len(detector.alerts)}")
    print(f"Detection scenarios fired: {fired}/3")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "detection_method": "Local Python event-based anomaly detection",
        "project3_attack_artifacts_loaded": attacks,
        "thresholds": {
            "api_requests": ">20",
            "window_seconds": 60
        },
        "scenarios_fired": fired,
        "alerts": detector.alerts,
        "raw_tokens_logged": False,
        "execution_scope": "Controlled local telemetry replay; no live API calls"
    }

    log_file = LOG_DIR / f"{timestamp}_anomaly_detection.json"
    log_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("Alert log:", log_file)

    if fired == 3:
        print("RESULT: ALL THREE ANOMALY DETECTIONS PASSED")
        return 0

    print("RESULT: ONE OR MORE DETECTION SCENARIOS FAILED")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ANOMALY DETECTION ERROR: {type(exc).__name__}: {exc}")
        sys.exit(1)
