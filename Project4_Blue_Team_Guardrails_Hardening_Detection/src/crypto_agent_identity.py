from pathlib import Path
from datetime import datetime, timezone
import base64
import copy
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from cryptography.hazmat.primitives import serialization


PROJECT_DIR = Path(__file__).resolve().parents[1]
KEY_DIR = PROJECT_DIR / "keys"
LOG_DIR = PROJECT_DIR / "logs"

PRIVATE_KEY_FILE = KEY_DIR / "agent_ed25519_private.pem"
PUBLIC_KEY_FILE = KEY_DIR / "agent_ed25519_public.pem"


def generate_or_load_keys():
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    private_exists = PRIVATE_KEY_FILE.exists()
    public_exists = PUBLIC_KEY_FILE.exists()

    if private_exists != public_exists:
        raise RuntimeError(
            "Only one key file exists. Restore the matching key pair "
            "or remove both files and regenerate the pair."
        )

    if not private_exists:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        PRIVATE_KEY_FILE.write_bytes(private_bytes)
        PUBLIC_KEY_FILE.write_bytes(public_bytes)

        print("[KEY GENERATION] Ed25519 key pair generated.")

    else:
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_FILE.read_bytes(),
            password=None
        )

        public_key = serialization.load_pem_public_key(
            PUBLIC_KEY_FILE.read_bytes()
        )

        derived_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        stored_public = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        if derived_public != stored_public:
            raise RuntimeError(
                "Private and public key files do not form a matching pair."
            )

        print("[KEY LOADING] Existing Ed25519 key pair verified.")

    print(f"Private key file: {PRIVATE_KEY_FILE}")
    print(f"Public key file:  {PUBLIC_KEY_FILE}")
    print(f"Private key exists: {PRIVATE_KEY_FILE.exists()}")
    print(f"Public key exists:  {PUBLIC_KEY_FILE.exists()}")

    return private_key, public_key


def canonical_message(message):
    """Return deterministic bytes for signing and verification."""
    unsigned_fields = {
        key: value
        for key, value in message.items()
        if key != "signature"
    }

    return json.dumps(
        unsigned_fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def sign_outgoing_message(message, private_key):
    """Agent A signs every outgoing message before transmission."""
    signature = private_key.sign(canonical_message(message))

    signed_message = copy.deepcopy(message)
    signed_message["signature"] = base64.b64encode(
        signature
    ).decode("ascii")

    return signed_message


def verify_incoming_message(signed_message, public_key):
    """Agent B verifies the signature before processing the message."""
    signature_text = signed_message.get("signature")

    if not signature_text:
        return False, "SIGNATURE_MISSING: message has no signature."

    try:
        signature = base64.b64decode(
            signature_text,
            validate=True
        )

        public_key.verify(
            signature,
            canonical_message(signed_message)
        )

        return True, "SIGNATURE_VERIFIED: sender authenticity confirmed."

    except InvalidSignature:
        return False, (
            "SIGNATURE_VERIFICATION_FAILED: message content or signature "
            "has been altered. Incoming message rejected."
        )

    except (ValueError, TypeError):
        return False, (
            "SIGNATURE_FORMAT_ERROR: invalid signature encoding."
        )


def process_incoming_message(message, public_key):
    """Reject messages before processing unless signature is valid."""
    valid, reason = verify_incoming_message(message, public_key)

    print(f"Verification: {reason}")

    if not valid:
        print("RECEIVER STATUS: REJECTED")
        return {
            "status": "REJECTED",
            "reason": reason
        }

    print("RECEIVER STATUS: ACCEPTED")
    print("Processed action:", message.get("action"))
    print("Processed payload:", message.get("payload"))

    return {
        "status": "ACCEPTED",
        "reason": reason,
        "action": message.get("action")
    }


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 72)
    print("SECURENOVA - PROJECT 4 BLUE TEAM")
    print("TASK 2: CRYPTOGRAPHIC AGENT IDENTITY BINDING")
    print("=" * 72)

    # Stage 1: Generate or load the Ed25519 key pair.
    print("\n[1] ED25519 KEY PAIR GENERATION")

    private_key, public_key = generate_or_load_keys()

    # Stage 2: Create and sign an outgoing Agent A message.
    print("\n[2] AGENT A - SIGN OUTGOING MESSAGE")

    original_message = {
        "message_id": "SECURENOVA-MSG-001",
        "sender": "Agent-A",
        "recipient": "Agent-B",
        "action": "UPDATE_AGENT_STATUS",
        "payload": {
            "status": "operational",
            "task": "identity-security-validation"
        },
        "timestamp_utc": datetime.now(timezone.utc).isoformat()
    }

    signed_message = sign_outgoing_message(
        original_message,
        private_key
    )

    print("Outgoing message signed successfully.")
    print("Message ID:", signed_message["message_id"])
    print("Sender:", signed_message["sender"])
    print("Signature algorithm: Ed25519")
    print("Signature attached: YES")

    # Stage 3: Agent B verifies the original message.
    print("\n[3] AGENT B - VERIFY ORIGINAL MESSAGE")

    legitimate_result = process_incoming_message(
        signed_message,
        public_key
    )

    # Stage 4: Change exactly one character after signing.
    print("\n[4] TAMPER DETECTION TEST")

    tampered_message = copy.deepcopy(signed_message)

    original_value = tampered_message["payload"]["status"]
    tampered_value = original_value.replace("n", "m", 1)

    tampered_message["payload"]["status"] = tampered_value

    print("Original status:", original_value)
    print("Tampered status:", tampered_value)
    print("Tampering: exactly one character changed.")

    # Stage 5: Agent B rejects the tampered message.
    print("\n[5] AGENT B - VERIFY TAMPERED MESSAGE")

    tampered_result = process_incoming_message(
        tampered_message,
        public_key
    )

    # Stage 6: Store an audit record without exposing private key data.
    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    audit = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "Ed25519",
        "sender": "Agent-A",
        "receiver": "Agent-B",
        "legitimate_message": {
            "message": signed_message,
            "result": legitimate_result
        },
        "tampered_message": {
            "message": tampered_message,
            "result": tampered_result
        },
        "private_key_material_logged": False
    }

    log_file = LOG_DIR / f"{timestamp}_ed25519_identity_audit.json"

    log_file.write_text(
        json.dumps(audit, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("\n" + "=" * 72)
    print("TASK 2 FINAL SUMMARY")
    print("=" * 72)
    print("Ed25519 key pair:", "GENERATED / VERIFIED")
    print("Legitimate message:", legitimate_result["status"])
    print("Tampered message:", tampered_result["status"])
    print("Private key material logged: NO")
    print("Audit log:", log_file)

    if (
        legitimate_result["status"] == "ACCEPTED"
        and tampered_result["status"] == "REJECTED"
    ):
        print("RESULT: CRYPTOGRAPHIC IDENTITY BINDING PASSED")
    else:
        print("RESULT: VERIFICATION NEEDS REVIEW")
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"\nCRYPTOGRAPHIC TEST ERROR: {type(exc).__name__}: {exc}")
        sys.exit(1)
