"""
Verifiable Credential issuance and verification.

A Verifiable Credential (VC) is a cryptographically signed statement:
    "Issuer X certifies that Subject Y has Capability Z"

In our system:
    "The Orchestrator certifies that Flight Agent can search flights"

The VC lifecycle:
    1. ISSUE — Create a credential and sign it with the issuer's private key
    2. VERIFY — Check signature, expiry, revocation, and capability
    3. REVOKE — Add a credential ID to the revocation list (instant cutoff)

Why VCs matter for agents:
    - UNFORGEABLE: Only the issuer's private key can produce a valid signature
    - TIME-LIMITED: Credentials expire, forcing regular renewal
    - REVOCABLE: Instant permission withdrawal without key rotation
    - SPECIFIC: Each credential grants only named capabilities (least privilege)
"""

import json
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


# ===================================================================
# ISSUANCE — Creating and signing a credential
# ===================================================================

def issue_credential(
    issuer_did: str,
    issuer_private_key: bytes,
    subject_did: str,
    subject_name: str,
    capabilities: list,
    constraints: dict = None,
    valid_days: int = 30,
) -> dict:
    """
    Issue a Verifiable Credential to an agent.

    This is what a "TravelCorp Admin" does:
    "I hereby grant FlightAgent the capability to search and book flights."

    The credential is signed with the issuer's private key, so anyone
    can verify it came from the issuer by checking against the issuer's
    public key (from their DID Document).

    Args:
        issuer_did: DID of the entity issuing the credential
        issuer_private_key: Issuer's Ed25519 private key (32 bytes)
        subject_did: DID of the agent receiving the credential
        subject_name: Human-readable name of the agent
        capabilities: List of capabilities granted (e.g., ["flight_search"])
        constraints: Optional limits (e.g., {"max_budget_usd": 5000})
        valid_days: How many days until the credential expires

    Returns:
        A signed credential (dict)
    """
    # Build the credential content (unsigned)
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": f"urn:uuid:{uuid4()}",
        "type": ["VerifiableCredential", "AgentCapabilityCredential"],
        "issuer": issuer_did,
        "issuance_date": datetime.utcnow().isoformat(),
        "expiration_date": (datetime.utcnow() + timedelta(days=valid_days)).isoformat(),
        "credential_subject": {
            "id": subject_did,
            "name": subject_name,
            "capabilities": capabilities,
            "constraints": constraints or {},
        },
    }

    # SIGN IT — this is what makes it "verifiable"
    # We sign the canonical JSON (sorted keys = deterministic byte representation)
    content_bytes = json.dumps(credential, sort_keys=True).encode("utf-8")
    signing_key = SigningKey(issuer_private_key)
    signed = signing_key.sign(content_bytes)

    # Attach the proof (signature + metadata about how it was created)
    credential["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.utcnow().isoformat(),
        "verification_method": f"{issuer_did}#key-1",
        "proof_purpose": "assertionMethod",
        "signature": urlsafe_b64encode(signed.signature).rstrip(b"=").decode(),
    }

    return credential


# ===================================================================
# VERIFICATION — Checking a credential is valid (four checks)
# ===================================================================

def verify_credential(
    credential: dict,
    issuer_public_key: bytes,
    required_capability: str = None,
    revoked_ids: list = None,
) -> dict:
    """
    Verify a Verifiable Credential with four checks.

    ALL checks must pass for authorization:
        1. SIGNATURE — Was it really signed by the claimed issuer?
        2. EXPIRY — Is it still within its validity period?
        3. REVOCATION — Has the issuer revoked it?
        4. CAPABILITY — Does it grant the specific capability we need?

    Args:
        credential: The credential dict to verify
        issuer_public_key: Public key of the claimed issuer (from their DID Doc)
        required_capability: The capability the verifier needs
        revoked_ids: List of revoked credential IDs

    Returns:
        dict with 'valid' (bool) and 'checks' (list of results)
    """
    checks = []

    # ─── CHECK 1: SIGNATURE ───
    # Recreate what was signed and verify against the issuer's public key.
    # This proves the credential was actually created by the claimed issuer.
    content = {k: v for k, v in credential.items() if k != "proof"}
    content_bytes = json.dumps(content, sort_keys=True).encode("utf-8")

    sig_encoded = credential["proof"]["signature"]
    padding = 4 - len(sig_encoded) % 4
    if padding != 4:
        sig_encoded += "=" * padding
    signature = urlsafe_b64decode(sig_encoded)

    try:
        verify_key = VerifyKey(issuer_public_key)
        verify_key.verify(content_bytes, signature)
        checks.append({"name": "Signature", "passed": True,
                       "detail": "Genuine — signed by the claimed issuer"})
    except BadSignatureError:
        checks.append({"name": "Signature", "passed": False,
                       "detail": "FORGED — not signed by the claimed issuer"})

    # ─── CHECK 2: EXPIRY ───
    # Credentials have a time limit. This forces periodic renewal
    # and limits the window if a credential is somehow leaked.
    expiry_str = credential.get("expiration_date")
    if expiry_str:
        expiry = datetime.fromisoformat(expiry_str)
        is_expired = datetime.utcnow() > expiry
        if is_expired:
            checks.append({"name": "Expiry", "passed": False,
                           "detail": f"EXPIRED on {expiry_str}"})
        else:
            checks.append({"name": "Expiry", "passed": True,
                           "detail": f"Valid until {expiry_str}"})

    # ─── CHECK 3: REVOCATION ───
    # The issuer maintains a list of revoked credential IDs.
    # This is the "kill switch" — instant permission withdrawal.
    cred_id = credential.get("id", "")
    is_revoked = cred_id in (revoked_ids or [])
    if is_revoked:
        checks.append({"name": "Revocation", "passed": False,
                       "detail": "REVOKED by issuer"})
    else:
        checks.append({"name": "Revocation", "passed": True,
                       "detail": "Not revoked"})

    # ─── CHECK 4: CAPABILITY ───
    # Principle of least privilege: the credential must explicitly
    # grant the specific capability needed for this task.
    if required_capability:
        capabilities = credential.get("credential_subject", {}).get("capabilities", [])
        has_it = required_capability in capabilities
        if has_it:
            checks.append({"name": "Capability", "passed": True,
                           "detail": f"Has '{required_capability}'"})
        else:
            checks.append({"name": "Capability", "passed": False,
                           "detail": f"MISSING '{required_capability}' (has: {capabilities})"})

    all_passed = all(c["passed"] for c in checks)
    return {"valid": all_passed, "checks": checks}


# ===================================================================
# HELPERS — Save/load credentials
# ===================================================================

def save_credential(credential: dict, path: Path) -> None:
    """Save a credential to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(credential, indent=2))


def load_credential(path: Path) -> dict:
    """Load a credential from a JSON file."""
    return json.loads(path.read_text())
