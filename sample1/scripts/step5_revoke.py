"""
STEP 5: Revoke a Credential and See Rejection
===============================================

This demonstrates the power of revocation:
    1. Verify the credential BEFORE revocation (passes)
    2. Revoke the credential (add ID to revocation list)
    3. Verify the SAME credential AFTER revocation (fails!)

Why revocation matters:
    - Agent compromised → revoke immediately, no waiting for expiry
    - Agent contract ends → revoke, access stops instantly
    - Agent misbehaves → revoke, other agents reject it
    - No key rotation needed across services

The revocation happens on the VERIFIER side. The agent doesn't
know it's been revoked — it still holds its credential. But every
time the verifier checks it, the revocation list catches it.

Usage:
    (Make sure step3 server is running in another terminal)
    python scripts/step5_revoke.py

Prerequisites:
    Run step1, step2, step3, and step4 first.
"""

import json
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import httpx

from lib.keys import load_public_key
from lib.credentials import verify_credential

IDENTITIES_DIR = project_root / "identities"
FLIGHT_AGENT_URL = "http://localhost:5001"


def main():
    # Load Orchestrator's public key (it's the issuer — we verify against its key)
    _, orchestrator_public_key = load_public_key("orchestrator", IDENTITIES_DIR)

    print()
    print("=" * 60)
    print("STEP 5: REVOCATION — Withdrawing Trust Instantly")
    print("=" * 60)
    print()

    # Fetch the Flight Agent's credential
    print("  Fetching Flight Agent's credential...")
    response = httpx.get(f"{FLIGHT_AGENT_URL}/flight/credentials")
    credential = response.json()["credentials"][0]
    cred_id = credential["id"]
    print(f"  Credential ID: {cred_id}")
    print()

    # ──────────────────────────────────────────────────────────
    # BEFORE revocation — credential is valid
    # ──────────────────────────────────────────────────────────
    print("  --- BEFORE REVOCATION ---")
    print()

    result = verify_credential(
        credential=credential,
        issuer_public_key=orchestrator_public_key,
        required_capability="flight_search",
        revoked_ids=[],  # Empty revocation list
    )

    for check in result["checks"]:
        icon = "PASS" if check["passed"] else "FAIL"
        print(f"    [{icon}] {check['name']}: {check['detail']}")

    print()
    print(f"    Overall: {'AUTHORIZED' if result['valid'] else 'REJECTED'}")
    print()

    # ──────────────────────────────────────────────────────────
    # REVOKE the credential
    # ──────────────────────────────────────────────────────────
    print("  --- REVOKING CREDENTIAL ---")
    print()
    print(f"    Adding credential ID to revocation list...")
    print(f"    Reason: Agent exceeded budget limits")
    print()

    # In production, this would be a DynamoDB put_item.
    # Here, we just add the ID to a list.
    revoked_ids = [cred_id]

    print(f"    Revocation list: {revoked_ids}")
    print()

    # ──────────────────────────────────────────────────────────
    # AFTER revocation — same credential, now rejected
    # ──────────────────────────────────────────────────────────
    print("  --- AFTER REVOCATION ---")
    print()

    result = verify_credential(
        credential=credential,
        issuer_public_key=orchestrator_public_key,
        required_capability="flight_search",
        revoked_ids=revoked_ids,  # Now contains the credential ID
    )

    for check in result["checks"]:
        icon = "PASS" if check["passed"] else "FAIL"
        print(f"    [{icon}] {check['name']}: {check['detail']}")

    print()
    print(f"    Overall: {'AUTHORIZED' if result['valid'] else 'REJECTED'}")
    print()

    # ──────────────────────────────────────────────────────────
    # Summary
    # ──────────────────────────────────────────────────────────
    print("=" * 60)
    print("REVOCATION DEMO COMPLETE")
    print("=" * 60)
    print()
    print("  What happened:")
    print("    1. Same credential, same signature (still cryptographically valid!)")
    print("    2. Same expiry date (hasn't expired!)")
    print("    3. But the REVOCATION CHECK caught it")
    print("    4. Agent is immediately cut off — it doesn't even know")
    print()
    print("  Why this matters in production:")
    print("    - Agent compromised → one DynamoDB write → instant cutoff")
    print("    - No key rotation needed")
    print("    - No service restarts needed")
    print("    - No coordination between services needed")
    print()
    print("  The four layers of VC protection:")
    print("    1. Signature  → prevents forgery")
    print("    2. Expiry     → time-limited permissions")
    print("    3. Revocation → instant permission withdrawal")
    print("    4. Capability → principle of least privilege")
    print()
    print("=" * 60)
    print("PART 1 COMPLETE!")
    print("=" * 60)
    print()
    print("  You've seen the full trust pipeline:")
    print("    Discovery → Resolution → Authentication → Authorization → Delegation")
    print()
    print("  Part 2 deploys this to AWS with:")
    print("    - Lambda functions (instead of Flask)")
    print("    - API Gateway (HTTPS endpoints)")
    print("    - Amazon Bedrock (real LLM-powered agents)")
    print("    - DynamoDB (credential storage + revocation)")
    print("    - Secrets Manager (private key storage)")
    print()


if __name__ == "__main__":
    main()
