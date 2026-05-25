"""
STEP 4: Run the Full Trust Chain
==================================

This is the heart of the system — what the Orchestrator does before
trusting any agent. It performs five steps:

    1. DISCOVER  — Fetch Agent Card, learn the agent's DID
    2. RESOLVE   — Fetch DID Document, extract public key + endpoints
    3. AUTHENTICATE — Challenge-response (prove the agent controls its DID)
    4. AUTHORIZE — Verify the agent's credential (4 sub-checks)
    5. DELEGATE  — Send the task (only if steps 1-4 all passed)

If ANY step fails, the agent is REJECTED and never receives the task.

Usage:
    (Make sure step3 server is running in another terminal)
    python scripts/step4_trust_chain.py

Prerequisites:
    Run step1, step2, and step3 (leave step3 running).
"""

import json
import os
import sys
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import httpx
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from lib.keys import load_private_key, load_public_key, extract_public_key_from_did_doc
from lib.credentials import verify_credential

IDENTITIES_DIR = project_root / "identities"
FLIGHT_AGENT_URL = "http://localhost:5001"


def main():
    # Load Orchestrator identity
    orchestrator_did, _ = load_private_key("orchestrator", IDENTITIES_DIR)
    _, orchestrator_public_key = load_public_key("orchestrator", IDENTITIES_DIR)

    print()
    print("=" * 60)
    print("FULL TRUST CHAIN: Orchestrator → Flight Agent")
    print("=" * 60)
    print()
    print(f"  Verifier: {orchestrator_did}")
    print(f"  Target:   {FLIGHT_AGENT_URL}")
    print()

    # ──────────────────────────────────────────────────────────
    # STEP 1: DISCOVERY — Fetch Agent Card
    # ──────────────────────────────────────────────────────────
    print("[1/5] DISCOVERY — Fetch Agent Card")
    print(f"      GET {FLIGHT_AGENT_URL}/.well-known/agent.json")

    response = httpx.get(f"{FLIGHT_AGENT_URL}/.well-known/agent.json")
    agent_card = response.json()

    print(f"      Found: {agent_card['name']}")
    print(f"      DID:   {agent_card['did']}")
    print(f"      Skills: {[s['name'] for s in agent_card.get('skills', [])]}")
    print(f"      RESULT: PASSED")
    print()

    agent_did = agent_card["did"]

    # ──────────────────────────────────────────────────────────
    # STEP 2: DID RESOLUTION — Fetch DID Document
    # ──────────────────────────────────────────────────────────
    print("[2/5] DID RESOLUTION — Fetch DID Document")

    # Convert DID to URL (did:web spec)
    # did:web:localhost:flight → /flight/did.json
    agent_path = agent_did.split(":")[-1]
    did_url = f"{FLIGHT_AGENT_URL}/{agent_path}/did.json"
    print(f"      GET {did_url}")

    response = httpx.get(did_url)
    did_document = response.json()

    # Extract public key from DID Document
    public_key = extract_public_key_from_did_doc(did_document)

    # Extract service endpoints
    services = {s["type"]: s["serviceEndpoint"] for s in did_document.get("service", [])}

    print(f"      Public key: {public_key.hex()[:32]}...")
    print(f"      Auth endpoint: {services.get('DIDAuthentication')}")
    print(f"      Cred endpoint: {services.get('CredentialPresentation')}")
    print(f"      A2A endpoint:  {services.get('A2AAgent')}")
    print(f"      RESULT: PASSED")
    print()

    # ──────────────────────────────────────────────────────────
    # STEP 3: AUTHENTICATION — Challenge-Response
    # ──────────────────────────────────────────────────────────
    print("[3/5] AUTHENTICATION — Challenge-Response")

    # Generate a random 32-byte nonce (unpredictable, prevents replay)
    nonce = os.urandom(32)
    nonce_b64 = urlsafe_b64encode(nonce).rstrip(b"=").decode()

    print(f"      Nonce sent: {nonce_b64[:24]}...")

    # Send the challenge to the agent
    challenge = {
        "nonce": nonce_b64,
        "challenger_did": orchestrator_did,
        "timestamp": time.time(),
    }
    response = httpx.post(services["DIDAuthentication"], json=challenge)
    auth_response = response.json()

    print(f"      Signature received: {auth_response['signature'][:24]}...")
    print(f"      Responder DID: {auth_response['responder_did']}")

    # Decode the signature
    sig_b64 = auth_response["signature"]
    padding = 4 - len(sig_b64) % 4
    if padding != 4:
        sig_b64 += "=" * padding
    signature = urlsafe_b64decode(sig_b64)

    # VERIFY: does this signature match the public key from the DID Document?
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(nonce, signature)
        print(f"      Verification: Signature VALID")
        print(f"      Meaning: Agent proved it controls {agent_did}")
        print(f"      RESULT: PASSED")
        authenticated = True
    except BadSignatureError:
        print(f"      Verification: Signature INVALID")
        print(f"      Meaning: Agent does NOT control this DID!")
        print(f"      RESULT: FAILED")
        authenticated = False

    print()

    if not authenticated:
        print("      STOPPING — Agent failed authentication. No task will be sent.")
        sys.exit(1)

    # ──────────────────────────────────────────────────────────
    # STEP 4: AUTHORIZATION — Verify Credential
    # ──────────────────────────────────────────────────────────
    print("[4/5] AUTHORIZATION — Verify Credential")
    print(f"      GET {services['CredentialPresentation']}")

    response = httpx.get(services["CredentialPresentation"])
    cred_response = response.json()
    credentials = cred_response.get("credentials", [])

    if not credentials:
        print("      No credentials presented!")
        print("      RESULT: FAILED — Agent has no authorization")
        sys.exit(1)

    credential = credentials[0]
    print(f"      Credential ID: {credential['id']}")
    print(f"      Subject: {credential['credential_subject']['name']}")
    print(f"      Capabilities: {credential['credential_subject']['capabilities']}")
    print()

    # Run the four verification checks
    required_capability = "flight_search"
    result = verify_credential(
        credential=credential,
        issuer_public_key=orchestrator_public_key,
        required_capability=required_capability,
    )

    print("      Verification checks:")
    for check in result["checks"]:
        icon = "PASS" if check["passed"] else "FAIL"
        print(f"        [{icon}] {check['name']}: {check['detail']}")

    if not result["valid"]:
        print()
        print("      RESULT: FAILED — Authorization denied")
        print("      STOPPING — Agent will not receive the task.")
        sys.exit(1)

    print()
    print(f"      RESULT: PASSED — Agent is authorized for '{required_capability}'")
    print()

    # ──────────────────────────────────────────────────────────
    # STEP 5: DELEGATION — Send Task
    # ──────────────────────────────────────────────────────────
    print("[5/5] DELEGATION — Send Task")

    task_message = "Find flights from San Francisco to Tokyo, 3 days in June"
    print(f"      Task: '{task_message}'")
    print(f"      POST {services['A2AAgent']}")

    response = httpx.post(services["A2AAgent"], json={
        "jsonrpc": "2.0",
        "id": "task-001",
        "method": "tasks/send",
        "params": {"message": {"role": "user", "content": task_message}},
    })

    task_result = response.json()["result"]["task"]
    print(f"      Status: {task_result['status']}")
    print()
    print("      Results:")
    artifacts = task_result.get("artifacts", [])
    if artifacts:
        data = artifacts[0].get("data", {})
        for flight in data.get("flights", []):
            print(f"        - {flight['airline']}: {flight['route']} "
                  f"({flight['price']}, {flight['duration']})")
    print()
    print(f"      RESULT: COMPLETED")
    print()

    # ──────────────────────────────────────────────────────────
    # SUMMARY
    # ──────────────────────────────────────────────────────────
    print("=" * 60)
    print("TRUST CHAIN COMPLETE")
    print("=" * 60)
    print()
    print("  All 5 steps passed:")
    print("    1. Discovery      — Agent Card found, DID extracted")
    print("    2. Resolution     — DID Document fetched, public key + endpoints found")
    print("    3. Authentication — Agent proved it controls its DID (signed our nonce)")
    print("    4. Authorization  — Credential verified (signature, expiry, revocation, capability)")
    print("    5. Delegation     — Task sent and completed successfully")
    print()
    print("  The task was ONLY sent because all checks passed.")
    print("  If any step had failed, the agent would never have seen the task.")
    print()
    print("  Next: python scripts/step5_revoke.py")
    print("  (See what happens when trust is withdrawn)")
    print()


if __name__ == "__main__":
    main()
