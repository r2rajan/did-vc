"""
STEP 2: Issue Verifiable Credentials
======================================

The Orchestrator (acting as "TravelCorp Admin") issues credentials
to each agent, granting them specific capabilities.

Think of it as an IT admin granting service accounts their permissions:
  - Flight Agent gets: flight_search, flight_booking
  - Hotel Agent gets: hotel_search, hotel_booking

The credential is SIGNED with the Orchestrator's private key.
Anyone with the Orchestrator's public key can verify it's genuine.

Usage:
    python scripts/step2_issue_credentials.py

Prerequisites:
    Run step1_generate_identities.py first
"""

import json
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from lib.keys import load_private_key, load_public_key
from lib.credentials import issue_credential, save_credential

IDENTITIES_DIR = project_root / "identities"
CREDENTIALS_DIR = project_root / "credentials"


def main():
    # Check that identities exist
    if not (IDENTITIES_DIR / "orchestrator" / "private_key.json").exists():
        print("ERROR: Identities not found! Run step 1 first:")
        print("  python scripts/step1_generate_identities.py")
        sys.exit(1)

    print()
    print("=" * 60)
    print("STEP 2: ISSUE VERIFIABLE CREDENTIALS")
    print("=" * 60)
    print()
    print("The Orchestrator (as TravelCorp Admin) issues credentials")
    print("to each agent, granting them specific capabilities.")
    print()

    # Load the issuer's identity (Orchestrator)
    orchestrator_did, orchestrator_key = load_private_key("orchestrator", IDENTITIES_DIR)
    print(f"  Issuer: {orchestrator_did}")
    print()

    CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)

    # ─── Issue to Flight Agent ───
    print("  Issuing credential to Flight Agent...")
    flight_did, _ = load_private_key("flight", IDENTITIES_DIR)
    flight_cred = issue_credential(
        issuer_did=orchestrator_did,
        issuer_private_key=orchestrator_key,
        subject_did=flight_did,
        subject_name="Flight Agent",
        capabilities=["flight_search", "flight_booking"],
        constraints={"max_budget_usd": 5000, "regions": ["asia", "north_america"]},
        valid_days=30,
    )
    save_credential(flight_cred, CREDENTIALS_DIR / "flight_credential.json")

    print(f"    Subject:      {flight_did}")
    print(f"    Capabilities: ['flight_search', 'flight_booking']")
    print(f"    Constraints:  max_budget=$5000, regions=[asia, north_america]")
    print(f"    Valid for:    30 days")
    print(f"    Credential ID: {flight_cred['id']}")
    print()

    # ─── Issue to Hotel Agent ───
    print("  Issuing credential to Hotel Agent...")
    hotel_did, _ = load_private_key("hotel", IDENTITIES_DIR)
    hotel_cred = issue_credential(
        issuer_did=orchestrator_did,
        issuer_private_key=orchestrator_key,
        subject_did=hotel_did,
        subject_name="Hotel Agent",
        capabilities=["hotel_search", "hotel_booking"],
        constraints={"max_budget_usd": 2000, "regions": ["asia"]},
        valid_days=30,
    )
    save_credential(hotel_cred, CREDENTIALS_DIR / "hotel_credential.json")

    print(f"    Subject:      {hotel_did}")
    print(f"    Capabilities: ['hotel_search', 'hotel_booking']")
    print(f"    Constraints:  max_budget=$2000, regions=[asia]")
    print(f"    Valid for:    30 days")
    print(f"    Credential ID: {hotel_cred['id']}")
    print()

    # ─── Show credential structure ───
    print("  Example credential (Flight Agent):")
    print("  " + "-" * 50)
    for line in json.dumps(flight_cred, indent=2).split("\n")[:25]:
        print(f"    {line}")
    print("    ...")
    print("  " + "-" * 50)
    print()

    print("=" * 60)
    print("CREDENTIALS ISSUED")
    print("=" * 60)
    print()
    print("  What just happened:")
    print("    1. Orchestrator created a statement about each agent's permissions")
    print("    2. Orchestrator SIGNED each statement with its private key")
    print("    3. The signed credentials were saved to credentials/ folder")
    print()
    print("  The signature means:")
    print("    Anyone with the Orchestrator's public key can verify")
    print("    that these credentials are genuine (not forged).")
    print()
    print("  Next: python scripts/step3_start_flight_agent.py")
    print("  (Run this in a separate terminal — it starts a server)")
    print()


if __name__ == "__main__":
    main()
