"""
STEP 1: Generate Agent Identities
===================================

Creates an Ed25519 key pair and DID Document for each agent.

What this produces for each agent:
  - private_key.json  → Secret! Used to sign challenges and credentials
  - public_key.json   → Shareable. Used by others to verify our signatures
  - did_document.json → Public identity card with key + service endpoints

The DID Document is what other agents fetch when they want to verify us.
It contains our public key and tells them where to reach us.

Usage:
    python scripts/step1_generate_identities.py
"""

import sys
from pathlib import Path

# Add project root to path so we can import lib/
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from lib.keys import generate_identity

IDENTITIES_DIR = project_root / "identities"

# Each agent gets a name and a port number
AGENTS = [
    ("orchestrator", 5000),
    ("flight", 5001),
    ("hotel", 5002),
]


def main():
    print()
    print("=" * 60)
    print("STEP 1: GENERATE AGENT IDENTITIES")
    print("=" * 60)
    print()
    print("Each agent gets an Ed25519 key pair and a DID Document.")
    print("The private key is secret; the DID Document is public.")
    print()

    for agent_name, port in AGENTS:
        result = generate_identity(agent_name, port, IDENTITIES_DIR)
        print(f"  {agent_name}:")
        print(f"    DID:        {result['did']}")
        print(f"    Public key: {result['public_key'].hex()[:32]}...")
        print(f"    Saved to:   identities/{agent_name}/")
        print()

    print("=" * 60)
    print("IDENTITIES GENERATED")
    print("=" * 60)
    print()
    print("  What was created:")
    print("    identities/orchestrator/  → key pair + DID Document")
    print("    identities/flight/        → key pair + DID Document")
    print("    identities/hotel/         → key pair + DID Document")
    print()
    print("  The DID Document contains:")
    print("    - The agent's public key (for signature verification)")
    print("    - Service endpoints (where to authenticate, get credentials, send tasks)")
    print()
    print("  Next: python scripts/step2_issue_credentials.py")
    print()


if __name__ == "__main__":
    main()
