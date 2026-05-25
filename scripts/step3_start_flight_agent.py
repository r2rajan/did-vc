"""
STEP 3: Start the Flight Agent Server
========================================

Starts a Flask server for the Flight Agent with all five endpoints:

    GET  http://localhost:5001/.well-known/agent.json   → Agent Card
    GET  http://localhost:5001/flight/did.json          → DID Document
    POST http://localhost:5001/flight/auth/challenge    → DID Authentication
    GET  http://localhost:5001/flight/credentials       → VC Presentation
    POST http://localhost:5001/a2a                      → Task Handling

Run this in a SEPARATE TERMINAL and leave it running.
Then run step4 in another terminal to test the trust chain.

Usage:
    python scripts/step3_start_flight_agent.py

Prerequisites:
    Run step1 and step2 first.
"""

import json
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from lib.keys import load_private_key, load_did_document
from lib.credentials import load_credential
from lib.agent_server import create_agent_server

IDENTITIES_DIR = project_root / "identities"
CREDENTIALS_DIR = project_root / "credentials"
PORT = 5001


def flight_search_handler(query: str) -> dict:
    """
    What the Flight Agent does when it receives a task.

    In a real system, this would call a flight search API.
    For the demo, we return realistic mock data.
    """
    return {
        "flights": [
            {"airline": "ANA", "route": "SFO → NRT", "price": "$850", "duration": "11h 15m"},
            {"airline": "JAL", "route": "SFO → HND", "price": "$920", "duration": "11h 30m"},
            {"airline": "United", "route": "SFO → NRT", "price": "$780", "duration": "11h 45m"},
        ],
        "query": query,
        "note": "Results from Flight Agent (mock data for demo)",
    }


def main():
    # Check prerequisites
    if not (IDENTITIES_DIR / "flight" / "private_key.json").exists():
        print("ERROR: Flight agent identity not found! Run step 1 first.")
        sys.exit(1)
    if not (CREDENTIALS_DIR / "flight_credential.json").exists():
        print("ERROR: Flight agent credential not found! Run step 2 first.")
        sys.exit(1)

    # Load identity and credential
    flight_did, flight_key = load_private_key("flight", IDENTITIES_DIR)
    did_document = load_did_document("flight", IDENTITIES_DIR)
    credential = load_credential(CREDENTIALS_DIR / "flight_credential.json")

    # Agent Card (what other agents see during A2A discovery)
    agent_card = {
        "name": "Flight Agent",
        "description": "Searches and recommends flights for travel planning",
        "url": f"http://localhost:{PORT}/a2a",
        "version": "1.0.0",
        "skills": [
            {
                "id": "flight_search",
                "name": "Flight Search",
                "description": "Search for flights based on destination, dates, and preferences",
            }
        ],
        "did": flight_did,  # ← This links A2A to DID-based trust
    }

    # Create the Flask server
    app = create_agent_server(
        agent_name="flight",
        agent_did=flight_did,
        private_key=flight_key,
        did_document=did_document,
        credential=credential,
        agent_card=agent_card,
        task_handler=flight_search_handler,
    )

    print()
    print("=" * 60)
    print("FLIGHT AGENT SERVER")
    print("=" * 60)
    print()
    print(f"  DID:  {flight_did}")
    print(f"  Port: {PORT}")
    print()
    print("  Endpoints:")
    print(f"    GET  http://localhost:{PORT}/.well-known/agent.json   (Discovery)")
    print(f"    GET  http://localhost:{PORT}/flight/did.json          (Resolution)")
    print(f"    POST http://localhost:{PORT}/flight/auth/challenge    (Authentication)")
    print(f"    GET  http://localhost:{PORT}/flight/credentials       (Authorization)")
    print(f"    POST http://localhost:{PORT}/a2a                      (Task Handling)")
    print()
    print("  Credential:")
    print(f"    ID:           {credential['id']}")
    print(f"    Capabilities: {credential['credential_subject']['capabilities']}")
    print()
    print("  Server starting... (press Ctrl+C to stop)")
    print()

    app.run(port=PORT, debug=True, use_reloader=False)


if __name__ == "__main__":
    main()
