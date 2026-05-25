"""
Flask server implementing the A2A protocol with DID trust endpoints.

Each agent runs one of these servers. It exposes five endpoints:

    GET  /.well-known/agent.json       → Agent Card (A2A discovery)
    GET  /<agent>/did.json             → DID Document (identity resolution)
    POST /<agent>/auth/challenge       → Sign nonce (authentication)
    GET  /<agent>/credentials          → Present VC (authorization)
    POST /a2a                          → Handle task (delegation)

The flow for a verifier (the Orchestrator):
    1. Fetch Agent Card → learn the agent's DID
    2. Resolve DID → get public key + service endpoints
    3. POST challenge → verify agent controls the DID
    4. GET credentials → verify agent has permission
    5. POST task → delegate work (only if steps 1-4 passed)

We use Flask for simplicity. In production (Part 2), this becomes
a Lambda function behind API Gateway.
"""

import json
from base64 import urlsafe_b64encode, urlsafe_b64decode

from flask import Flask, jsonify, request
from nacl.signing import SigningKey


def create_agent_server(
    agent_name: str,
    agent_did: str,
    private_key: bytes,
    did_document: dict,
    credential: dict,
    agent_card: dict,
    task_handler=None,
) -> Flask:
    """
    Create a Flask app with all A2A + DID trust endpoints.

    Args:
        agent_name: Name of this agent (e.g., "flight")
        agent_did: This agent's DID (e.g., "did:web:localhost:flight")
        private_key: 32-byte Ed25519 private key (for signing challenges)
        did_document: The DID Document to serve (public identity)
        credential: The Verifiable Credential to present (authorization)
        agent_card: The A2A Agent Card to serve (discovery)
        task_handler: Function(message: str) -> dict that processes tasks

    Returns:
        A Flask app ready to run
    """
    app = Flask(agent_name)

    # ─────────────────────────────────────────────────────────
    # Endpoint 1: Agent Card — A2A Discovery
    # Other agents fetch this to learn our capabilities and DID.
    # ─────────────────────────────────────────────────────────
    @app.route("/.well-known/agent.json")
    def serve_agent_card():
        """Serve the Agent Card for A2A discovery."""
        return jsonify(agent_card)

    # ─────────────────────────────────────────────────────────
    # Endpoint 2: DID Document — Identity Resolution
    # When someone resolves our DID, they fetch this to get
    # our public key and service endpoints.
    # did:web:localhost:flight → GET /flight/did.json
    # ─────────────────────────────────────────────────────────
    @app.route(f"/{agent_name}/did.json")
    def serve_did_document():
        """Serve the DID Document for identity resolution."""
        print(f"  [{agent_name}] DID Document requested (resolution)")
        return jsonify(did_document)

    # ─────────────────────────────────────────────────────────
    # Endpoint 3: Authentication — Challenge-Response
    # A verifier sends a random nonce. We sign it with our
    # private key. They verify against our DID Document's public key.
    # If it matches → we proved we control this DID.
    # ─────────────────────────────────────────────────────────
    @app.route(f"/{agent_name}/auth/challenge", methods=["POST"])
    def handle_auth_challenge():
        """Sign a challenge nonce to prove we control our DID."""
        data = request.get_json()
        nonce_b64 = data["nonce"]

        # Decode the nonce (base64url → bytes)
        padding = 4 - len(nonce_b64) % 4
        if padding != 4:
            nonce_b64 += "=" * padding
        nonce = urlsafe_b64decode(nonce_b64)

        # Sign it with our private key
        signing_key = SigningKey(private_key)
        signed = signing_key.sign(nonce)

        print(f"  [{agent_name}] Signed auth challenge from {data.get('challenger_did')}")

        return jsonify({
            "signature": urlsafe_b64encode(signed.signature).rstrip(b"=").decode(),
            "responder_did": agent_did,
        })

    # ─────────────────────────────────────────────────────────
    # Endpoint 4: Credential Presentation — Authorization
    # When the Orchestrator asks "show me your credentials",
    # we present our VC. They verify it (signature, expiry,
    # revocation, capability) before delegating any task.
    # ─────────────────────────────────────────────────────────
    @app.route(f"/{agent_name}/credentials")
    def serve_credentials():
        """Present our Verifiable Credential for authorization."""
        print(f"  [{agent_name}] Credential requested (authorization check)")
        if credential:
            return jsonify({"credentials": [credential]})
        return jsonify({"credentials": [], "error": "No credential available"}), 404

    # ─────────────────────────────────────────────────────────
    # Endpoint 5: A2A Task Handling — Delegation
    # The main endpoint. After trust is established, the
    # Orchestrator sends tasks here as JSON-RPC 2.0 messages.
    # ─────────────────────────────────────────────────────────
    @app.route("/a2a", methods=["POST"])
    def handle_task():
        """Handle an A2A task (JSON-RPC 2.0)."""
        data = request.get_json()
        message = data.get("params", {}).get("message", {}).get("content", "")
        print(f"  [{agent_name}] Task received: {message[:60]}...")

        if task_handler:
            result_data = task_handler(message)
        else:
            result_data = {"response": f"Echo from {agent_name}: task received!"}

        return jsonify({
            "jsonrpc": "2.0",
            "id": data.get("id", "1"),
            "result": {
                "task": {
                    "status": "completed",
                    "artifacts": [{"name": f"{agent_name}_results", "data": result_data}],
                }
            },
        })

    return app
