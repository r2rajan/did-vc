"""
Key generation and DID Document creation.

Each agent needs:
  - A private key (32 bytes, kept secret — used to sign things)
  - A public key (32 bytes, shared freely — used to verify signatures)
  - A DID Document (JSON, served over HTTP — the agent's public identity card)

We use Ed25519 (via PyNaCl/libsodium) — the standard signing algorithm
in the DID ecosystem. It's fast, secure, and produces compact keys.
"""

import json
from base64 import urlsafe_b64encode, urlsafe_b64decode
from pathlib import Path

from nacl.signing import SigningKey


def generate_identity(agent_name: str, port: int, output_dir: Path) -> dict:
    """
    Generate an Ed25519 key pair and DID Document for one agent.

    The DID (Decentralized Identifier) follows the did:web method:
      did:web:localhost:flight → resolves to http://localhost:5001/flight/did.json

    Args:
        agent_name: Name of the agent (e.g., "flight", "hotel", "orchestrator")
        port: Port number where the agent's Flask server will run
        output_dir: Directory to save key files and DID Document

    Returns:
        dict with 'did', 'private_key', 'public_key', 'did_document'
    """
    # Generate key pair — 32 bytes each
    signing_key = SigningKey.generate()
    private_key = bytes(signing_key)           # 32 bytes — KEEP SECRET
    public_key = bytes(signing_key.verify_key)  # 32 bytes — share freely

    # The DID (did:web method means "resolve this by fetching a URL")
    agent_did = f"did:web:localhost:{agent_name}"

    # Encode public key for the DID Document
    # "z" prefix = base64url encoding (a multibase convention in the DID spec)
    public_key_multibase = "z" + urlsafe_b64encode(public_key).rstrip(b"=").decode()

    # Build the DID Document — this is the agent's public identity card
    # It contains:
    #   - The public key (so others can verify our signatures)
    #   - Service endpoints (so others know where to reach us)
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": agent_did,
        "verificationMethod": [
            {
                "id": f"{agent_did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": agent_did,
                "publicKeyMultibase": public_key_multibase,
            }
        ],
        "authentication": [f"{agent_did}#key-1"],
        "assertionMethod": [f"{agent_did}#key-1"],
        "service": [
            {
                "id": f"{agent_did}#a2a",
                "type": "A2AAgent",
                "serviceEndpoint": f"http://localhost:{port}/a2a",
            },
            {
                "id": f"{agent_did}#auth",
                "type": "DIDAuthentication",
                "serviceEndpoint": f"http://localhost:{port}/{agent_name}/auth/challenge",
            },
            {
                "id": f"{agent_did}#credentials",
                "type": "CredentialPresentation",
                "serviceEndpoint": f"http://localhost:{port}/{agent_name}/credentials",
            },
        ],
    }

    # Save to disk
    agent_dir = output_dir / agent_name
    agent_dir.mkdir(parents=True, exist_ok=True)

    # Private key file (NEVER share this!)
    (agent_dir / "private_key.json").write_text(json.dumps({
        "did": agent_did,
        "private_key_base64url": urlsafe_b64encode(private_key).rstrip(b"=").decode(),
    }, indent=2))

    # Public key file (safe to share)
    (agent_dir / "public_key.json").write_text(json.dumps({
        "did": agent_did,
        "public_key_base64url": urlsafe_b64encode(public_key).rstrip(b"=").decode(),
    }, indent=2))

    # DID Document (served publicly over HTTP)
    (agent_dir / "did_document.json").write_text(json.dumps(did_document, indent=2))

    return {
        "did": agent_did,
        "private_key": private_key,
        "public_key": public_key,
        "did_document": did_document,
    }


def load_private_key(agent_name: str, identities_dir: Path) -> tuple:
    """
    Load an agent's private key from disk.

    Returns:
        (did, private_key_bytes)
    """
    data = json.loads((identities_dir / agent_name / "private_key.json").read_text())
    encoded = data["private_key_base64url"]
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    return data["did"], urlsafe_b64decode(encoded)


def load_public_key(agent_name: str, identities_dir: Path) -> tuple:
    """
    Load an agent's public key from disk.

    Returns:
        (did, public_key_bytes)
    """
    data = json.loads((identities_dir / agent_name / "public_key.json").read_text())
    encoded = data["public_key_base64url"]
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    return data["did"], urlsafe_b64decode(encoded)


def load_did_document(agent_name: str, identities_dir: Path) -> dict:
    """Load an agent's DID Document from disk."""
    return json.loads((identities_dir / agent_name / "did_document.json").read_text())


def extract_public_key_from_did_doc(did_document: dict) -> bytes:
    """
    Extract the public key bytes from a DID Document.

    The public key is stored as publicKeyMultibase with a "z" prefix
    (indicating base64url encoding).
    """
    multibase = did_document["verificationMethod"][0]["publicKeyMultibase"]
    encoded = multibase[1:]  # Remove 'z' prefix
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    return urlsafe_b64decode(encoded)
