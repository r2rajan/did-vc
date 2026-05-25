# Part 1: Building Trust Between AI Agents with Decentralized Identifiers and Verifiable Credentials

A hands-on prototype demonstrating how Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) establish trust between cooperating AI agents. You can run this in your computer if you have python. 

## What This Demonstrates

Three agents run as local Flask server. Before the Orchestrator delegates any task, it performs a 5-step trust chain:

1. **Discover** — Fetch the Agent Card, learn the agent's DID
2. **Resolve** — Fetch the DID Document, extract public key and service endpoints
3. **Authenticate** — Challenge-response with a random nonce (proves identity)
4. **Authorize** — Verify the agent's Verifiable Credential (4 checks: signature, expiry, revocation, capability)
5. **Delegate** — Only now does the agent receive the task

If any step fails, the agent is rejected.

## Quick Start

### Prerequisites

- Python 3.11+
- pip

### Install Dependencies

```bash
cd part1-did-vc
pip install -r requirements.txt
```

### Run the Demo (5 steps)

**Step 1:** Generate cryptographic identities for all agents

```bash
python scripts/step1_generate_identities.py
```

**Step 2:** Issue Verifiable Credentials (Orchestrator grants permissions)

```bash
python scripts/step2_issue_credentials.py
```

**Step 3:** Start the Flight Agent server (leave this running in a separate terminal)

```bash
python scripts/step3_start_flight_agent.py
```

**Step 4:** Run the full trust chain (in a new terminal)

```bash
python scripts/step4_trust_chain.py
```

**Step 5:** Demonstrate credential revocation

```bash
python scripts/step5_revoke.py
```

## Project Structure

```
part1-did-vc/
├── README.md
├── requirements.txt
├── lib/
│   ├── __init__.py
│   ├── keys.py            # Ed25519 key generation + DID Documents
│   ├── credentials.py     # VC issuance + verification (4 checks)
│   └── agent_server.py    # Flask server with 5 trust endpoints
├── scripts/
│   ├── step1_generate_identities.py
│   ├── step2_issue_credentials.py
│   ├── step3_start_flight_agent.py
│   ├── step4_trust_chain.py
│   └── step5_revoke.py
├── identities/            # Generated: key pairs + DID Documents
└── credentials/           # Generated: signed VCs
```

## Key Concepts

| Concept | What It Is | Role in This Demo |
|---------|-----------|-------------------|
| DID | Decentralized Identifier (e.g., `did:web:localhost:flight`) | Unique agent identity |
| DID Document | JSON with public key + service endpoints | How verifiers find and authenticate agents |
| Ed25519 | Signing algorithm (32-byte keys, 64-byte signatures) | All cryptographic operations |
| Verifiable Credential | Signed capability token from an issuer | Authorization proof |
| A2A Protocol | Google's Agent-to-Agent protocol (JSON-RPC) | Task exchange between agents |
| Agent Card | JSON metadata at `/.well-known/agent.json` | Agent discovery |

## The Trust Endpoints (per agent)

| Endpoint | Purpose | Trust Step |
|----------|---------|-----------|
| `GET /.well-known/agent.json` | Agent Card (capabilities + DID) | Discovery |
| `GET /<agent>/did.json` | DID Document (public key + endpoints) | Resolution |
| `POST /<agent>/auth/challenge` | Sign a nonce with private key | Authentication |
| `GET /<agent>/credentials` | Present Verifiable Credential | Authorization |
| `POST /a2a` | Handle tasks (JSON-RPC) | Delegation |

## What's in Part 2

Part 2 deploys this same trust chain to AWS:

- Flask → Lambda functions
- localhost → API Gateway + CloudFront (HTTPS)
- File system → DynamoDB + Secrets Manager
- Mock responses → Amazon Bedrock (real LLM reasoning)
- Terminal output → Interactive dashboard with trust audit visualization

The cryptographic trust chain stays identical — only the infrastructure changes.

## Technologies Used

- **Python 3.11** — Language
- **Flask** — HTTP server (development)
- **PyNaCl** — Ed25519 signing (libsodium bindings)
- **httpx** — HTTP client for agent-to-agent calls
- **W3C DID Core 1.0** — Identity standard
- **W3C VC Data Model 1.1** — Credential standard
- **Google A2A Protocol** — Agent communication
