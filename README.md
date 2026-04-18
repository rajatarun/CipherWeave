# CipherWeave

**Agentic Cryptography Intelligence Layer** — policy-enforced, explainable encryption strategy for AI agents.

CipherWeave intercepts every key-derivation request, traverses a Memgraph topology graph to assess risk, and returns a fully-justified cipher strategy in one MCP tool call. Unknown endpoints are registered on the fly via Bedrock-inferred policy — no pre-seeding required.

> **Core Philosophy**: The Agent Decides *what* to encrypt. CipherWeave decides *how*.

---

## Architecture

```
Agent ──► get_encryption_strategy() ──► RiskGraph (Memgraph)
                │                            │
                │                    endpoint known?
                │                    /           \
                │                  yes            no
                │                   │              │
                │                   │         Bedrock Inference
                │                   │         (claude-haiku-4-5)
                │                   │              │
                │                   │         JIT upsert into
                │                   │         Memgraph graph
                │                   │              │
                │                PathRiskResult ◄──┘
                │                   │
                ▼                   ▼
         DriftDetector ──────► fail-secure override?
                │
                ▼
         CipherJanitor (HKDF + ML-KEM-768)
                │
                ▼
         EncryptionStrategy JSON  ◄── explainable audit trail
```

### Five Modules

| Module | File | Responsibility |
|--------|------|---------------|
| Topological Risk Engine | `risk_engine.py` | Memgraph path scoring + JIT registration |
| Stateless HKDF + PQC | `cipher_janitor.py` | RFC 5869 HKDF + ML-KEM-768 |
| FastMCP Server | `server.py` | Single MCP tool entrypoint |
| Lifecycle & Auth | `lifecycle.py` | MSK rotation, token validation |
| Cipher Drift Detection | `drift_detector.py` | Anomaly detection + override |

---

## Quick Start

### Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) package manager
- Docker + Docker Compose (for Memgraph)

### 1. Clone & Install

```bash
git clone https://github.com/rajatarun/cipherweave
cd cipherweave
uv sync
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env — for local dev, defaults work as-is (CIPHERWEAVE_USE_LOCAL_KMS=true)
```

### 3. Start Memgraph

```bash
docker-compose up -d
# Wait for healthy: docker-compose ps
```

### 4. Run the MCP Server

```bash
uv run python -m cipherweave.server
```

> **Note**: Pre-seeding the graph is no longer required. The first call for any unknown agent/endpoint pair triggers JIT registration using Bedrock-inferred policy.

---

## MCP Tool: `get_encryption_strategy`

### Signature

```python
get_encryption_strategy(
    agent_id: str,          # Unique agent identifier
    data_metadata: dict,    # See fields below
    destination_url: str    # Target endpoint URL
) -> dict
```

### `data_metadata` Fields

| Field | Required | Description |
|-------|----------|-------------|
| `classification` | **Yes** | One of `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, `TOP_SECRET` |
| `tags` | **Yes** | List of regulatory tags e.g. `["GDPR", "HIPAA"]`. Empty list is valid (means no regulations). |
| `data_type` | Recommended | e.g. `"user_analytics"`, `"financial_records"`, `"patient_records"` |
| `description` | Recommended | Human-readable description of the data — improves Bedrock inference accuracy |
| `contains_pii` | Recommended | `true` / `false` |
| `cross_border_transfer` | Recommended | `true` if data crosses jurisdiction boundaries |
| `retention_days` | Optional | Retention period in days |

When `classification` or `tags` is missing, `MetadataInferenceError` is raised immediately — CipherWeave will not guess the policy.

### Example Request

```json
{
  "agent_id": "agent-analytics",
  "data_metadata": {
    "classification": "CONFIDENTIAL",
    "tags": ["GDPR"],
    "data_type": "user_analytics",
    "description": "User behavioural analytics including session tracking and usage patterns",
    "contains_pii": true,
    "cross_border_transfer": true,
    "retention_days": 365
  },
  "destination_url": "https://api.example.com/prod/query"
}
```

### Example Response

```json
{
  "decision_id": "cw_b4ba5ac8",
  "timestamp": "2026-04-18T21:59:15.865330",
  "agent_id": "agent-analytics",
  "destination_url": "https://api.example.com/prod/query",
  "cipher_profile": "QUANTUM_SAFE",
  "algorithm": "ML-KEM-768+AES-256-GCM",
  "key_length_bits": 256,
  "kdf_algorithm": "HKDF-SHA512",
  "salt_b64": "krkJ/+L5KXgvEC+tDzuMYLAk8iUJ0Q67iENvIf8CQM8=",
  "info_string": "cipherweave:v1:agent-analytics:279302a5cc8eab76:17bf47208a9b5d72:1776549555",
  "regulations_crossed": ["GDPR"],
  "threat_proximity": 999,
  "path_nodes": [
    "Agent:agent-analytics",
    "DataAsset:jit_023eb102be9c",
    "Endpoint:279302a5cc8eab76"
  ],
  "risk_score": 0.65,
  "justification": "[ANOMALY DETECTED — QUANTUM_SAFE enforced] Selected HARDENED: path crosses GDPR regulation(s)",
  "cost_per_operation_usd": 0.0000087,
  "ttl_seconds": 1800,
  "hybrid_keypair": {
    "x25519_public_b64": "WREeDDglUHkq5ZF633eAWzgg4B9XN0UtifNg00h1P0w=",
    "mlkem_public_b64": "..."
  },
  "audit_log": {
    "decision_made_by": "CipherJanitor",
    "drift_detected": true,
    "override_applied": true,
    "alert_id": "cw_alert_4c215fef",
    "alert_type": "NEW_AGENT",
    "latency_ms": 1493.365,
    "decision_id": "cw_b4ba5ac8"
  }
}
```

### Cipher Profiles

| Profile | Algorithm | KDF | Key Size | When Applied |
|---------|-----------|-----|----------|-------------|
| `QUANTUM_SAFE` | ML-KEM-768 + AES-256-GCM | HKDF-SHA512 | 256-bit | HIPAA/ITAR, threat ≤2 hops, RESTRICTED/TOP_SECRET, anomaly override |
| `HARDENED` | AES-256-GCM | HKDF-SHA384 | 256-bit | GDPR/PCI/SOX, CONFIDENTIAL |
| `BALANCED` | AES-256-GCM | HKDF-SHA256 | 256-bit | Default |
| `CHEAP` | AES-128-GCM | HKDF-SHA256 | 128-bit | VPC-internal, INTERNAL, no regs/threats |

---

## JIT Endpoint Registration

Unknown agent/endpoint pairs are automatically registered on the first call:

1. `data_metadata` is strictly validated — `classification` and `tags` are required
2. Metadata is sent to **Bedrock** (`us.anthropic.claude-haiku-4-5-20251001-v1:0`) with a strict prompt that returns a structured policy JSON or `can_infer: false`
3. If the model cannot infer (missing/ambiguous metadata), `MetadataInferenceError` is raised — no fallback guess
4. On success, `Agent`, `Endpoint`, `DataAsset`, and `Regulation` nodes are upserted into Memgraph with all edges (`ACCESSES`, `STORED_AT`, `AUTHORIZED_FOR`, `GOVERNED_BY`) — idempotent via deterministic sha256-based IDs
5. Normal `get_path_risk` flow proceeds using the freshly seeded path

**Local dev / tests**: when `CIPHERWEAVE_USE_LOCAL_KMS=true`, no Bedrock client is created and inference falls back to the rule-based routing table (same strict metadata validation applies).

---

## Running Tests

```bash
# All tests (excluding benchmarks)
uv run pytest tests/ -v --benchmark-disable

# Include red-team adversarial tests
uv run pytest tests/red_team.py -v

# Latency benchmarks
uv run pytest tests/benchmarks.py -v -s

# With pytest-benchmark
uv run pytest tests/benchmarks.py --benchmark-only
```

### Linting & Type Checking

```bash
uv run ruff check src/ tests/
uv run pyright src/
```

---

## Memgraph Schema

```cypher
(:Agent {agent_id, name, trust_level})
(:DataAsset {asset_id, classification, tags, jit_registered})
(:Endpoint {endpoint_id, url, region, vpc_internal, jit_registered})
(:Regulation {reg_id, name, cipher_floor})
(:ThreatIndicator {indicator_id, severity, ttl_hours})

(:Agent)-[:ACCESSES]->(:DataAsset)
(:DataAsset)-[:STORED_AT]->(:Endpoint)
(:DataAsset)-[:GOVERNED_BY]->(:Regulation)
(:Endpoint)-[:EXPOSED_TO]->(:ThreatIndicator)
(:Agent)-[:AUTHORIZED_FOR]->(:Endpoint)
```

JIT-registered nodes carry `jit_registered: true` so they can be audited or pruned separately from pre-seeded topology.

---

## Security Properties

- **Fail-Secure**: Unknown agents, new agents, and anomalies all default to `QUANTUM_SAFE`
- **Strict Metadata Enforcement**: Missing or unrecognized `classification` / `tags` raise `MetadataInferenceError` — no silent default
- **Salt Uniqueness**: `SaltReuseError` raised on any `(salt, info)` reuse within a process
- **Memory Sanitation**: IKM is zeroed after HKDF expansion; `secure_context()` zeros all registered buffers
- **No Plaintext MSK Persistence**: Master secret lives only for the duration of one tool invocation
- **Zero-Trust**: `AUTHORIZED_FOR` edge must exist in the graph; no edge = `UnauthorizedAgentError`

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CIPHERWEAVE_MEMGRAPH_HOST` | `localhost` | Memgraph host |
| `CIPHERWEAVE_MEMGRAPH_PORT` | `7687` | Memgraph Bolt port |
| `CIPHERWEAVE_USE_LOCAL_KMS` | `true` | Use `os.urandom` instead of AWS KMS (also disables Bedrock) |
| `CIPHERWEAVE_KMS_KEY_ID` | `` | AWS KMS key ID (production) |
| `CIPHERWEAVE_AWS_REGION` | `us-east-1` | AWS region |
| `CIPHERWEAVE_BEDROCK_INFERENCE_MODEL_ID` | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | Bedrock cross-region inference profile for JIT policy inference |
| `CIPHERWEAVE_TOKEN_SECRET` | `change-me-...` | HMAC token secret |
| `CIPHERWEAVE_DRIFT_WINDOW_SIZE` | `100` | Decisions tracked per agent |
| `CIPHERWEAVE_LOG_LEVEL` | `INFO` | Logging verbosity |

---

## Deployment (AWS Lambda + API Gateway)

CipherWeave ships as an AWS SAM application deployed via GitHub Actions with OIDC (no stored credentials).

```
GitHub Actions (OIDC)
  └─► SAM Build + Deploy
        └─► Lambda (VPC, 512 MB) ◄─── API Gateway HTTP v2
              ├─► Memgraph (private VPC IP, Bolt 7687)
              ├─► AWS KMS (GenerateDataKey / Decrypt)
              └─► AWS Bedrock (claude-haiku-4-5, cross-region inference profile)
```

**VPC note**: The Lambda subnet must have outbound internet access (NAT gateway or NAT instance) to reach Bedrock, or a `bedrock-runtime` VPC endpoint must be provisioned.

Trigger a deploy: `gh workflow run deploy.yml` or push to `main`.

---

## References

- [FastMCP](https://github.com/modelcontextprotocol/python-sdk)
- [HKDF — RFC 5869](https://tools.ietf.org/html/rfc5869)
- [ML-KEM — FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [AWS Bedrock cross-region inference profiles](https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html)
- [cryptography.io](https://cryptography.io/en/latest/)
