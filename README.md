# CipherWeave

**Agentic Cryptography Intelligence Layer** — policy-enforced, explainable encryption strategy for AI agents.

CipherWeave intercepts every key-derivation request, traverses a Memgraph topology graph to assess risk, and returns a fully-justified cipher strategy in one MCP tool call.

> **Core Philosophy**: The Agent Decides *what* to encrypt. CipherWeave decides *how*.

---

## Architecture

```
Agent ──► get_encryption_strategy() ──► RiskGraph (Memgraph)
                │                            │
                │                      PathRiskResult
                │                            │
                ▼                            ▼
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
| Topological Risk Engine | `risk_engine.py` | Memgraph path scoring |
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

### 4. Seed Demo Topology

```bash
uv run python scripts/seed_graph.py
```

### 5. Run the MCP Server

```bash
uv run python -m cipherweave.server
```

---

## MCP Tool: `get_encryption_strategy`

### Signature

```python
get_encryption_strategy(
    agent_id: str,          # Unique agent identifier
    data_metadata: dict,    # {"tags": ["PII"], "classification": "CONFIDENTIAL"}
    destination_url: str    # Target endpoint URL
) -> dict
```

### Example Request

```json
{
  "agent_id": "agent-analytics",
  "data_metadata": {
    "tags": ["PHI"],
    "classification": "RESTRICTED"
  },
  "destination_url": "https://ehr.hospital/api"
}
```

### Example Response

```json
{
  "decision_id": "cw_a3f7b2c1",
  "timestamp": "2026-04-17T14:32:10.123456",
  "agent_id": "agent-analytics",
  "destination_url": "https://ehr.hospital/api",
  "cipher_profile": "QUANTUM_SAFE",
  "algorithm": "ML-KEM-768+AES-256-GCM",
  "key_length_bits": 256,
  "kdf_algorithm": "HKDF-SHA512",
  "salt_b64": "3q2+7w==...",
  "info_string": "cipherweave:v1:agent-analytics:ep-ehr-system:a1b2c3d4:1713366730",
  "regulations_crossed": ["HIPAA"],
  "threat_proximity": 999,
  "path_nodes": ["Agent:agent-analytics", "DataAsset:asset-patient-records", "Endpoint:ep-ehr-system"],
  "risk_score": 0.90,
  "justification": "Upgraded to QUANTUM_SAFE: path crosses HIPAA boundary",
  "cost_per_operation_usd": 0.0000087,
  "ttl_seconds": 1800,
  "hybrid_keypair": {
    "x25519_public_b64": "...",
    "mlkem_public_b64": "..."
  },
  "audit_log": {
    "decision_made_by": "CipherJanitor",
    "drift_detected": false,
    "override_applied": false,
    "alert_id": null,
    "alert_type": null,
    "latency_ms": 2.147,
    "decision_id": "cw_a3f7b2c1"
  }
}
```

### Cipher Profiles

| Profile | Algorithm | KDF | Key Size | When Applied |
|---------|-----------|-----|----------|-------------|
| `QUANTUM_SAFE` | ML-KEM-768 + AES-256-GCM | HKDF-SHA512 | 256-bit | HIPAA/ITAR, threat ≤2 hops, RESTRICTED/TOP_SECRET |
| `HARDENED` | AES-256-GCM | HKDF-SHA384 | 256-bit | GDPR/PCI/SOX, CONFIDENTIAL |
| `BALANCED` | AES-256-GCM | HKDF-SHA256 | 256-bit | Default |
| `CHEAP` | AES-128-GCM | HKDF-SHA256 | 128-bit | VPC-internal, INTERNAL, no regs/threats |

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
(:DataAsset {asset_id, classification, tags})
(:Endpoint {endpoint_id, url, region, vpc_internal})
(:Regulation {reg_id, name, cipher_floor})
(:ThreatIndicator {indicator_id, severity, ttl_hours})

(:Agent)-[:ACCESSES]->(:DataAsset)
(:DataAsset)-[:STORED_AT]->(:Endpoint)
(:DataAsset)-[:GOVERNED_BY]->(:Regulation)
(:Endpoint)-[:EXPOSED_TO]->(:ThreatIndicator)
(:Agent)-[:AUTHORIZED_FOR]->(:Endpoint)
```

---

## Security Properties

- **Fail-Secure**: Unknown agents, new agents, and anomalies all default to `QUANTUM_SAFE`
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
| `CIPHERWEAVE_USE_LOCAL_KMS` | `true` | Use `os.urandom` instead of AWS KMS |
| `CIPHERWEAVE_KMS_KEY_ID` | `` | AWS KMS key ID (production) |
| `CIPHERWEAVE_AWS_REGION` | `us-east-1` | AWS region |
| `CIPHERWEAVE_TOKEN_SECRET` | `change-me-...` | HMAC token secret |
| `CIPHERWEAVE_DRIFT_WINDOW_SIZE` | `100` | Decisions tracked per agent |
| `CIPHERWEAVE_LOG_LEVEL` | `INFO` | Logging verbosity |

---

## References

- [FastMCP](https://github.com/modelcontextprotocol/python-sdk)
- [GQLAlchemy](https://github.com/memgraph/gqlalchemy)
- [HKDF — RFC 5869](https://tools.ietf.org/html/rfc5869)
- [ML-KEM — FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [cryptography.io](https://cryptography.io/en/latest/)
