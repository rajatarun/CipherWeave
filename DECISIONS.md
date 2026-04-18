# CipherWeave — Architectural Decisions

This document records deliberate design choices, trade-offs, and assumptions made during implementation of CipherWeave v0.1.

---

## ADR-001: Fail-Secure Default — QUANTUM_SAFE for Unknown State

**Decision**: Any condition that cannot be evaluated (new agent, unknown topology, drift anomaly) defaults to `QUANTUM_SAFE`, not to a lower profile.

**Rationale**: The cost of a false positive (encrypting with a stronger cipher than necessary) is a small computational overhead. The cost of a false negative (sending PHI over AES-128 because the graph had no history) is a compliance violation and potential breach. We chose the conservative failure mode.

**Trade-off**: New agents incur `QUANTUM_SAFE` overhead for their first request. Operators should pre-seed the Memgraph topology and warm the `DriftDetector` history via `log_decision()` before production traffic.

---

## ADR-002: MockRiskGraph for Testing (No Memgraph in CI)

**Decision**: `MockRiskGraph` mirrors the full `RiskGraph` API using in-memory dicts and list traversal. Tests import it directly from `risk_engine.py`.

**Rationale**: Spinning up a real Memgraph container in every CI run adds latency, flakiness, and infrastructure dependency. The mock gives deterministic, fast tests while keeping the production code path identical.

**Trade-off**: The mock does not validate Cypher query correctness. The `seed_graph.py` script and manual integration tests against a live Memgraph validate the real query path.

---

## ADR-003: Stateless HKDF — One Master Secret Per Invocation

**Decision**: `CipherJanitor.get_master_secret()` fetches a fresh MSK from KMS on every `get_encryption_strategy()` call. The MSK is never cached in plaintext.

**Rationale**: The spec says "NEVER cache plaintext beyond single tool invocation." Caching the MSK would mean a memory disclosure attack could recover all derived keys for the cache's lifetime. Statelessness is the simpler, safer choice.

**Trade-off**: Additional KMS latency per call (~1–3ms in production). Mitigated in local dev by `os.urandom()`. In production, AWS KMS `GenerateDataKey` can be batched or pre-fetched with envelope encryption, but this is outside v0.1 scope.

---

## ADR-004: Salt Reuse Detection via In-Process Set

**Decision**: `CipherJanitor` tracks all `(salt_hex, info)` pairs seen in a single process lifetime in a Python `set`. Reuse raises `SaltReuseError`.

**Rationale**: RFC 5869 requires unique salts. A same-salt re-derivation with the same IKM yields identical OKM — a key reuse vulnerability. The in-process set catches this for the common case of programmatic misuse.

**Limitation**: Across process restarts or multiple replicas, salt reuse is not detected. Production systems should use a distributed salt ledger (e.g., Redis with TTL) for cross-instance protection. The spec's 10ms budget makes a Redis round-trip risky for v0.1, so we defer to v0.2.

---

## ADR-005: Memory Sanitation — Best-Effort via ctypes

**Decision**: `_zero_bytes()` attempts to overwrite the internal buffer of Python `bytes` objects using `ctypes.memmove`. For `bytearray`, it uses index assignment (reliable).

**Rationale**: Python's immutable `bytes` objects cannot be zeroed via normal Python code. The `ctypes` approach targets the CPython object layout, which is an implementation detail. We document this as best-effort.

**Trade-off**: This is CPython-specific and may break on PyPy or future CPython versions. The safer alternative is to use `bytearray` throughout the key derivation pipeline, converting to `bytes` only at API boundaries. Refactoring to use `bytearray` everywhere is a v0.2 target.

---

## ADR-006: Single MCP Tool

**Decision**: The entire CipherWeave surface is exposed as a single MCP tool: `get_encryption_strategy()`. No separate tools for authorization checks, key listing, or profile queries.

**Rationale**: The spec mandates a single tool. This also enforces the "agent invokes, CipherWeave decides" philosophy — there is no API for an agent to query what profiles are available and then request a specific one separately (which would allow bypass).

---

## ADR-007: Routing Logic — Explicit Table, Not ML

**Decision**: Risk routing uses a deterministic priority table (HIPAA → QUANTUM_SAFE, GDPR → HARDENED, etc.) rather than a learned model.

**Rationale**: An ML model for compliance routing is a liability: it can be fooled, it requires training data, and its decisions are opaque to auditors. A static table is auditable, reproducible, and legally defensible. The spec explicitly documents the routing table.

**Trade-off**: New regulations or edge cases require a code change and deployment, not a model update. Acceptable for v0.1.

---

## ADR-008: Hybrid Keypair — Public Keys Only in Response

**Decision**: `get_encryption_strategy()` returns only the public components of the hybrid keypair (`x25519_public`, `mlkem_public`). Private keys are never included in the response.

**Rationale**: The response is an MCP tool output that may be logged, transmitted to the agent, or stored in audit logs. Private key material must never leave the CipherWeave process boundary.

**Implication**: The current architecture generates the keypair server-side and discards the private key after returning the response. In production, the server would encapsulate the ML-KEM key and return the ciphertext alongside the encapsulation key, so the agent can derive the shared secret. This is the full DHKE flow — deferred to v0.2 because it requires a two-phase protocol.

---

## ADR-009: DriftDetector — Rolling Window, In-Memory

**Decision**: Agent history is stored in a `deque(maxlen=window_size)` in-process. No persistence across restarts.

**Rationale**: Persistence would require a database write on every decision, adding latency. For v0.1, we accept that a process restart clears history (treating the agent as "new" → QUANTUM_SAFE override). This is fail-secure.

**Production path**: Persist decision records to Memgraph or Redis with a TTL equal to the window duration. Query on startup to pre-warm the deque.

---

## ADR-010: FastMCP — stdio Transport for v0.1

**Decision**: The server uses `transport="stdio"` for MCP communication, matching the default for embedded MCP agents.

**Rationale**: HTTP transport adds network setup complexity. For v0.1 local development, stdio is sufficient and matches how Claude Code and similar agents invoke MCP tools.

**Production path**: Switch to `transport="http"` with TLS and add the `AuthMiddleware` to validate `X-Agent-ID` headers at the HTTP layer.

---

## ADR-011: mlkem Package — Stub Fallback

**Decision**: If the `mlkem` package is not installed, `cipher_janitor.py` falls back to `os.urandom()` stubs of the correct key sizes.

**Rationale**: `mlkem` (FIPS 203 ML-KEM-768) is a specialized package that may not be available in all environments. The stub allows tests and local development to proceed without a native ML-KEM implementation, while clearly logging a warning.

**Requirement**: Production deployments MUST install `mlkem` and verify the stub is not active before handling real key material.

---

## ADR-012: < 10ms Budget — In-Process Graph Only

**Decision**: The 10ms budget is achievable only with the `MockRiskGraph` (in-process). A live Memgraph connection adds ~2–5ms for a Bolt round-trip on LAN.

**Mitigation strategies for production**:
1. Connection pooling (persistent Bolt connections, not per-request)
2. Memgraph read replicas co-located with the CipherWeave process
3. Aggressive Cypher query optimization (cover indexes on `agent_id`, `url`)
4. Pre-computed risk score cache with TTL (invalidated on graph mutations)

The benchmark suite tests against `MockRiskGraph` to validate the non-graph overhead is < 10ms, serving as the upper bound for optimization targets.

---

## ADR-013: SAM + GitHub Actions OIDC Deployment

**Decision**: Deploy via AWS SAM with GitHub Actions using OIDC (no long-lived AWS credentials stored as secrets).

**OIDC trust policy required on `arn:aws:iam::239571291755:role/teamweave-github-actions-sam-deployer`**:
```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::239571291755:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
    "StringLike":   {"token.actions.githubusercontent.com:sub": "repo:rajatarun/CipherWeave:*"}
  }
}
```

**Deployment flow**:
1. OIDC exchange → short-lived credentials (no stored secrets)
2. EC2 `describe-instances` on `i-04b2d0f387d2c7d53` → resolves VPC, Subnet, Security Group
3. `sam build` → `sam deploy` with VPC params injected
4. `SeedGraphOnDeploy` CloudFormation Custom Resource runs `SeedGraphFunction` in-VPC
5. `SeedGraphFunction` (inside Lambda SG) opens Bolt to Memgraph `172.31.12.134:7687`
6. Smoke test via direct Lambda invoke

**Trade-off**: The seed step runs in-VPC via Lambda, not from the GitHub runner, because Memgraph is on a private IP (`172.31.12.134`). This is correct but means seed failures must be debugged via CloudWatch, not runner logs.

---

## ADR-014: neo4j Python Driver vs. mgclient for Lambda

**Decision**: Use the `neo4j` (pure-Python) Bolt driver as the primary driver in Lambda. `mgclient` (C extension, requires compilation) remains optional for local dev.

**Rationale**: SAM `sam build` without `--use-container` cannot compile C extensions. The `neo4j` driver is pip-installable with no native compilation and fully supports Memgraph's Bolt protocol.

**Trade-off**: `neo4j` driver has ~2ms more connection overhead than `mgclient`. Acceptable for Lambda cold starts; connection is reused across warm invocations.

---

## ADR-015: Memgraph Topology Includes Real contextweave-rag-prod Endpoints

**Decision**: The seed graph includes `ep-contextweave-api` and `ep-query-expertise` nodes pointing to `https://56u86rj4qk.execute-api.us-east-1.amazonaws.com/prod*`, which are the real API Gateway endpoints from the existing stack.

**Rationale**: CipherWeave policy decisions should cover the endpoints that agents actually call. Seeding real endpoints means agents sending data to `contextweave-rag-prod` will immediately get policy decisions without manual graph construction.

**Security implication**: The `ep-contextweave-api` endpoint is not VPC-internal, so agents accessing it will get `BALANCED` or higher profiles depending on the data classification. TRADE_SECRET assets mapped to this endpoint will trigger `QUANTUM_SAFE`.

---

## ADR-016: JIT Endpoint Registration with Bedrock Policy Inference

**Decision**: When `get_encryption_strategy` is called for an unknown agent/endpoint pair, CipherWeave infers the encryption policy from `data_metadata` via a Bedrock LLM call, then upserts the full graph path (Agent → DataAsset → Endpoint, Regulation nodes, all edges) into Memgraph before proceeding with the normal risk evaluation. Pre-seeding the graph is no longer a deployment prerequisite.

**Rationale**: Real-world deployments have URLs that change constantly — new services, blue/green deployments, feature branches. Requiring operators to manually seed every agent/endpoint pair before production traffic is a brittle coupling between the deploy pipeline and CipherWeave state. JIT registration removes this coupling: the graph self-populates as agents make real requests.

**Why Bedrock for inference (not hardcoded rules only)**: The rule-based routing table (ADR-007) works well for well-labelled metadata but cannot interpret free-form fields like `description`, `data_type`, or `contains_pii`. A small LLM (Haiku 4.5) can parse these contextual signals and return a structured policy decision. The rule table remains as the local dev / test fallback when no Bedrock client is present.

**Strict metadata enforcement**: The inference function requires `classification` (must be one of the five valid levels) and `tags` (list, may be empty). If either is missing or unrecognized, `MetadataInferenceError` is raised immediately. The model is prompted with `can_infer: false` semantics — if it cannot confidently determine a policy, it signals failure and the call is rejected rather than silently defaulting. This prevents policy under-enforcement from malformed requests.

**Idempotency**: Node IDs are deterministic sha256 hashes of the URL (endpoint) and `agent_id:url` (asset). Repeated JIT calls for the same pair are safe MERGE operations — no duplicate nodes.

**JIT vs. pre-seeded nodes**: JIT-registered nodes carry `jit_registered: true`. Operators can audit or prune them separately. Pre-seeded nodes from `seed_graph.py` carry richer metadata (VPC flags, explicit regulation edges, threat indicators) and take precedence because they are written first.

**Trade-off**: The first call for an unknown pair incurs Bedrock inference latency (~1–2s on a cold NAT path). Subsequent calls hit the warm Memgraph path (~2–5ms). The DriftDetector also fires `NEW_AGENT` on the first call, upgrading the profile to `QUANTUM_SAFE` as a fail-secure measure — this is intentional.

**Infrastructure requirement**: The Lambda subnet needs outbound internet access to reach Bedrock (NAT gateway or NAT instance). A `bedrock-runtime` VPC endpoint is the lower-latency alternative for production.

---

## ADR-017: Custom ASGI Adapter for Lambda (No Mangum)

**Decision**: Rather than using Mangum as the ASGI–Lambda adapter, CipherWeave implements a minimal bespoke adapter in `lambda_handler.py`.

**Rationale**: Mangum is synchronous and calls `loop.run_until_complete()` internally. On Python 3.12, when the Lambda handler itself already runs inside an event loop (as required for the per-invocation `async with _asgi_app.lifespan(...)` pattern), Mangum's nested call raises `RuntimeError: This event loop is already running`.

FastMCP 3.x uses contextvars internally. Lifespan `__aenter__()` tokens must be reset in the same `Context` they were created in. Running lifespan startup once at cold-start and dispatching in subsequent `run_until_complete()` calls puts them in different Contexts, causing `ValueError` on `token.reset()`. The per-invocation `async with` keeps everything in one Context per call.

**What the adapter does**:
1. Converts an API Gateway HTTP v2 (payload format 2.0) event into an ASGI `http` scope
2. Strips the stage prefix (`/prod`) from `rawPath` so FastMCP sees `/mcp`
3. Implements `receive` and `send` callables with a `response_complete` event to avoid premature SSE disconnection
4. Enters and exits the FastMCP lifespan within a single coroutine invocation

**Trade-off**: The custom adapter must be maintained if FastMCP's ASGI interface changes. It covers only API GW HTTP v2 (payload format 2.0) — REST API (v1) events are not supported.
