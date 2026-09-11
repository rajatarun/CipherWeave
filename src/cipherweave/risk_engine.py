"""Module 1: Topological Risk Engine — graph-based path risk scoring via Memgraph.

Driver strategy:
  1. neo4j (pure-Python Bolt driver) — preferred in Lambda / production
  2. mgclient (C extension) — fallback for local dev when neo4j not installed
  3. MockRiskGraph — in-memory stub for unit tests
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any

from cipherweave.exceptions import (
    GraphConnectionError,
    MetadataInferenceError,
    PathNotFoundError,
    UnauthorizedAgentError,
)
from cipherweave.models import PathRiskResult
from cipherweave.profiles import CipherProfile
from cipherweave.scoring import (
    DEFAULT_GAMMA,
    DEFAULT_HOP_BOUND,
    aggregate_path_risk,
    combine,
    compliance_floor,
    justify,
    profile_for_score,
)

logger = logging.getLogger(__name__)

# Detect available Bolt driver at import time
try:
    from neo4j import AsyncGraphDatabase as _Neo4jDriver  # type: ignore[import]
    _BOLT_DRIVER = "neo4j"
except ImportError:
    _Neo4jDriver = None
    _BOLT_DRIVER = "mgclient"

# Data classification ordinal (higher = more sensitive)
_CLASSIFICATION_RANK: dict[str, int] = {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "RESTRICTED": 3,
    "TOP_SECRET": 4,
}

# Regulations that mandate QUANTUM_SAFE
_QUANTUM_REGS: frozenset[str] = frozenset({"HIPAA", "ITAR"})

# Regulations that mandate HARDENED minimum
_HARDENED_REGS: frozenset[str] = frozenset({"GDPR", "PCI_DSS_4", "SOX"})

_VALID_CLASSIFICATIONS: frozenset[str] = frozenset(_CLASSIFICATION_RANK.keys())

_BEDROCK_PROMPT = """\
You are a cryptographic policy engine. Analyze the data metadata below and determine the appropriate encryption profile.

METADATA:
{metadata_json}

VALID PROFILES (strongest → weakest):
- QUANTUM_SAFE  (risk ≥ 0.80): required for HIPAA/ITAR, RESTRICTED/TOP_SECRET data, or active threats
- HARDENED      (risk 0.60-0.79): required for GDPR/PCI_DSS_4/SOX or CONFIDENTIAL data
- BALANCED      (risk 0.30-0.59): standard for INTERNAL data with no regulatory burden
- CHEAP         (risk < 0.30): only for VPC-internal PUBLIC/INTERNAL data with zero regulations

Respond ONLY with valid JSON, no markdown, no extra text.

If you CAN infer the policy:
{{"can_infer": true, "classification": "<PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED|TOP_SECRET>", "regulations": ["<UPPERCASE>"], "profile": "<PROFILE>", "risk_score": <0.0-1.0>, "justification": "<one sentence>"}}

If metadata is missing, ambiguous, or classification is unrecognizable:
{{"can_infer": false, "error_field": "<field>", "error_reason": "<why>"}}

Be strict: do not guess. If classification is absent or not one of the five valid values, set can_infer=false.\
"""


def _invoke_bedrock_sync(client: Any, model_id: str, metadata: dict) -> dict:
    prompt = _BEDROCK_PROMPT.format(metadata_json=json.dumps(metadata, indent=2))
    response = client.converse(
        modelId=model_id,
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": 512, "temperature": 0},
    )
    content = response.get("output", {}).get("message", {}).get("content", [])
    text = content[0]["text"].strip() if content else ""

    # Strip markdown code fences the model may add despite being told not to
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1]).strip()

    if not text:
        stop_reason = response.get("stopReason", "unknown")
        raise ValueError(f"empty response from Bedrock model (stopReason={stop_reason})")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise ValueError(f"model returned non-JSON: {text[:300]!r}") from None


async def infer_policy_from_metadata(
    data_metadata: dict,
    bedrock_client: Any = None,
    model_id: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0",
) -> tuple[str, list[str], CipherProfile, float, str]:
    """Strictly validate metadata and infer (classification, regulations, profile, score, justification).

    Uses Bedrock when bedrock_client is provided; otherwise falls back to rule-based inference.
    Raises MetadataInferenceError if metadata is missing, unrecognized, or the model cannot infer.
    """
    if not isinstance(data_metadata, dict):
        raise MetadataInferenceError("data_metadata", "must be a dict")

    if bedrock_client is not None:
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None, _invoke_bedrock_sync, bedrock_client, model_id, data_metadata
            )
        except Exception as exc:
            raise MetadataInferenceError("bedrock_call", str(exc)) from exc

        if not result.get("can_infer"):
            raise MetadataInferenceError(
                result.get("error_field", "unknown"),
                result.get("error_reason", "model could not infer policy"),
            )

        classification = result["classification"].upper()
        if classification not in _VALID_CLASSIFICATIONS:
            raise MetadataInferenceError(
                "classification",
                f"model returned unrecognized value '{classification}'",
            )

        profile_name = result["profile"].upper()
        try:
            profile = CipherProfile[profile_name]
        except KeyError:
            raise MetadataInferenceError("profile", f"model returned unrecognized profile '{profile_name}'")  # noqa: B904

        risk_score = float(result["risk_score"])
        if not (0.0 <= risk_score <= 1.0):
            raise MetadataInferenceError("risk_score", f"model returned out-of-range value {risk_score}")

        regulations: list[str] = [r.upper() for r in result.get("regulations", [])]
        justification: str = result.get("justification", "Inferred via Bedrock policy engine")
        return classification, regulations, profile, risk_score, justification

    # Rule-based fallback (local dev / tests — no Bedrock client)
    if "classification" not in data_metadata:
        raise MetadataInferenceError("classification", "field is required to infer encryption policy")

    raw_cls = data_metadata["classification"]
    if not isinstance(raw_cls, str):
        raise MetadataInferenceError("classification", f"must be a string, got {type(raw_cls).__name__}")

    classification = raw_cls.upper()
    if classification not in _VALID_CLASSIFICATIONS:
        raise MetadataInferenceError(
            "classification",
            f"'{raw_cls}' not recognized. Valid values: {sorted(_VALID_CLASSIFICATIONS)}",
        )

    if "tags" not in data_metadata:
        raise MetadataInferenceError(
            "tags",
            "field is required. Provide an empty list if no regulatory tags apply",
        )

    tags = data_metadata["tags"]
    if not isinstance(tags, list):
        raise MetadataInferenceError("tags", f"must be a list of strings, got {type(tags).__name__}")
    if not all(isinstance(t, str) for t in tags):
        raise MetadataInferenceError("tags", "all elements must be strings")

    regulations = [t.upper() for t in tags]
    # vpc_internal unknown → False (conservative: treat as internet-facing)
    # threat_proximity unknown → 999 (no known threats)
    profile, risk_score, justification = _profile_from_risk(
        regulations=regulations,
        threat_proximity=999,
        classification=classification,
        vpc_internal=False,
    )
    return classification, regulations, profile, risk_score, justification


def _jit_endpoint_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _jit_asset_id(agent_id: str, url: str) -> str:
    return f"jit_{hashlib.sha256(f'{agent_id}:{url}'.encode()).hexdigest()[:12]}"


def _profile_from_risk(
    regulations: list[str],
    threat_proximity: int,
    classification: str,
    vpc_internal: bool,
) -> tuple[CipherProfile, float, str]:
    """Apply routing logic table and return (profile, risk_score, justification)."""
    reg_set = {r.upper() for r in regulations}
    cls_rank = _CLASSIFICATION_RANK.get(classification.upper(), 0)

    # Tier 1 — QUANTUM_SAFE
    if reg_set & _QUANTUM_REGS:
        crossed = reg_set & _QUANTUM_REGS
        return (
            CipherProfile.QUANTUM_SAFE,
            0.90,
            f"Upgraded to QUANTUM_SAFE: path crosses {', '.join(sorted(crossed))} boundary",
        )
    if threat_proximity <= 2:
        return (
            CipherProfile.QUANTUM_SAFE,
            0.85,
            f"Upgraded to QUANTUM_SAFE: active threat indicator within {threat_proximity} hop(s)",
        )
    if cls_rank >= _CLASSIFICATION_RANK["RESTRICTED"]:
        return (
            CipherProfile.QUANTUM_SAFE,
            0.80,
            f"Upgraded to QUANTUM_SAFE: data classification is {classification}",
        )

    # Tier 2 — HARDENED
    if reg_set & _HARDENED_REGS:
        crossed = reg_set & _HARDENED_REGS
        return (
            CipherProfile.HARDENED,
            0.65,
            f"Selected HARDENED: path crosses {', '.join(sorted(crossed))} regulation(s)",
        )
    if cls_rank == _CLASSIFICATION_RANK["CONFIDENTIAL"]:
        return (
            CipherProfile.HARDENED,
            0.60,
            "Selected HARDENED: data classification is CONFIDENTIAL",
        )

    # Tier 3 — CHEAP (VPC-internal only)
    if vpc_internal and cls_rank <= _CLASSIFICATION_RANK["INTERNAL"] and not regulations and threat_proximity > 2:
        return (
            CipherProfile.CHEAP,
            0.15,
            "Selected CHEAP: VPC-internal path, low-sensitivity data, no regulations or threats",
        )

    # Tier 4 — BALANCED (default)
    return (
        CipherProfile.BALANCED,
        0.35,
        "Selected BALANCED: standard risk level — no elevated regulations, threats, or classification",
    )


def _score(
    seeds: list[str],
    adjacency: dict[str, list[str]],
    attributes: dict[str, dict],
    agent_id: str,
    asset_id: str | None,
    endpoint_id: str,
    classification: str,
    hop_bound: int,
    gamma: float,
) -> PathRiskResult:
    """Run Algorithm 1 over a local adjacency map and apply the raise-only operators."""
    agg = aggregate_path_risk(
        seeds,
        neighbors=lambda n: adjacency.get(n, ()),
        attributes=lambda n: attributes.get(n, {}),
        hop_bound=hop_bound,
        gamma=gamma,
    )
    from_score = profile_for_score(agg.risk_score)
    floor = compliance_floor(agg.regulations)
    final = combine(from_score, floor)

    path_nodes = [f"Agent:{agent_id}"]
    if asset_id:
        path_nodes.append(f"DataAsset:{asset_id}")
    path_nodes.append(f"Endpoint:{endpoint_id}")

    return PathRiskResult(
        path_nodes=path_nodes,
        regulations_crossed=agg.regulations,
        threat_proximity=agg.threat_proximity,
        data_classification=classification,
        recommended_profile=final,
        risk_score=agg.risk_score,
        justification=justify(agg, floor, final),
        evidence_mass=agg.evidence_mass,
        evidence_trail=agg.explain(),
        nodes_visited=agg.visited_nodes,
        compliance_floor=floor,
    )


class RiskGraph:
    """Graph-based path risk scoring using Memgraph (Bolt/Cypher).

    Uses the neo4j async driver (pure-Python, Lambda-safe) when available;
    falls back to mgclient (C extension) for local dev.
    """

    def __init__(self, memgraph_host: str = "localhost", memgraph_port: int = 7687) -> None:
        self._host = memgraph_host
        self._port = memgraph_port
        self._driver: Any = None

    async def connect(self) -> None:
        """Open a Bolt connection to Memgraph."""
        try:
            if _BOLT_DRIVER == "neo4j" and _Neo4jDriver is not None:
                self._driver = _Neo4jDriver.driver(
                    f"bolt://{self._host}:{self._port}",
                    auth=None,       # Memgraph default: no auth
                    encrypted=False,
                )
                # Verify connectivity
                async with self._driver.session() as session:
                    await session.run("RETURN 1")
                logger.info("Connected to Memgraph via neo4j driver at %s:%s", self._host, self._port)
            else:
                import mgclient  # type: ignore[import]
                self._driver = mgclient.connect(host=self._host, port=self._port)
                logger.info("Connected to Memgraph via mgclient at %s:%s", self._host, self._port)
        except Exception as exc:
            raise GraphConnectionError(
                f"Cannot connect to Memgraph at {self._host}:{self._port}: {exc}"
            ) from exc

    async def close(self) -> None:
        if self._driver is not None:
            try:
                if _BOLT_DRIVER == "neo4j":
                    await self._driver.close()
                else:
                    self._driver.close()
            except Exception:
                pass
            self._driver = None

    async def _execute(self, query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Run a Cypher query and return rows as dicts (async)."""
        if self._driver is None:
            raise GraphConnectionError("Not connected to Memgraph. Call connect() first.")

        if _BOLT_DRIVER == "neo4j":
            async with self._driver.session() as session:
                result = await session.run(query, params or {})
                records = await result.data()
                return records  # neo4j driver returns list[dict] from .data()
        else:
            # mgclient synchronous path
            cursor = self._driver.cursor()
            cursor.execute(query, params or {})
            cols = [desc[0] for desc in cursor.description] if cursor.description else []
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    async def initialize_schema(self) -> None:
        """Create indexes and constraints."""
        ddl_statements = [
            "CREATE INDEX ON :Agent(agent_id);",
            "CREATE INDEX ON :DataAsset(asset_id);",
            "CREATE INDEX ON :Endpoint(endpoint_id);",
            "CREATE INDEX ON :Endpoint(url);",
            "CREATE INDEX ON :Regulation(reg_id);",
            "CREATE INDEX ON :ThreatIndicator(indicator_id);",
        ]
        for stmt in ddl_statements:
            try:
                await self._execute(stmt)
            except Exception:
                # Indexes may already exist; non-fatal
                pass
        logger.info("Memgraph schema initialized")

    _NEIGHBOR_CYPHER = """
    UNWIND $frontier AS fid
    MATCH (a)-[]-(b)
    WHERE coalesce(a.agent_id, a.asset_id, a.endpoint_id, a.reg_id, a.indicator_id) = fid
    RETURN fid AS src,
           coalesce(b.agent_id, b.asset_id, b.endpoint_id, b.reg_id, b.indicator_id) AS dst,
           labels(b)[0] AS type,
           b.name AS name,
           b.classification AS classification,
           b.vpc_internal AS vpc_internal,
           b.severity AS severity,
           b.weight AS weight
    """

    async def _fetch_neighborhood(
        self, seeds: list[str], hop_bound: int
    ) -> tuple[dict[str, list[str]], dict[str, dict]]:
        """Level-synchronous BFS prefetch: one query per level, at most `hop_bound` levels.

        Pulling the bounded neighborhood into a local adjacency map lets the same
        `aggregate_path_risk` (Algorithm 1) run over Memgraph and over the in-memory
        test double, rather than maintaining two different scoring paths.
        """
        adjacency: dict[str, list[str]] = {}
        attributes: dict[str, dict] = {}
        frontier = [s for s in seeds if s]
        visited: set[str] = set(frontier)

        for _ in range(hop_bound):
            if not frontier:
                break
            rows = await self._execute(self._NEIGHBOR_CYPHER, {"frontier": frontier})
            nxt: list[str] = []
            for row in rows:
                src, dst = row.get("src"), row.get("dst")
                if not src or not dst:
                    continue
                adjacency.setdefault(src, []).append(dst)
                if dst not in attributes:
                    attributes[dst] = {
                        "type": row.get("type"),
                        "name": row.get("name"),
                        "classification": row.get("classification"),
                        "vpc_internal": row.get("vpc_internal"),
                        "severity": row.get("severity"),
                        "weight": row.get("weight"),
                    }
                if dst not in visited:
                    visited.add(dst)
                    nxt.append(dst)
            frontier = nxt
        return adjacency, attributes

    async def get_path_risk(
        self,
        agent_id: str,
        destination_url: str,
        data_tags: list[str],
        hop_bound: int = DEFAULT_HOP_BOUND,
        gamma: float = DEFAULT_GAMMA,
    ) -> PathRiskResult:
        """Score an agent->endpoint flow by bounded evidence aggregation (Eq. 1/2)."""
        ep_rows = await self._execute(
            "MATCH (e:Endpoint {url: $url}) RETURN e.endpoint_id AS endpoint_id, "
            "e.vpc_internal AS vpc_internal",
            {"url": destination_url},
        )
        if not ep_rows:
            raise PathNotFoundError(agent_id, destination_url)
        endpoint_id = ep_rows[0]["endpoint_id"]
        vpc_internal = bool(ep_rows[0].get("vpc_internal", False))

        asset_rows = await self._execute(
            """
            MATCH (a:Agent {agent_id: $agent_id})-[:ACCESSES]->(d:DataAsset)-[:STORED_AT]->(e:Endpoint {endpoint_id: $ep_id})
            RETURN d.asset_id AS asset_id, d.classification AS classification
            LIMIT 1
            """,
            {"agent_id": agent_id, "ep_id": endpoint_id},
        )
        asset_id = asset_rows[0].get("asset_id") if asset_rows else None
        classification = (asset_rows[0].get("classification") or "INTERNAL") if asset_rows else "INTERNAL"

        seeds = [x for x in (agent_id, asset_id, endpoint_id) if x]
        adjacency, attributes = await self._fetch_neighborhood(seeds, hop_bound)

        # Seed attributes are known locally and are not re-fetched.
        attributes[agent_id] = {"type": "Agent"}
        attributes[endpoint_id] = {"type": "Endpoint", "vpc_internal": vpc_internal}
        if asset_id:
            attributes[asset_id] = {"type": "DataAsset", "classification": classification}

        return _score(seeds, adjacency, attributes, agent_id, asset_id, endpoint_id,
                      classification, hop_bound, gamma)

    async def validate_agent_authorization(
        self,
        agent_id: str,
        endpoint_id: str,
    ) -> bool:
        """Verify AUTHORIZED_FOR edge exists; raise UnauthorizedAgentError if not."""
        rows = await self._execute(
            """
            MATCH (a:Agent {agent_id: $agent_id})-[:AUTHORIZED_FOR]->(e:Endpoint {endpoint_id: $ep_id})
            RETURN count(*) AS cnt
            """,
            {"agent_id": agent_id, "ep_id": endpoint_id},
        )
        authorized = bool(rows and rows[0]["cnt"] > 0)
        if not authorized:
            raise UnauthorizedAgentError(agent_id, endpoint_id)
        return True

    async def get_endpoint_id_for_url(self, url: str) -> str | None:
        """Look up endpoint_id by URL."""
        rows = await self._execute(
            "MATCH (e:Endpoint {url: $url}) RETURN e.endpoint_id AS endpoint_id",
            {"url": url},
        )
        return rows[0]["endpoint_id"] if rows else None

    async def agent_exists(self, agent_id: str) -> bool:
        rows = await self._execute(
            "MATCH (a:Agent {agent_id: $agent_id}) RETURN count(*) AS cnt",
            {"agent_id": agent_id},
        )
        return bool(rows and rows[0]["cnt"] > 0)

    async def upsert_jit_path(
        self,
        agent_id: str,
        destination_url: str,
        classification: str,
        regulations: list[str],
    ) -> str:
        """JIT-register an agent→endpoint path derived from inferred metadata. Idempotent.

        Returns the endpoint_id (deterministic sha256-based, stable across retries).
        """
        endpoint_id = _jit_endpoint_id(destination_url)
        asset_id = _jit_asset_id(agent_id, destination_url)

        await self._execute(
            "MERGE (:Agent {agent_id: $agent_id})",
            {"agent_id": agent_id},
        )
        await self._execute(
            """
            MERGE (e:Endpoint {url: $url})
            ON CREATE SET e.endpoint_id = $endpoint_id, e.vpc_internal = false, e.jit_registered = true
            """,
            {"url": destination_url, "endpoint_id": endpoint_id},
        )
        await self._execute(
            """
            MERGE (d:DataAsset {asset_id: $asset_id})
            ON CREATE SET d.classification = $classification, d.tags = $tags, d.jit_registered = true
            """,
            {"asset_id": asset_id, "classification": classification, "tags": regulations},
        )
        await self._execute(
            """
            MATCH (a:Agent {agent_id: $agent_id}), (d:DataAsset {asset_id: $asset_id}),
                  (e:Endpoint {url: $url})
            MERGE (a)-[:ACCESSES]->(d)
            MERGE (d)-[:STORED_AT]->(e)
            MERGE (a)-[:AUTHORIZED_FOR]->(e)
            """,
            {"agent_id": agent_id, "asset_id": asset_id, "url": destination_url},
        )
        for reg in regulations:
            reg_id = f"reg_{reg.lower()}"
            await self._execute(
                """
                MERGE (r:Regulation {name: $name})
                ON CREATE SET r.reg_id = $reg_id
                """,
                {"name": reg, "reg_id": reg_id},
            )
            await self._execute(
                """
                MATCH (d:DataAsset {asset_id: $asset_id}), (r:Regulation {name: $name})
                MERGE (d)-[:GOVERNED_BY]->(r)
                """,
                {"asset_id": asset_id, "name": reg},
            )

        # Return the stable endpoint_id (may differ from stored if endpoint pre-existed)
        rows = await self._execute(
            "MATCH (e:Endpoint {url: $url}) RETURN e.endpoint_id AS endpoint_id",
            {"url": destination_url},
        )
        return rows[0]["endpoint_id"]


class MockRiskGraph(RiskGraph):
    """In-memory stub for testing — no Memgraph required."""

    def __init__(self) -> None:
        # Don't call super().__init__() to avoid needing host/port
        self._host = "mock"
        self._port = 0
        self._conn = None
        self._agents: dict[str, dict[str, Any]] = {}
        self._endpoints: dict[str, dict[str, Any]] = {}
        self._assets: dict[str, dict[str, Any]] = {}
        self._regulations: dict[str, dict[str, Any]] = {}
        self._threats: dict[str, dict[str, Any]] = {}
        self._edges: list[tuple[str, str, str]] = []  # (from_id, rel, to_id)
        # Adjacency indexes. The previous implementation rescanned the whole edge
        # list per lookup, making a single decision quadratic in graph size; these
        # make neighbour lookup O(degree).
        self._adj_typed: dict[tuple[str, str], list[str]] = {}
        self._adj_undirected: dict[str, list[str]] = {}
        self._url_index: dict[str, str] = {}

    async def connect(self) -> None:
        logger.info("MockRiskGraph connected (in-memory)")

    async def close(self) -> None:
        pass

    async def initialize_schema(self) -> None:
        pass

    def seed(
        self,
        agents: list[dict[str, Any]] | None = None,
        endpoints: list[dict[str, Any]] | None = None,
        assets: list[dict[str, Any]] | None = None,
        regulations: list[dict[str, Any]] | None = None,
        threats: list[dict[str, Any]] | None = None,
        edges: list[tuple[str, str, str]] | None = None,
    ) -> None:
        """Populate the in-memory store for test scenarios."""
        for a in agents or []:
            self._agents[a["agent_id"]] = a
        for e in endpoints or []:
            self._endpoints[e["endpoint_id"]] = e
        for d in assets or []:
            self._assets[d["asset_id"]] = d
        for r in regulations or []:
            self._regulations[r["reg_id"]] = r
        for t in threats or []:
            self._threats[t["indicator_id"]] = t
        for edge in edges or []:
            self._edges.append(edge)
            self._index_edge(*edge)
        for e in endpoints or []:
            self._url_index[e["url"]] = e["endpoint_id"]

    def _index_edge(self, frm: str, rel: str, to: str) -> None:
        self._adj_typed.setdefault((frm, rel), []).append(to)
        self._adj_undirected.setdefault(frm, []).append(to)
        self._adj_undirected.setdefault(to, []).append(frm)

    def _node_attrs(self, node_id: str) -> dict[str, Any]:
        """Uniform attribute view over the heterogeneous in-memory stores."""
        if node_id in self._assets:
            a = self._assets[node_id]
            return {"type": "DataAsset", "classification": a.get("classification", "INTERNAL")}
        if node_id in self._endpoints:
            e = self._endpoints[node_id]
            return {"type": "Endpoint", "vpc_internal": e.get("vpc_internal", False)}
        if node_id in self._regulations:
            r = self._regulations[node_id]
            return {"type": "Regulation", "name": r.get("name", node_id), "weight": r.get("weight")}
        if node_id in self._threats:
            t = self._threats[node_id]
            return {"type": "ThreatIndicator", "name": t.get("name", node_id),
                    "severity": t.get("severity"), "weight": t.get("weight")}
        if node_id in self._agents:
            return {"type": "Agent"}
        return {}

    def _neighbors(self, node_id: str, rel: str) -> list[str]:
        return self._adj_typed.get((node_id, rel), [])

    async def get_path_risk(
        self,
        agent_id: str,
        destination_url: str,
        data_tags: list[str],
        hop_bound: int = DEFAULT_HOP_BOUND,
        gamma: float = DEFAULT_GAMMA,
    ) -> PathRiskResult:
        endpoint_id = self._url_index.get(destination_url)
        if endpoint_id is None:
            raise PathNotFoundError(agent_id, destination_url)

        asset_id = None
        classification = "INTERNAL"
        for aid in self._neighbors(agent_id, "ACCESSES"):
            if endpoint_id in self._neighbors(aid, "STORED_AT"):
                asset_id = aid
                classification = self._assets.get(aid, {}).get("classification", "INTERNAL")
                break

        seeds = [x for x in (agent_id, asset_id, endpoint_id) if x]
        return _score(seeds, self._adj_undirected, self._node_attrs_map(), agent_id,
                      asset_id, endpoint_id, classification, hop_bound, gamma)

    def _node_attrs_map(self) -> dict[str, dict[str, Any]]:
        """Lazy attribute view presented as a mapping for the shared scorer."""

        class _View(dict):
            def __init__(self, owner): self._owner = owner
            def get(self, key, default=None):  # type: ignore[override]
                return self._owner._node_attrs(key) or (default if default is not None else {})

        return _View(self)

    async def validate_agent_authorization(
        self,
        agent_id: str,
        endpoint_id: str,
    ) -> bool:
        authorized = endpoint_id in self._neighbors(agent_id, "AUTHORIZED_FOR")
        if not authorized:
            raise UnauthorizedAgentError(agent_id, endpoint_id)
        return True

    async def get_endpoint_id_for_url(self, url: str) -> str | None:
        ep = next((e for e in self._endpoints.values() if e["url"] == url), None)
        return ep["endpoint_id"] if ep else None

    async def agent_exists(self, agent_id: str) -> bool:
        return agent_id in self._agents

    async def upsert_jit_path(
        self,
        agent_id: str,
        destination_url: str,
        classification: str,
        regulations: list[str],
    ) -> str:
        """JIT-register an agent→endpoint path in the in-memory store. Idempotent."""
        endpoint_id = _jit_endpoint_id(destination_url)
        asset_id = _jit_asset_id(agent_id, destination_url)

        self._agents.setdefault(agent_id, {"agent_id": agent_id})
        self._endpoints.setdefault(endpoint_id, {
            "endpoint_id": endpoint_id,
            "url": destination_url,
            "vpc_internal": False,
            "jit_registered": True,
        })
        self._assets.setdefault(asset_id, {
            "asset_id": asset_id,
            "classification": classification,
            "tags": regulations,
            "jit_registered": True,
        })
        for reg in regulations:
            reg_id = f"reg_{reg.lower()}"
            self._regulations.setdefault(reg_id, {"reg_id": reg_id, "name": reg})
            edge = (asset_id, "GOVERNED_BY", reg_id)
            if edge not in self._edges:
                self._edges.append(edge)
                self._index_edge(*edge)

        for frm, rel, to in [
            (agent_id, "ACCESSES", asset_id),
            (asset_id, "STORED_AT", endpoint_id),
            (agent_id, "AUTHORIZED_FOR", endpoint_id),
        ]:
            if (frm, rel, to) not in self._edges:
                self._edges.append((frm, rel, to))
                self._index_edge(frm, rel, to)

        self._url_index[destination_url] = endpoint_id
        return endpoint_id
