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
        inferenceConfig={"maxTokens": 300, "temperature": 0},
    )
    text = response["output"]["message"]["content"][0]["text"].strip()
    return json.loads(text)


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
        except json.JSONDecodeError as exc:
            raise MetadataInferenceError("bedrock_response", f"model returned non-JSON: {exc}") from exc
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

    async def get_path_risk(
        self,
        agent_id: str,
        destination_url: str,
        data_tags: list[str],
    ) -> PathRiskResult:
        """Compute cipher profile and risk score for an agent→endpoint path."""
        # 1. Find matching endpoint
        ep_rows = await self._execute(
            "MATCH (e:Endpoint {url: $url}) RETURN e.endpoint_id AS endpoint_id, e.vpc_internal AS vpc_internal",
            {"url": destination_url},
        )
        if not ep_rows:
            raise PathNotFoundError(agent_id, destination_url)
        endpoint_id = ep_rows[0]["endpoint_id"]
        vpc_internal = bool(ep_rows[0].get("vpc_internal", False))

        # 2. Find DataAssets accessed by this agent that are stored at this endpoint
        asset_rows = await self._execute(
            """
            MATCH (a:Agent {agent_id: $agent_id})-[:ACCESSES]->(d:DataAsset)-[:STORED_AT]->(e:Endpoint {endpoint_id: $ep_id})
            RETURN d.asset_id AS asset_id, d.classification AS classification, d.tags AS tags
            LIMIT 1
            """,
            {"agent_id": agent_id, "ep_id": endpoint_id},
        )

        classification = "INTERNAL"
        asset_id = None
        if asset_rows:
            classification = asset_rows[0].get("classification", "INTERNAL")
            asset_id = asset_rows[0].get("asset_id")

        # 3. Find regulations governing data assets on this path
        reg_rows = await self._execute(
            """
            MATCH (a:Agent {agent_id: $agent_id})-[:ACCESSES]->(d:DataAsset)-[:GOVERNED_BY]->(r:Regulation)
            WHERE EXISTS { (d)-[:STORED_AT]->(:Endpoint {endpoint_id: $ep_id}) }
            RETURN DISTINCT r.name AS reg_name
            """,
            {"agent_id": agent_id, "ep_id": endpoint_id},
        )
        regulations = [row["reg_name"] for row in reg_rows]

        # 4. Find direct threats on the target endpoint (threat_proximity=1)
        threat_rows = await self._execute(
            """
            MATCH (e:Endpoint {endpoint_id: $ep_id})-[:EXPOSED_TO]->(t:ThreatIndicator)
            RETURN count(t) AS threat_count
            """,
            {"ep_id": endpoint_id},
        )
        direct_threats = threat_rows[0]["threat_count"] if threat_rows else 0
        threat_proximity = 1 if direct_threats > 0 else 999

        # 5. Build path nodes list for audit trail
        path_nodes = [f"Agent:{agent_id}"]
        if asset_id:
            path_nodes.append(f"DataAsset:{asset_id}")
        path_nodes.append(f"Endpoint:{endpoint_id}")

        # 6. Determine profile via routing table
        profile, risk_score, justification = _profile_from_risk(
            regulations, threat_proximity, classification, vpc_internal
        )

        return PathRiskResult(
            path_nodes=path_nodes,
            regulations_crossed=regulations,
            threat_proximity=threat_proximity,
            data_classification=classification,
            recommended_profile=profile,
            risk_score=risk_score,
            justification=justification,
        )

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

    def _neighbors(self, node_id: str, rel: str) -> list[str]:
        return [to for (frm, r, to) in self._edges if frm == node_id and r == rel]

    async def get_path_risk(
        self,
        agent_id: str,
        destination_url: str,
        data_tags: list[str],
    ) -> PathRiskResult:
        ep = next((e for e in self._endpoints.values() if e["url"] == destination_url), None)
        if ep is None:
            raise PathNotFoundError(agent_id, destination_url)

        endpoint_id = ep["endpoint_id"]
        vpc_internal = ep.get("vpc_internal", False)

        # Find data assets the agent accesses stored at this endpoint
        accessed_asset_ids = self._neighbors(agent_id, "ACCESSES")
        classification = "INTERNAL"
        asset_id = None
        for aid in accessed_asset_ids:
            stored_at = self._neighbors(aid, "STORED_AT")
            if endpoint_id in stored_at:
                asset_id = aid
                classification = self._assets.get(aid, {}).get("classification", "INTERNAL")
                break

        # Regulations
        regulations: list[str] = []
        for aid in accessed_asset_ids:
            stored_at = self._neighbors(aid, "STORED_AT")
            if endpoint_id in stored_at:
                for rid in self._neighbors(aid, "GOVERNED_BY"):
                    reg = self._regulations.get(rid, {})
                    if reg.get("name"):
                        regulations.append(reg["name"])

        # Threat proximity
        exposed_threats = self._neighbors(endpoint_id, "EXPOSED_TO")
        threat_proximity = 1 if exposed_threats else 999

        path_nodes = [f"Agent:{agent_id}"]
        if asset_id:
            path_nodes.append(f"DataAsset:{asset_id}")
        path_nodes.append(f"Endpoint:{endpoint_id}")

        profile, risk_score, justification = _profile_from_risk(
            regulations, threat_proximity, classification, vpc_internal
        )

        return PathRiskResult(
            path_nodes=path_nodes,
            regulations_crossed=regulations,
            threat_proximity=threat_proximity,
            data_classification=classification,
            recommended_profile=profile,
            risk_score=risk_score,
            justification=justification,
        )

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

        for frm, rel, to in [
            (agent_id, "ACCESSES", asset_id),
            (asset_id, "STORED_AT", endpoint_id),
            (agent_id, "AUTHORIZED_FOR", endpoint_id),
        ]:
            if (frm, rel, to) not in self._edges:
                self._edges.append((frm, rel, to))

        return endpoint_id
