"""Module 1: Topological Risk Engine — graph-based path risk scoring via Memgraph."""

from __future__ import annotations

import logging
from typing import Any

from cipherweave.exceptions import GraphConnectionError, PathNotFoundError, UnauthorizedAgentError
from cipherweave.models import PathRiskResult
from cipherweave.profiles import CipherProfile

logger = logging.getLogger(__name__)

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
    """Graph-based path risk scoring using Memgraph (Bolt/Cypher)."""

    def __init__(self, memgraph_host: str = "localhost", memgraph_port: int = 7687) -> None:
        self._host = memgraph_host
        self._port = memgraph_port
        self._conn: Any = None  # neo4j/mgclient driver connection

    async def connect(self) -> None:
        """Open a Bolt connection to Memgraph."""
        try:
            import mgclient  # type: ignore[import]

            self._conn = mgclient.connect(host=self._host, port=self._port)
            logger.info("Connected to Memgraph at %s:%s", self._host, self._port)
        except Exception as exc:
            raise GraphConnectionError(
                f"Cannot connect to Memgraph at {self._host}:{self._port}: {exc}"
            ) from exc

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _execute(self, query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Run a Cypher query and return rows as dicts."""
        if self._conn is None:
            raise GraphConnectionError("Not connected to Memgraph. Call connect() first.")
        cursor = self._conn.cursor()
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
                self._execute(stmt)
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
        ep_rows = self._execute(
            "MATCH (e:Endpoint {url: $url}) RETURN e.endpoint_id AS endpoint_id, e.vpc_internal AS vpc_internal",
            {"url": destination_url},
        )
        if not ep_rows:
            raise PathNotFoundError(agent_id, destination_url)
        endpoint_id = ep_rows[0]["endpoint_id"]
        vpc_internal = bool(ep_rows[0].get("vpc_internal", False))

        # 2. Find DataAssets accessed by this agent that are stored at this endpoint
        asset_rows = self._execute(
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
        reg_rows = self._execute(
            """
            MATCH (a:Agent {agent_id: $agent_id})-[:ACCESSES]->(d:DataAsset)-[:GOVERNED_BY]->(r:Regulation)
            WHERE EXISTS { (d)-[:STORED_AT]->(:Endpoint {endpoint_id: $ep_id}) }
            RETURN DISTINCT r.name AS reg_name
            """,
            {"agent_id": agent_id, "ep_id": endpoint_id},
        )
        regulations = [row["reg_name"] for row in reg_rows]

        # 4. Find shortest threat proximity (hops from endpoint to nearest ThreatIndicator)
        threat_rows = self._execute(
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
        rows = self._execute(
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
        rows = self._execute(
            "MATCH (e:Endpoint {url: $url}) RETURN e.endpoint_id AS endpoint_id",
            {"url": url},
        )
        return rows[0]["endpoint_id"] if rows else None

    async def agent_exists(self, agent_id: str) -> bool:
        rows = self._execute(
            "MATCH (a:Agent {agent_id: $agent_id}) RETURN count(*) AS cnt",
            {"agent_id": agent_id},
        )
        return bool(rows and rows[0]["cnt"] > 0)


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
