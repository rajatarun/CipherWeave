"""Seed Memgraph with a demo topology for CipherWeave.

Local (Docker):
    docker-compose up -d
    uv run python scripts/seed_graph.py

Against live Memgraph EC2 (requires VPN or SSH tunnel to 172.31.12.134:7687):
    uv run python scripts/seed_graph.py --host 172.31.12.134

Uses neo4j driver (pure-Python) when available; falls back to mgclient.
"""

from __future__ import annotations

import logging
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CYPHER_STATEMENTS = [
    # Agents
    "MERGE (:Agent {agent_id: 'agent-analytics', name: 'AnalyticsBot', trust_level: 'MEDIUM'});",
    "MERGE (:Agent {agent_id: 'agent-reporting', name: 'ReportingBot', trust_level: 'HIGH'});",
    "MERGE (:Agent {agent_id: 'agent-internal', name: 'InternalService', trust_level: 'HIGH'});",
    # Data assets
    "MERGE (:DataAsset {asset_id: 'asset-patient-records', classification: 'RESTRICTED', tags: ['PHI', 'PII']});",
    "MERGE (:DataAsset {asset_id: 'asset-financial-reports', classification: 'CONFIDENTIAL', tags: ['PCI']});",
    "MERGE (:DataAsset {asset_id: 'asset-internal-metrics', classification: 'INTERNAL', tags: []});",
    "MERGE (:DataAsset {asset_id: 'asset-public-docs', classification: 'PUBLIC', tags: []});",
    # Endpoints — includes the live contextweave-rag-prod API (from CFN outputs)
    "MERGE (:Endpoint {endpoint_id: 'ep-ehr-system', url: 'https://ehr.hospital/api', region: 'us-east-1', vpc_internal: false});",
    "MERGE (:Endpoint {endpoint_id: 'ep-finance-db', url: 'https://finance.corp/db', region: 'eu-west-1', vpc_internal: false});",
    "MERGE (:Endpoint {endpoint_id: 'ep-metrics-vpc', url: 'https://metrics.internal/api', region: 'us-east-1', vpc_internal: true});",
    "MERGE (:Endpoint {endpoint_id: 'ep-cdn', url: 'https://cdn.public/assets', region: 'us-east-1', vpc_internal: false});",
    "MERGE (:Endpoint {endpoint_id: 'ep-contextweave-api', url: 'https://56u86rj4qk.execute-api.us-east-1.amazonaws.com/prod', region: 'us-east-1', vpc_internal: false});",
    "MERGE (:Endpoint {endpoint_id: 'ep-query-expertise', url: 'https://56u86rj4qk.execute-api.us-east-1.amazonaws.com/prod/query-expertise', region: 'us-east-1', vpc_internal: false});",
    # Regulations
    "MERGE (:Regulation {reg_id: 'reg-hipaa', name: 'HIPAA', cipher_floor: 'QUANTUM_SAFE'});",
    "MERGE (:Regulation {reg_id: 'reg-gdpr', name: 'GDPR', cipher_floor: 'HARDENED'});",
    "MERGE (:Regulation {reg_id: 'reg-pci', name: 'PCI_DSS_4', cipher_floor: 'HARDENED'});",
    # Threat indicators
    "MERGE (:ThreatIndicator {indicator_id: 'threat-apt-group', severity: 'CRITICAL', ttl_hours: 48});",
    # Edges: Agent → DataAsset (ACCESSES)
    """
    MATCH (a:Agent {agent_id: 'agent-analytics'}), (d:DataAsset {asset_id: 'asset-patient-records'})
    MERGE (a)-[:ACCESSES]->(d);
    """,
    """
    MATCH (a:Agent {agent_id: 'agent-reporting'}), (d:DataAsset {asset_id: 'asset-financial-reports'})
    MERGE (a)-[:ACCESSES]->(d);
    """,
    """
    MATCH (a:Agent {agent_id: 'agent-internal'}), (d:DataAsset {asset_id: 'asset-internal-metrics'})
    MERGE (a)-[:ACCESSES]->(d);
    """,
    # Edges: DataAsset → Endpoint (STORED_AT)
    """
    MATCH (d:DataAsset {asset_id: 'asset-patient-records'}), (e:Endpoint {endpoint_id: 'ep-ehr-system'})
    MERGE (d)-[:STORED_AT]->(e);
    """,
    """
    MATCH (d:DataAsset {asset_id: 'asset-financial-reports'}), (e:Endpoint {endpoint_id: 'ep-finance-db'})
    MERGE (d)-[:STORED_AT]->(e);
    """,
    """
    MATCH (d:DataAsset {asset_id: 'asset-internal-metrics'}), (e:Endpoint {endpoint_id: 'ep-metrics-vpc'})
    MERGE (d)-[:STORED_AT]->(e);
    """,
    # Edges: DataAsset → Regulation (GOVERNED_BY)
    """
    MATCH (d:DataAsset {asset_id: 'asset-patient-records'}), (r:Regulation {reg_id: 'reg-hipaa'})
    MERGE (d)-[:GOVERNED_BY]->(r);
    """,
    """
    MATCH (d:DataAsset {asset_id: 'asset-financial-reports'}), (r:Regulation {reg_id: 'reg-gdpr'})
    MERGE (d)-[:GOVERNED_BY]->(r);
    """,
    """
    MATCH (d:DataAsset {asset_id: 'asset-financial-reports'}), (r:Regulation {reg_id: 'reg-pci'})
    MERGE (d)-[:GOVERNED_BY]->(r);
    """,
    # Edges: Endpoint → ThreatIndicator (EXPOSED_TO)
    """
    MATCH (e:Endpoint {endpoint_id: 'ep-cdn'}), (t:ThreatIndicator {indicator_id: 'threat-apt-group'})
    MERGE (e)-[:EXPOSED_TO]->(t);
    """,
    # Edges: Agent → Endpoint (AUTHORIZED_FOR)
    """
    MATCH (a:Agent {agent_id: 'agent-analytics'}), (e:Endpoint {endpoint_id: 'ep-ehr-system'})
    MERGE (a)-[:AUTHORIZED_FOR]->(e);
    """,
    """
    MATCH (a:Agent {agent_id: 'agent-reporting'}), (e:Endpoint {endpoint_id: 'ep-finance-db'})
    MERGE (a)-[:AUTHORIZED_FOR]->(e);
    """,
    """
    MATCH (a:Agent {agent_id: 'agent-internal'}), (e:Endpoint {endpoint_id: 'ep-metrics-vpc'})
    MERGE (a)-[:AUTHORIZED_FOR]->(e);
    """,
]


def seed(host: str = "localhost", port: int = 7687) -> None:
    """Seed Memgraph using neo4j driver (preferred) or mgclient fallback."""
    # Try neo4j driver first (pure-Python, no compilation needed)
    try:
        from neo4j import GraphDatabase  # type: ignore[import]

        driver = GraphDatabase.driver(
            f"bolt://{host}:{port}",
            auth=None,
            encrypted=False,
        )
        with driver.session() as session:
            for stmt in CYPHER_STATEMENTS:
                stmt = stmt.strip()
                if not stmt:
                    continue
                try:
                    session.run(stmt)
                    logger.info("OK (neo4j): %s", stmt[:60].replace("\n", " "))
                except Exception as exc:
                    logger.warning("SKIP (%s): %s", exc, stmt[:60].replace("\n", " "))
        driver.close()
        logger.info("Seed complete (neo4j driver).")
        return
    except ImportError:
        logger.info("neo4j not installed, trying mgclient...")

    # Fallback: mgclient
    try:
        import mgclient  # type: ignore[import]
    except ImportError:
        logger.error("Neither neo4j nor mgclient installed. Run: pip install neo4j")
        sys.exit(1)

    conn = mgclient.connect(host=host, port=port)
    cursor = conn.cursor()
    for stmt in CYPHER_STATEMENTS:
        stmt = stmt.strip()
        if not stmt:
            continue
        try:
            cursor.execute(stmt)
            conn.commit()
            logger.info("OK (mgclient): %s", stmt[:60].replace("\n", " "))
        except Exception as exc:
            logger.warning("SKIP (%s): %s", exc, stmt[:60].replace("\n", " "))
    conn.close()
    logger.info("Seed complete (mgclient).")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Seed Memgraph with CipherWeave demo topology")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=7687)
    args = parser.parse_args()
    seed(host=args.host, port=args.port)
