"""CloudFormation Custom Resource Lambda — seeds Memgraph with CipherWeave topology.

Invoked automatically on every SAM deploy via the SeedGraphOnDeploy Custom Resource.
Can also be invoked manually:
    aws lambda invoke --function-name cipherweave-seed-graph-prod \
        --payload '{"RequestType":"Create"}' /tmp/out.json

The handler is idempotent: uses MERGE so re-runs are safe.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("CIPHERWEAVE_LOG_LEVEL", "INFO"))

# ---------------------------------------------------------------------------
# Topology: mirrors scripts/seed_graph.py but uses neo4j async driver
# ---------------------------------------------------------------------------
_CYPHER_STATEMENTS = [
    # Agents
    "MERGE (:Agent {agent_id: 'agent-analytics', name: 'AnalyticsBot', trust_level: 'MEDIUM'});",
    "MERGE (:Agent {agent_id: 'agent-reporting', name: 'ReportingBot', trust_level: 'HIGH'});",
    "MERGE (:Agent {agent_id: 'agent-internal', name: 'InternalService', trust_level: 'HIGH'});",
    "MERGE (:Agent {agent_id: 'agent-ml-pipeline', name: 'MLPipeline', trust_level: 'MEDIUM'});",

    # Data assets
    "MERGE (:DataAsset {asset_id: 'asset-patient-records', classification: 'RESTRICTED', tags: ['PHI', 'PII']});",
    "MERGE (:DataAsset {asset_id: 'asset-financial-reports', classification: 'CONFIDENTIAL', tags: ['PCI']});",
    "MERGE (:DataAsset {asset_id: 'asset-internal-metrics', classification: 'INTERNAL', tags: []});",
    "MERGE (:DataAsset {asset_id: 'asset-public-docs', classification: 'PUBLIC', tags: []});",
    "MERGE (:DataAsset {asset_id: 'asset-trade-secrets', classification: 'TOP_SECRET', tags: ['TRADE_SECRET']});",

    # Endpoints — using the real stack's API endpoint where applicable
    "MERGE (:Endpoint {endpoint_id: 'ep-ehr-system', url: 'https://ehr.hospital/api', region: 'us-east-1', vpc_internal: false});",
    "MERGE (:Endpoint {endpoint_id: 'ep-finance-db', url: 'https://finance.corp/db', region: 'eu-west-1', vpc_internal: false});",
    "MERGE (:Endpoint {endpoint_id: 'ep-metrics-vpc', url: 'https://metrics.internal/api', region: 'us-east-1', vpc_internal: true});",
    "MERGE (:Endpoint {endpoint_id: 'ep-cdn', url: 'https://cdn.public/assets', region: 'us-east-1', vpc_internal: false});",
    "MERGE (:Endpoint {endpoint_id: 'ep-contextweave-api', url: 'https://56u86rj4qk.execute-api.us-east-1.amazonaws.com/prod', region: 'us-east-1', vpc_internal: false});",

    # Regulations
    "MERGE (:Regulation {reg_id: 'reg-hipaa', name: 'HIPAA', cipher_floor: 'QUANTUM_SAFE'});",
    "MERGE (:Regulation {reg_id: 'reg-gdpr', name: 'GDPR', cipher_floor: 'HARDENED'});",
    "MERGE (:Regulation {reg_id: 'reg-pci', name: 'PCI_DSS_4', cipher_floor: 'HARDENED'});",
    "MERGE (:Regulation {reg_id: 'reg-sox', name: 'SOX', cipher_floor: 'HARDENED'});",

    # Threat indicators
    "MERGE (:ThreatIndicator {indicator_id: 'threat-apt-group', severity: 'CRITICAL', ttl_hours: 48});",

    # ── Edges ──────────────────────────────────────────────────────────────
    # Agent → DataAsset (ACCESSES)
    """MATCH (a:Agent {agent_id: 'agent-analytics'}), (d:DataAsset {asset_id: 'asset-patient-records'})
       MERGE (a)-[:ACCESSES]->(d);""",
    """MATCH (a:Agent {agent_id: 'agent-reporting'}), (d:DataAsset {asset_id: 'asset-financial-reports'})
       MERGE (a)-[:ACCESSES]->(d);""",
    """MATCH (a:Agent {agent_id: 'agent-internal'}), (d:DataAsset {asset_id: 'asset-internal-metrics'})
       MERGE (a)-[:ACCESSES]->(d);""",
    """MATCH (a:Agent {agent_id: 'agent-ml-pipeline'}), (d:DataAsset {asset_id: 'asset-trade-secrets'})
       MERGE (a)-[:ACCESSES]->(d);""",

    # DataAsset → Endpoint (STORED_AT)
    """MATCH (d:DataAsset {asset_id: 'asset-patient-records'}), (e:Endpoint {endpoint_id: 'ep-ehr-system'})
       MERGE (d)-[:STORED_AT]->(e);""",
    """MATCH (d:DataAsset {asset_id: 'asset-financial-reports'}), (e:Endpoint {endpoint_id: 'ep-finance-db'})
       MERGE (d)-[:STORED_AT]->(e);""",
    """MATCH (d:DataAsset {asset_id: 'asset-internal-metrics'}), (e:Endpoint {endpoint_id: 'ep-metrics-vpc'})
       MERGE (d)-[:STORED_AT]->(e);""",
    """MATCH (d:DataAsset {asset_id: 'asset-trade-secrets'}), (e:Endpoint {endpoint_id: 'ep-contextweave-api'})
       MERGE (d)-[:STORED_AT]->(e);""",

    # DataAsset → Regulation (GOVERNED_BY)
    """MATCH (d:DataAsset {asset_id: 'asset-patient-records'}), (r:Regulation {reg_id: 'reg-hipaa'})
       MERGE (d)-[:GOVERNED_BY]->(r);""",
    """MATCH (d:DataAsset {asset_id: 'asset-financial-reports'}), (r:Regulation {reg_id: 'reg-gdpr'})
       MERGE (d)-[:GOVERNED_BY]->(r);""",
    """MATCH (d:DataAsset {asset_id: 'asset-financial-reports'}), (r:Regulation {reg_id: 'reg-pci'})
       MERGE (d)-[:GOVERNED_BY]->(r);""",
    """MATCH (d:DataAsset {asset_id: 'asset-financial-reports'}), (r:Regulation {reg_id: 'reg-sox'})
       MERGE (d)-[:GOVERNED_BY]->(r);""",

    # Endpoint → ThreatIndicator (EXPOSED_TO)
    """MATCH (e:Endpoint {endpoint_id: 'ep-cdn'}), (t:ThreatIndicator {indicator_id: 'threat-apt-group'})
       MERGE (e)-[:EXPOSED_TO]->(t);""",

    # Agent → Endpoint (AUTHORIZED_FOR)
    """MATCH (a:Agent {agent_id: 'agent-analytics'}), (e:Endpoint {endpoint_id: 'ep-ehr-system'})
       MERGE (a)-[:AUTHORIZED_FOR]->(e);""",
    """MATCH (a:Agent {agent_id: 'agent-reporting'}), (e:Endpoint {endpoint_id: 'ep-finance-db'})
       MERGE (a)-[:AUTHORIZED_FOR]->(e);""",
    """MATCH (a:Agent {agent_id: 'agent-internal'}), (e:Endpoint {endpoint_id: 'ep-metrics-vpc'})
       MERGE (a)-[:AUTHORIZED_FOR]->(e);""",
    """MATCH (a:Agent {agent_id: 'agent-ml-pipeline'}), (e:Endpoint {endpoint_id: 'ep-contextweave-api'})
       MERGE (a)-[:AUTHORIZED_FOR]->(e);""",
]


def _seed_graph() -> dict[str, Any]:
    """Connect to Memgraph and execute all MERGE statements. Returns result dict."""
    host = os.environ.get("CIPHERWEAVE_MEMGRAPH_HOST", "172.31.12.134")
    port = int(os.environ.get("CIPHERWEAVE_MEMGRAPH_PORT", "7687"))

    try:
        from neo4j import GraphDatabase  # type: ignore[import]
    except ImportError:
        return {"status": "error", "message": "neo4j driver not installed in Lambda layer"}

    driver = GraphDatabase.driver(
        f"bolt://{host}:{port}",
        auth=None,
        encrypted=False,
    )

    ok_count = 0
    skip_count = 0
    errors: list[str] = []

    with driver.session() as session:
        for stmt in _CYPHER_STATEMENTS:
            stmt = stmt.strip()
            if not stmt:
                continue
            try:
                session.run(stmt)
                ok_count += 1
                logger.debug("MERGE OK: %s", stmt[:60].replace("\n", " "))
            except Exception as exc:
                skip_count += 1
                errors.append(f"{exc}: {stmt[:60]}")
                logger.warning("MERGE SKIP: %s — %s", stmt[:60].replace("\n", " "), exc)

    driver.close()

    result = {
        "status": "success" if not errors else "partial",
        "statements_executed": ok_count,
        "statements_skipped": skip_count,
        "host": f"{host}:{port}",
    }
    if errors:
        result["errors"] = errors[:5]  # cap to avoid oversized response
    logger.info("Seed complete: %s", result)
    return result


def _cfn_send(event: dict, context: Any, status: str, data: dict, reason: str = "") -> None:
    """Send response to CloudFormation pre-signed URL."""
    response_url = event.get("ResponseURL")
    if not response_url:
        return

    body = json.dumps({
        "Status": status,
        "Reason": reason or f"See CloudWatch: {context.log_stream_name}",
        "PhysicalResourceId": event.get("PhysicalResourceId", "cipherweave-seed-graph"),
        "StackId": event.get("StackId", ""),
        "RequestId": event.get("RequestId", ""),
        "LogicalResourceId": event.get("LogicalResourceId", ""),
        "Data": data,
    }).encode("utf-8")

    req = urllib.request.Request(
        response_url,
        data=body,
        method="PUT",
        headers={"Content-Type": ""},
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as exc:
        logger.error("Failed to send CFN response: %s", exc)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for both CloudFormation Custom Resource and direct invocation."""
    request_type = event.get("RequestType", "Invoke")
    logger.info("SeedGraph invoked: RequestType=%s", request_type)

    # CloudFormation Delete event — do nothing (keep graph data)
    if request_type == "Delete":
        _cfn_send(event, context, "SUCCESS", {"message": "Delete: no graph changes"})
        return {"status": "no-op", "requestType": "Delete"}

    try:
        result = _seed_graph()
        if event.get("ResponseURL"):
            _cfn_send(event, context, "SUCCESS", result)
        return result
    except Exception as exc:
        logger.exception("Seed graph failed: %s", exc)
        if event.get("ResponseURL"):
            _cfn_send(event, context, "FAILED", {}, reason=str(exc))
        raise
