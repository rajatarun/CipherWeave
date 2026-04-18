"""Module 3: FastMCP 3.0 Server — single tool: get_encryption_strategy."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import time
import uuid
from datetime import datetime

import fastmcp

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.config import settings
from cipherweave.drift_detector import DriftDetector
from cipherweave.exceptions import (
    CipherWeaveError,
    PathNotFoundError,
    UnauthorizedAgentError,
)
from cipherweave.models import EncryptionStrategy
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import RiskGraph

logger = logging.getLogger(__name__)

mcp = fastmcp.FastMCP("CipherWeave")

# Module singletons — initialized in main()
_risk_graph: RiskGraph | None = None
_cipher_janitor: CipherJanitor | None = None
_drift_detector: DriftDetector | None = None


def _build_info_string(
    agent_id: str,
    endpoint_id: str,
    path_nodes: list[str],
) -> str:
    """Build a deterministic, context-bound HKDF info string."""
    path_hash = hashlib.sha256(":".join(path_nodes).encode()).hexdigest()[:16]
    ts = int(time.time())
    return f"cipherweave:v1:{agent_id}:{endpoint_id}:{path_hash}:{ts}"


def _make_decision_id() -> str:
    return f"cw_{uuid.uuid4().hex[:8]}"


@mcp.tool()
async def get_encryption_strategy(
    agent_id: str,
    data_metadata: dict,
    destination_url: str,
) -> dict:
    """Return an explainable encryption strategy for an agent sending data to an endpoint.

    Args:
        agent_id: Unique identifier of the requesting agent.
        data_metadata: Dict with keys "tags" (list[str]) and "classification" (str).
        destination_url: Target endpoint URL.

    Returns:
        Explainable JSON dict with cipher profile, algorithm, key material info, and audit log.
    """
    assert _risk_graph is not None, "RiskGraph not initialized"
    assert _cipher_janitor is not None, "CipherJanitor not initialized"
    assert _drift_detector is not None, "DriftDetector not initialized"

    start_ns = time.monotonic_ns()
    decision_id = _make_decision_id()
    data_tags: list[str] = data_metadata.get("tags", [])

    # Step 1: Validate agent exists and is authorized for destination endpoint
    endpoint_id = await _risk_graph.get_endpoint_id_for_url(destination_url)
    if endpoint_id is None:
        raise PathNotFoundError(agent_id, destination_url)

    try:
        await _risk_graph.validate_agent_authorization(agent_id, endpoint_id)
    except UnauthorizedAgentError:
        raise

    # Step 2: Graph path risk
    path_risk = await _risk_graph.get_path_risk(agent_id, destination_url, data_tags)

    # Step 3: Drift detection
    is_anomalous, alert = await _drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=path_risk.recommended_profile,
        data_tags=data_tags,
        endpoint_id=endpoint_id,
    )

    # Apply fail-secure override if anomalous
    final_profile = (
        CipherProfile.QUANTUM_SAFE
        if is_anomalous
        else path_risk.recommended_profile
    )
    override_applied = is_anomalous

    # Step 4: Derive HKDF key
    salt = os.urandom(32)
    info_string = _build_info_string(agent_id, endpoint_id, path_risk.path_nodes)
    info_bytes = info_string.encode()

    msk = await _cipher_janitor.get_master_secret()
    with _cipher_janitor.secure_context():
        _cipher_janitor.register_buffer(msk)
        derived = _cipher_janitor.derive_key(msk, salt, info_bytes, final_profile)

    # Step 5: Generate hybrid keypair for QUANTUM_SAFE
    hybrid_public: dict | None = None
    if final_profile == CipherProfile.QUANTUM_SAFE:
        keypair = _cipher_janitor.generate_hybrid_keypair()
        hybrid_public = keypair.as_public_dict()

    # Log decision for drift tracking
    await _drift_detector.log_decision(
        agent_id=agent_id,
        profile=final_profile,
        endpoint_id=endpoint_id,
        risk_score=path_risk.risk_score,
    )

    elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000
    if elapsed_ms > 10:
        logger.warning(
            "get_encryption_strategy latency %.2fms exceeded 10ms budget for agent %s",
            elapsed_ms,
            agent_id,
        )

    strategy = EncryptionStrategy(
        decision_id=decision_id,
        timestamp=datetime.utcnow(),
        agent_id=agent_id,
        destination_url=destination_url,
        cipher_profile=final_profile,
        algorithm=final_profile.algorithm_label(),
        key_length_bits=final_profile.key_length_bits(),
        kdf_algorithm=final_profile.kdf_label(),
        salt_b64=base64.b64encode(salt).decode(),
        info_string=info_string,
        regulations_crossed=path_risk.regulations_crossed,
        threat_proximity=path_risk.threat_proximity,
        path_nodes=path_risk.path_nodes,
        risk_score=path_risk.risk_score,
        justification=(
            f"[DRIFT OVERRIDE] {path_risk.justification}"
            if override_applied and not is_anomalous
            else (
                f"[ANOMALY DETECTED — QUANTUM_SAFE enforced] {path_risk.justification}"
                if override_applied
                else path_risk.justification
            )
        ),
        cost_per_operation_usd=final_profile.cost_per_operation_usd(),
        ttl_seconds=final_profile.ttl_seconds(),
        hybrid_keypair=hybrid_public,
        audit_log={
            "decision_made_by": "CipherJanitor",
            "drift_detected": is_anomalous,
            "override_applied": override_applied,
            "alert_id": alert.alert_id if alert else None,
            "alert_type": alert.alert_type if alert else None,
            "latency_ms": round(elapsed_ms, 3),
            "decision_id": decision_id,
        },
    )

    return strategy.model_dump(mode="json")


async def _init_components() -> None:
    """Initialize all module singletons."""
    global _risk_graph, _cipher_janitor, _drift_detector

    # Risk graph
    _risk_graph = RiskGraph(
        memgraph_host=settings.memgraph_host,
        memgraph_port=settings.memgraph_port,
    )
    await _risk_graph.connect()
    await _risk_graph.initialize_schema()

    # KMS client
    kms_client = None
    if not settings.use_local_kms and settings.kms_key_id:
        import boto3

        kms_client = boto3.client("kms", region_name=settings.aws_region)

    _cipher_janitor = CipherJanitor(
        kms_client=kms_client,
        master_key_id=settings.kms_key_id,
    )

    # Drift detector
    _drift_detector = DriftDetector(window_size=settings.drift_window_size)

    logger.info("CipherWeave components initialized")


def inject_components(
    risk_graph: RiskGraph,
    cipher_janitor: CipherJanitor,
    drift_detector: DriftDetector,
) -> None:
    """Inject pre-built components (used in tests)."""
    global _risk_graph, _cipher_janitor, _drift_detector
    _risk_graph = risk_graph
    _cipher_janitor = cipher_janitor
    _drift_detector = drift_detector


async def main() -> None:
    logging.basicConfig(level=settings.log_level)
    await _init_components()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
