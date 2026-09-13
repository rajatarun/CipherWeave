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
from cipherweave.exceptions import (  # noqa: F401 — re-exported so FastMCP surfaces them as tool errors
    CipherWeaveError,
    MetadataInferenceError,
    PathNotFoundError,
    UnauthorizedAgentError,
)
from cipherweave.gate_integration import decide_profile
from cipherweave.models import EncryptionStrategy
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import RiskGraph

logger = logging.getLogger(__name__)

mcp = fastmcp.FastMCP("CipherWeave")

# Module singletons — initialized in main()
_risk_graph: RiskGraph | None = None
_cipher_janitor: CipherJanitor | None = None
_drift_detector: DriftDetector | None = None
_bedrock_client: object | None = None  # boto3 bedrock-runtime client; None in local dev


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

    # Steps 1-3 — endpoint resolution (JIT-registering an unknown one), authorization,
    # Eq. 1/2 aggregation with the compliance floor, and the drift override, joined
    # over the profile lattice. This is the same call the propose-time gate client
    # makes (`gate_integration.required_profile`), so a channel the gate binds can
    # never be weaker than the one this tool would have issued for the same flow.
    decision = await decide_profile(
        agent_id=agent_id,
        destination_url=destination_url,
        data_metadata=data_metadata,
        risk_graph=_risk_graph,
        drift_detector=_drift_detector,
        bedrock_client=_bedrock_client,
    )
    endpoint_id = decision.endpoint_id or ""
    final_profile = decision.profile
    is_anomalous = decision.drift_detected
    alert = decision.alert

    # Step 4: Derive HKDF key
    salt = os.urandom(32)
    info_string = _build_info_string(agent_id, endpoint_id, list(decision.path_nodes))
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
        risk_score=decision.risk_score,
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
        regulations_crossed=list(decision.regulations_crossed),
        threat_proximity=decision.threat_proximity,
        path_nodes=list(decision.path_nodes),
        risk_score=decision.risk_score,
        justification=decision.justification,
        cost_per_operation_usd=final_profile.cost_per_operation_usd(),
        ttl_seconds=final_profile.ttl_seconds(),
        hybrid_keypair=hybrid_public,
        audit_log={
            "decision_made_by": "CipherJanitor",
            "drift_detected": is_anomalous,
            "override_applied": is_anomalous,
            "alert_id": alert.alert_id if alert else None,
            "alert_type": alert.alert_type if alert else None,
            "latency_ms": round(elapsed_ms, 3),
            "decision_id": decision_id,
        },
    )

    return strategy.model_dump(mode="json")


async def _init_components() -> None:
    """Initialize all module singletons."""
    global _risk_graph, _cipher_janitor, _drift_detector, _bedrock_client

    # Risk graph
    _risk_graph = RiskGraph(
        memgraph_host=settings.memgraph_host,
        memgraph_port=settings.memgraph_port,
    )
    await _risk_graph.connect()
    await _risk_graph.initialize_schema()

    # AWS clients (production only)
    kms_client = None
    if not settings.use_local_kms and settings.kms_key_id:
        import boto3
        kms_client = boto3.client("kms", region_name=settings.aws_region)
        _bedrock_client = boto3.client("bedrock-runtime", region_name=settings.aws_region)
        logger.info("Bedrock policy inference enabled (model=%s)", settings.bedrock_inference_model_id)

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
    bedrock_client: object | None = None,
) -> None:
    """Inject pre-built components (used in Lambda handler and tests)."""
    global _risk_graph, _cipher_janitor, _drift_detector, _bedrock_client
    _risk_graph = risk_graph
    _cipher_janitor = cipher_janitor
    _drift_detector = drift_detector
    _bedrock_client = bedrock_client


async def main() -> None:
    logging.basicConfig(level=settings.log_level)
    await _init_components()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
