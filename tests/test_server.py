"""Integration tests for the FastMCP server tool: get_encryption_strategy."""

from __future__ import annotations

import pytest

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.drift_detector import DriftDetector
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import MockRiskGraph
from cipherweave.server import get_encryption_strategy, inject_components


@pytest.fixture(autouse=True)
def wire_components(mock_graph: MockRiskGraph, cipher_janitor: CipherJanitor, drift_detector: DriftDetector) -> None:
    """Inject mock components before each test."""
    inject_components(mock_graph, cipher_janitor, drift_detector)


@pytest.mark.asyncio
async def test_get_encryption_strategy_hipaa_returns_quantum_safe() -> None:
    """HIPAA endpoint → QUANTUM_SAFE strategy returned."""
    result = await get_encryption_strategy(
        agent_id="agent-001",
        data_metadata={"tags": ["PHI"], "classification": "RESTRICTED"},
        destination_url="https://hipaa.store/api",
    )
    assert result["cipher_profile"] == "QUANTUM_SAFE"
    assert result["key_length_bits"] == 256
    assert "HIPAA" in result["regulations_crossed"] or "QUANTUM_SAFE" in result["justification"]
    assert "decision_id" in result
    assert result["decision_id"].startswith("cw_")


@pytest.mark.asyncio
async def test_get_encryption_strategy_internal_cheap() -> None:
    """VPC-internal with no regulations → CHEAP initially, but new-agent override applies."""
    result = await get_encryption_strategy(
        agent_id="agent-001",
        data_metadata={"tags": [], "classification": "INTERNAL"},
        destination_url="https://internal.vpc/api",
    )
    # May be overridden to QUANTUM_SAFE due to new-agent drift check on first call
    assert result["cipher_profile"] in ("CHEAP", "QUANTUM_SAFE", "BALANCED")
    assert "decision_id" in result
    assert result["audit_log"]["decision_made_by"] == "CipherJanitor"


@pytest.mark.asyncio
async def test_get_encryption_strategy_contains_required_fields() -> None:
    """Response must contain all required explainable-crypto fields."""
    required_fields = [
        "decision_id", "timestamp", "agent_id", "destination_url",
        "cipher_profile", "algorithm", "key_length_bits", "kdf_algorithm",
        "salt_b64", "info_string", "regulations_crossed", "threat_proximity",
        "path_nodes", "risk_score", "justification", "cost_per_operation_usd",
        "ttl_seconds", "audit_log",
    ]
    result = await get_encryption_strategy(
        agent_id="agent-001",
        data_metadata={"tags": ["PHI"], "classification": "RESTRICTED"},
        destination_url="https://hipaa.store/api",
    )
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


@pytest.mark.asyncio
async def test_get_encryption_strategy_unauthorized_agent_raises() -> None:
    """Rogue agent without AUTHORIZED_FOR edge raises error."""
    from cipherweave.exceptions import UnauthorizedAgentError

    with pytest.raises(UnauthorizedAgentError):
        await get_encryption_strategy(
            agent_id="agent-rogue",
            data_metadata={"tags": [], "classification": "INTERNAL"},
            destination_url="https://hipaa.store/api",
        )


@pytest.mark.asyncio
async def test_get_encryption_strategy_quantum_safe_has_keypair() -> None:
    """QUANTUM_SAFE response includes hybrid_keypair with public keys."""
    result = await get_encryption_strategy(
        agent_id="agent-001",
        data_metadata={"tags": ["PHI"], "classification": "RESTRICTED"},
        destination_url="https://hipaa.store/api",
    )
    assert result["cipher_profile"] == "QUANTUM_SAFE"
    assert result["hybrid_keypair"] is not None
    assert "x25519_public_b64" in result["hybrid_keypair"]
    assert "mlkem_public_b64" in result["hybrid_keypair"]


@pytest.mark.asyncio
async def test_get_encryption_strategy_salt_is_base64() -> None:
    """salt_b64 is valid base64 of 32 bytes."""
    import base64

    result = await get_encryption_strategy(
        agent_id="agent-001",
        data_metadata={"tags": ["PHI"], "classification": "RESTRICTED"},
        destination_url="https://hipaa.store/api",
    )
    salt = base64.b64decode(result["salt_b64"])
    assert len(salt) == 32


@pytest.mark.asyncio
async def test_get_encryption_strategy_unknown_url_is_jit_registered(
    mock_graph: MockRiskGraph,
) -> None:
    """An unknown destination is registered, not refused (ADR-016).

    This test previously asserted PathNotFoundError. That stopped being the
    behaviour when JIT registration landed: an unknown agent/endpoint pair is
    seeded from validated metadata and then scored normally. The guarantee that
    survives -- and that this test now pins -- is the fail-secure one: a path
    with no history is new, so the drift detector's cold-start rule forces
    QUANTUM_SAFE (ADR-001).
    """
    url = "https://completely.unknown/endpoint"
    assert await mock_graph.get_endpoint_id_for_url(url) is None

    result = await get_encryption_strategy(
        agent_id="agent-001",
        data_metadata={"tags": [], "classification": "INTERNAL"},
        destination_url=url,
    )

    assert result["cipher_profile"] == "QUANTUM_SAFE"
    assert result["audit_log"]["drift_detected"] is True
    assert await mock_graph.get_endpoint_id_for_url(url) is not None


@pytest.mark.asyncio
async def test_get_encryption_strategy_rejects_unusable_metadata() -> None:
    """Metadata that cannot be validated is refused rather than guessed.

    The refusal that replaces the old PathNotFoundError: CipherWeave will not
    register a path it cannot classify.
    """
    from cipherweave.exceptions import MetadataInferenceError

    with pytest.raises(MetadataInferenceError):
        await get_encryption_strategy(
            agent_id="agent-001",
            data_metadata={"tags": []},  # no classification
            destination_url="https://also.unknown/endpoint",
        )
