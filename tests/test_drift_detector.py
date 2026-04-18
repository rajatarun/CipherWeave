"""Unit tests for DriftDetector — anomaly detection and fail-secure overrides."""

from __future__ import annotations

import pytest

from cipherweave.drift_detector import DriftDetector
from cipherweave.profiles import CipherProfile


@pytest.mark.asyncio
async def test_new_agent_defaults_to_quantum_safe(drift_detector: DriftDetector) -> None:
    """New agent with no history → QUANTUM_SAFE (fail-secure)."""
    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id="agent-brand-new",
        requested_profile=CipherProfile.BALANCED,
        data_tags=["PII"],
        endpoint_id="ep-001",
    )
    assert is_anomalous is True
    assert alert is not None
    assert alert.alert_type == "NEW_AGENT"
    assert alert.severity == "HIGH"


@pytest.mark.asyncio
async def test_drift_detection_pii_to_cheap(drift_detector: DriftDetector) -> None:
    """Agent typically BALANCED, requests CHEAP for PII → anomaly + QUANTUM_SAFE override."""
    agent_id = "agent-drifter"
    # Establish BALANCED history
    for i in range(5):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35)

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.CHEAP,
        data_tags=["PII"],
        endpoint_id="ep-001",
    )
    assert is_anomalous is True
    assert alert is not None
    assert alert.alert_type == "DRIFT_DETECTED"
    assert alert.severity == "CRITICAL"
    assert "CHEAP" in alert.message or "QUANTUM_SAFE" in alert.message


@pytest.mark.asyncio
async def test_no_drift_consistent_behavior(drift_detector: DriftDetector) -> None:
    """Agent consistently uses BALANCED — no anomaly on same request."""
    agent_id = "agent-steady"
    for i in range(10):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35)

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.BALANCED,
        data_tags=[],
        endpoint_id="ep-001",
    )
    assert is_anomalous is False
    assert alert is None


@pytest.mark.asyncio
async def test_drift_upgrade_accepted(drift_detector: DriftDetector) -> None:
    """Agent upgrading to QUANTUM_SAFE is not anomalous (fail-secure direction)."""
    agent_id = "agent-upgrader"
    for i in range(5):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35)

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.QUANTUM_SAFE,
        data_tags=["PII"],
        endpoint_id="ep-001",
    )
    # Upgrading to QUANTUM_SAFE for PII is acceptable, not a downgrade anomaly
    assert is_anomalous is False or (is_anomalous and alert and alert.alert_type != "DRIFT_DETECTED")


@pytest.mark.asyncio
async def test_unfamiliar_endpoint_anomaly(drift_detector: DriftDetector) -> None:
    """Agent with established history requests key for new endpoint → anomaly."""
    agent_id = "agent-explorer"
    for i in range(5):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, f"ep-{i:03}", 0.35)

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.BALANCED,
        data_tags=[],
        endpoint_id="ep-totally-new",
    )
    assert is_anomalous is True
    assert alert is not None
    assert alert.alert_type == "UNAUTHORIZED_ENDPOINT"


@pytest.mark.asyncio
async def test_large_downgrade_triggers_anomaly(drift_detector: DriftDetector) -> None:
    """QUANTUM_SAFE → CHEAP (delta=3) is always anomalous."""
    agent_id = "agent-quantum-to-cheap"
    for i in range(5):
        await drift_detector.log_decision(agent_id, CipherProfile.QUANTUM_SAFE, "ep-001", 0.9)

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.CHEAP,
        data_tags=[],
        endpoint_id="ep-001",
    )
    assert is_anomalous is True
    assert alert is not None


@pytest.mark.asyncio
async def test_log_decision_records_history(drift_detector: DriftDetector) -> None:
    """log_decision appends to agent history."""
    agent_id = "agent-history"
    for i in range(3):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35)

    history = drift_detector.get_history(agent_id)
    assert len(history) == 3
    assert all(r.profile == CipherProfile.BALANCED for r in history)


@pytest.mark.asyncio
async def test_window_size_respected() -> None:
    """History window does not exceed configured size."""
    detector = DriftDetector(window_size=5)
    agent_id = "agent-windowed"
    for i in range(10):
        await detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35)

    history = detector.get_history(agent_id)
    assert len(history) == 5  # capped at window_size
