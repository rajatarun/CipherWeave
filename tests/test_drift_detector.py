"""Unit tests for DriftDetector — anomaly detection and fail-secure overrides."""

from __future__ import annotations

import pytest

from cipherweave.drift_detector import DEFAULT_N_MIN, DriftDetector

#: Observations needed before the detector will trust a baseline (Eq. 3 cold start).
_BASELINE_N = DEFAULT_N_MIN + 5

#: Spacing between seeded decisions. Baselines are only sampled from a window that
#: spans enough time to describe steady state, so seeded history must be spread
#: over the clock the way real traffic is; logging every decision at the same
#: instant leaves the agent permanently in cold start.
_SPACING = 10.0


def _seeded_now(i: int) -> float:
    return i * _SPACING


#: Timestamp to evaluate at after seeding _BASELINE_N decisions.
_EVAL_NOW = _BASELINE_N * _SPACING
from cipherweave.profiles import CipherProfile


@pytest.mark.asyncio
async def test_new_agent_defaults_to_quantum_safe(drift_detector: DriftDetector) -> None:
    """New agent with no history → QUANTUM_SAFE (fail-secure)."""
    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id="agent-brand-new",
        requested_profile=CipherProfile.BALANCED,
        data_tags=["PII"],
        endpoint_id="ep-001",
        now=_EVAL_NOW,
    )
    assert is_anomalous is True
    assert alert is not None
    assert alert.alert_type == "NEW_AGENT"
    assert alert.severity == "HIGH"


@pytest.mark.asyncio
async def test_drift_detection_pii_to_cheap(drift_detector: DriftDetector) -> None:
    """Agent typically BALANCED, requests CHEAP for PII → anomaly + QUANTUM_SAFE override."""
    agent_id = "agent-drifter"
    # Establish a BALANCED baseline. The detector requires n_min observations before
    # it will trust a baseline at all (cold start is fail-secure), so seed past it.
    for i in range(_BASELINE_N):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35, now=_seeded_now(i))

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.CHEAP,
        data_tags=["PII"],
        endpoint_id="ep-001",
        now=_EVAL_NOW,
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
    for i in range(_BASELINE_N):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35, now=_seeded_now(i))

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.BALANCED,
        data_tags=[],
        endpoint_id="ep-001",
        now=_EVAL_NOW,
    )
    assert is_anomalous is False
    assert alert is None


@pytest.mark.asyncio
async def test_drift_upgrade_accepted(drift_detector: DriftDetector) -> None:
    """Agent upgrading to QUANTUM_SAFE is not anomalous (fail-secure direction)."""
    agent_id = "agent-upgrader"
    for i in range(5):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35, now=_seeded_now(i))

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.QUANTUM_SAFE,
        data_tags=["PII"],
        endpoint_id="ep-001",
        now=_EVAL_NOW,
    )
    # Upgrading to QUANTUM_SAFE for PII is acceptable, not a downgrade anomaly
    assert is_anomalous is False or (is_anomalous and alert and alert.alert_type != "DRIFT_DETECTED")


@pytest.mark.asyncio
async def test_first_seen_endpoint_alone_is_not_an_anomaly(
    drift_detector: DriftDetector,
) -> None:
    """Reaching a new endpoint is not, by itself, evidence of compromise.

    A first-seen-endpoint rule used to fire here. It was removed after measurement:
    on the evaluation corpus it produced a 100% false-positive rate on `crawler`
    and `expanding` traffic and 40-52% on `bursty_etl`, because every long-running
    agent eventually contacts somewhere new and the benign first-contact rate
    (~3%) sits below any threshold that would still catch an attacker.

    Whether an agent may talk to an endpoint at all is authorization --- enforced
    deterministically by RiskGraph.validate_agent_authorization --- not something
    to infer statistically. Dispersion changes remain the entropy channel's job.
    """
    agent_id = "agent-explorer"
    for i in range(_BASELINE_N):
        await drift_detector.log_decision(
            agent_id, CipherProfile.BALANCED, f"ep-{i % 4:03}", 0.35, now=_seeded_now(i)
        )

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=CipherProfile.BALANCED,
        data_tags=[],
        endpoint_id="ep-totally-new",
        now=_EVAL_NOW,
    )
    assert is_anomalous is False, "a single new endpoint must not raise an alert"
    assert alert is None


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
        now=_EVAL_NOW,
    )
    assert is_anomalous is True
    assert alert is not None


@pytest.mark.asyncio
async def test_log_decision_records_history(drift_detector: DriftDetector) -> None:
    """log_decision appends to agent history."""
    agent_id = "agent-history"
    for i in range(3):
        await drift_detector.log_decision(agent_id, CipherProfile.BALANCED, "ep-001", 0.35, now=_seeded_now(i))

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
