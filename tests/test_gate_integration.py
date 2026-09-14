"""Tests for the propose-time gate client (`cipherweave.gate_integration`).

Two things are being pinned here. First, that the client answers with the profile
the risk graph actually implies -- it is not a stub that says QUANTUM_SAFE to
everything, which would be useless to a gate. Second, that every way it can fail
lands on QUANTUM_SAFE with the reason recorded, because a propose-time answer of
"no requirement" is a downgrade (ADR-001, docs/gate-integration.md).
"""

from __future__ import annotations

import asyncio
import time

import pytest

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.drift_detector import DEFAULT_N_MIN, DriftDetector
from cipherweave.gate_integration import (
    FAIL_SECURE_PROFILE,
    ProfileDecision,
    required_profile,
    required_profile_async,
)
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import MockRiskGraph, RiskGraph

#: Observations needed before the detector trusts a baseline (Eq. 3 cold start).
_BASELINE_N = DEFAULT_N_MIN + 5

#: Spacing between seeded decisions. Baselines are sampled only from a window that
#: spans enough time to describe steady state, so history has to be spread over the
#: clock; seeding it all at one instant leaves the agent permanently in cold start.
_SPACING = 10.0


async def _warm(
    detector: DriftDetector,
    agent_id: str,
    endpoint_id: str,
    profile: CipherProfile,
) -> None:
    """Give an agent a steady-state history ending at (approximately) now.

    Seeded against `time.monotonic()` rather than an arbitrary origin because the
    client calls `detect_anomaly` with the real clock -- history in the distant
    past would fall outside the trailing window and read as a cold start.
    """
    base = time.monotonic()
    for i in range(_BASELINE_N):
        await detector.log_decision(
            agent_id=agent_id,
            profile=profile,
            endpoint_id=endpoint_id,
            risk_score=0.65,
            now=base - (_BASELINE_N - i) * _SPACING,
        )


# ---------------------------------------------------------------------------
# The decision the graph implies
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_known_high_risk_path_requires_quantum_safe(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector
) -> None:
    """RESTRICTED PHI to a HIPAA endpoint: QUANTUM_SAFE, and not by fail-secure."""
    await _warm(drift_detector, "agent-001", "ep-hipaa-store", CipherProfile.QUANTUM_SAFE)

    decision = await required_profile_async(
        "agent-001",
        "https://hipaa.store/api",
        classification="RESTRICTED",
        regulations=["PHI"],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )

    assert decision.profile is CipherProfile.QUANTUM_SAFE
    assert decision.fail_secure is False, "must be the graph's answer, not the catch-all"
    assert decision.error is None
    assert "HIPAA" in decision.regulations_crossed


@pytest.mark.asyncio
async def test_regulated_path_requires_hardened_not_everything(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector
) -> None:
    """A GDPR/CONFIDENTIAL flow gets HARDENED — the client discriminates."""
    await _warm(drift_detector, "agent-002", "ep-gdpr", CipherProfile.HARDENED)

    decision = await required_profile_async(
        "agent-002",
        "https://gdpr.eu/data",
        classification="CONFIDENTIAL",
        regulations=["PCI"],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )

    assert decision.profile is CipherProfile.HARDENED
    assert decision.fail_secure is False
    assert decision.drift_detected is False
    assert "GDPR" in decision.regulations_crossed


@pytest.mark.asyncio
async def test_explanation_survives_into_the_audit_record(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector
) -> None:
    """Only the profile rides in the token; the reason must ride in the record."""
    await _warm(drift_detector, "agent-002", "ep-gdpr", CipherProfile.HARDENED)

    decision = await required_profile_async(
        "agent-002",
        "https://gdpr.eu/data",
        classification="CONFIDENTIAL",
        regulations=["PCI"],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )

    assert decision.justification, "justification must be populated"
    assert "HARDENED" in decision.justification
    assert decision.evidence_trail, "per-term evidence breakdown must be populated"
    assert decision.path_nodes
    assert decision.risk_score > 0.0

    audit = decision.as_audit_dict()
    assert audit["required_cipher_profile"] == "HARDENED"
    assert audit["cipher_justification"] == decision.justification
    assert audit["cipher_fail_secure"] is False


@pytest.mark.asyncio
async def test_drift_override_raises_the_profile(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector
) -> None:
    """A flow the graph scores low still binds QUANTUM_SAFE when drift fires.

    The VPC-internal path is the cheapest in the fixture topology; an agent with
    no baseline is in cold start, which is drift, so the join raises it. This is
    an override, not a failure: `fail_secure` stays False and the reason names the
    anomaly rather than an error.
    """
    decision = await required_profile_async(
        "agent-001",
        "https://internal.vpc/api",
        classification="INTERNAL",
        regulations=[],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )

    assert decision.profile is CipherProfile.QUANTUM_SAFE
    assert decision.drift_detected is True
    assert decision.fail_secure is False
    assert "ANOMALY DETECTED" in decision.justification
    assert decision.alert is not None


# ---------------------------------------------------------------------------
# Fail-secure on every failure mode
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unreachable_graph_is_fail_secure(drift_detector: DriftDetector) -> None:
    """A RiskGraph that was never connected fails closed, not open."""
    disconnected = RiskGraph(memgraph_host="127.0.0.1", memgraph_port=1)

    decision = await required_profile_async(
        "agent-001",
        "https://hipaa.store/api",
        classification="RESTRICTED",
        regulations=["PHI"],
        risk_graph=disconnected,
        drift_detector=drift_detector,
    )

    assert decision.profile is FAIL_SECURE_PROFILE
    assert decision.fail_secure is True
    assert "GraphConnectionError" in (decision.error or "")
    assert "FAIL-SECURE" in decision.justification


@pytest.mark.asyncio
async def test_unknown_agent_is_fail_secure(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector
) -> None:
    """An agent with no AUTHORIZED_FOR edge gets the strongest profile, not the weakest."""
    decision = await required_profile_async(
        "agent-never-seen",
        "https://hipaa.store/api",
        classification="RESTRICTED",
        regulations=["PHI"],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )

    assert decision.profile is FAIL_SECURE_PROFILE
    assert decision.fail_secure is True
    assert "UnauthorizedAgentError" in (decision.error or "")


@pytest.mark.asyncio
async def test_unclassifiable_metadata_is_fail_secure(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector
) -> None:
    """An unknown endpoint that cannot be classified binds QUANTUM_SAFE.

    The MCP tool raises MetadataInferenceError here — it refuses to register a
    path it cannot describe. The gate client cannot raise, so the refusal becomes
    the strongest requirement instead.
    """
    decision = await required_profile_async(
        "agent-001",
        "https://brand.new/endpoint",
        classification="NOT_A_REAL_LEVEL",
        regulations=[],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )

    assert decision.profile is FAIL_SECURE_PROFILE
    assert decision.fail_secure is True
    assert "MetadataInferenceError" in (decision.error or "")


@pytest.mark.asyncio
async def test_exception_in_scoring_is_fail_secure(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug anywhere under the decision path fails closed rather than propagating."""

    def _boom(*_args, **_kwargs):
        raise ZeroDivisionError("synthetic scoring defect")

    monkeypatch.setattr("cipherweave.gate_integration.combine", _boom)

    decision = await required_profile_async(
        "agent-001",
        "https://hipaa.store/api",
        classification="RESTRICTED",
        regulations=["PHI"],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )

    assert decision.profile is FAIL_SECURE_PROFILE
    assert decision.fail_secure is True
    assert "ZeroDivisionError" in (decision.error or "")


@pytest.mark.asyncio
async def test_slow_lookup_is_fail_secure(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreachable graph usually presents as a hang, so the timeout fails closed too."""

    async def _hang(*_args, **_kwargs):
        await asyncio.sleep(3600)

    monkeypatch.setattr(mock_graph, "get_endpoint_id_for_url", _hang)

    decision = await required_profile_async(
        "agent-001",
        "https://hipaa.store/api",
        classification="RESTRICTED",
        regulations=["PHI"],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
        timeout_seconds=0.05,
    )

    assert decision.profile is FAIL_SECURE_PROFILE
    assert decision.fail_secure is True
    assert "TimeoutError" in (decision.error or "")


# ---------------------------------------------------------------------------
# The commit-side comparison and the synchronous entry point
# ---------------------------------------------------------------------------

def test_satisfied_by_is_a_lattice_comparison() -> None:
    """The check the commit verifier performs: meet-or-exceed, never equality."""
    required = ProfileDecision(profile=CipherProfile.HARDENED, justification="test")

    assert required.satisfied_by(CipherProfile.HARDENED) is True
    assert required.satisfied_by("QUANTUM_SAFE") is True, "raising the profile is allowed"
    assert required.satisfied_by("BALANCED") is False, "lowering it is not"
    assert required.satisfied_by(None) is False, "an unstated channel satisfies nothing"
    assert required.satisfied_by("AES-256-GCM") is False, "nor does an unparseable one"


def test_sync_entry_point_matches_the_async_one(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector
) -> None:
    """`required_profile` is callable from a synchronous proposer."""
    decision = required_profile(
        "agent-001",
        "https://hipaa.store/api",
        classification="RESTRICTED",
        regulations=["PHI"],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )

    assert decision.profile is CipherProfile.QUANTUM_SAFE
    assert decision.token_value == "QUANTUM_SAFE"  # noqa: S105 — a profile name, not a secret


# ---------------------------------------------------------------------------
# The property the shared decision path exists for
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gate_and_mcp_tool_agree_on_the_same_flow(
    mock_graph: MockRiskGraph, drift_detector: DriftDetector, cipher_janitor: CipherJanitor
) -> None:
    """The profile bound at propose time is the one the tool would have issued.

    If these could diverge, the gate would authorize a channel weaker than the
    one CipherWeave requires for the very same flow — which is the failure the
    shared `decide_profile` path exists to make unrepresentable.
    """
    from cipherweave.server import get_encryption_strategy, inject_components

    await _warm(drift_detector, "agent-002", "ep-gdpr", CipherProfile.HARDENED)
    inject_components(mock_graph, cipher_janitor, drift_detector)

    proposed = await required_profile_async(
        "agent-002",
        "https://gdpr.eu/data",
        classification="CONFIDENTIAL",
        regulations=["PCI"],
        risk_graph=mock_graph,
        drift_detector=drift_detector,
    )
    issued = await get_encryption_strategy(
        agent_id="agent-002",
        data_metadata={"classification": "CONFIDENTIAL", "tags": ["PCI"]},
        destination_url="https://gdpr.eu/data",
    )

    assert proposed.profile.value == issued["cipher_profile"]
    assert proposed.justification == issued["justification"]
