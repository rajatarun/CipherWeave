"""Unit tests for RiskGraph — path risk, routing logic, authorization."""

from __future__ import annotations

import pytest

from cipherweave.exceptions import PathNotFoundError, UnauthorizedAgentError
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import MockRiskGraph


@pytest.mark.asyncio
async def test_path_risk_quantum_safe_hipaa(mock_graph: MockRiskGraph) -> None:
    """Path crossing HIPAA regulation → QUANTUM_SAFE."""
    result = await mock_graph.get_path_risk(
        agent_id="agent-001",
        destination_url="https://hipaa.store/api",
        data_tags=["PHI"],
    )
    assert result.recommended_profile == CipherProfile.QUANTUM_SAFE
    assert result.risk_score >= 0.8
    assert "HIPAA" in result.regulations_crossed
    assert "QUANTUM_SAFE" in result.justification or "HIPAA" in result.justification


@pytest.mark.asyncio
async def test_path_risk_cheap_vpc_internal(mock_graph: MockRiskGraph) -> None:
    """VPC-internal, INTERNAL classification, no regs → CHEAP."""
    result = await mock_graph.get_path_risk(
        agent_id="agent-001",
        destination_url="https://internal.vpc/api",
        data_tags=[],
    )
    assert result.recommended_profile == CipherProfile.CHEAP
    assert result.risk_score < 0.3
    assert "CHEAP" in result.justification


@pytest.mark.asyncio
async def test_path_risk_hardened_gdpr(mock_graph: MockRiskGraph) -> None:
    """Path crossing GDPR with CONFIDENTIAL data → HARDENED."""
    result = await mock_graph.get_path_risk(
        agent_id="agent-002",
        destination_url="https://gdpr.eu/data",
        data_tags=["PCI"],
    )
    assert result.recommended_profile == CipherProfile.HARDENED
    assert "GDPR" in result.regulations_crossed
    assert result.risk_score >= 0.5


@pytest.mark.asyncio
async def test_path_risk_quantum_safe_threat(mock_graph: MockRiskGraph) -> None:
    """Endpoint directly exposed to threat → QUANTUM_SAFE (threat_proximity=1)."""
    result = await mock_graph.get_path_risk(
        agent_id="agent-001",
        destination_url="https://public.api/data",
        data_tags=[],
    )
    assert result.recommended_profile == CipherProfile.QUANTUM_SAFE
    assert result.threat_proximity <= 2
    assert result.risk_score >= 0.8


@pytest.mark.asyncio
async def test_path_risk_unknown_endpoint_raises(mock_graph: MockRiskGraph) -> None:
    """Unknown destination URL raises PathNotFoundError."""
    with pytest.raises(PathNotFoundError):
        await mock_graph.get_path_risk(
            agent_id="agent-001",
            destination_url="https://unknown.evil/exfil",
            data_tags=[],
        )


@pytest.mark.asyncio
async def test_unauthorized_agent_fails(mock_graph: MockRiskGraph) -> None:
    """Rogue agent without AUTHORIZED_FOR edge raises UnauthorizedAgentError."""
    with pytest.raises(UnauthorizedAgentError):
        await mock_graph.validate_agent_authorization(
            agent_id="agent-rogue",
            endpoint_id="ep-hipaa-store",
        )


@pytest.mark.asyncio
async def test_authorized_agent_succeeds(mock_graph: MockRiskGraph) -> None:
    """Agent with AUTHORIZED_FOR edge returns True."""
    result = await mock_graph.validate_agent_authorization(
        agent_id="agent-001",
        endpoint_id="ep-hipaa-store",
    )
    assert result is True


@pytest.mark.asyncio
async def test_path_nodes_contain_agent(mock_graph: MockRiskGraph) -> None:
    """PathRiskResult.path_nodes must start with the agent."""
    result = await mock_graph.get_path_risk(
        agent_id="agent-001",
        destination_url="https://hipaa.store/api",
        data_tags=[],
    )
    assert result.path_nodes[0] == "Agent:agent-001"
    assert any("Endpoint:" in n for n in result.path_nodes)


@pytest.mark.asyncio
async def test_agent_exists(mock_graph: MockRiskGraph) -> None:
    assert await mock_graph.agent_exists("agent-001") is True
    assert await mock_graph.agent_exists("agent-ghost") is False


@pytest.mark.asyncio
async def test_routing_restricted_classification(mock_graph: MockRiskGraph) -> None:
    """RESTRICTED classification triggers QUANTUM_SAFE even without regulations."""
    # Seed a minimal graph with RESTRICTED data and no regulations
    g = MockRiskGraph()
    g.seed(
        agents=[{"agent_id": "ag-x", "name": "X", "trust_level": "HIGH"}],
        endpoints=[{"endpoint_id": "ep-x", "url": "https://ep-x/", "region": "us", "vpc_internal": False}],
        assets=[{"asset_id": "asset-restricted", "classification": "RESTRICTED", "tags": []}],
        regulations=[],
        threats=[],
        edges=[
            ("ag-x", "ACCESSES", "asset-restricted"),
            ("asset-restricted", "STORED_AT", "ep-x"),
            ("ag-x", "AUTHORIZED_FOR", "ep-x"),
        ],
    )
    result = await g.get_path_risk("ag-x", "https://ep-x/", [])
    assert result.recommended_profile == CipherProfile.QUANTUM_SAFE
