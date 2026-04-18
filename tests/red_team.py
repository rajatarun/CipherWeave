"""Red-team adversarial tests — rogue agents, poisoning, salt reuse, puppet attacks."""

from __future__ import annotations

import os

import pytest

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.drift_detector import DriftDetector
from cipherweave.exceptions import (
    PathNotFoundError,
    SaltReuseError,
    UnauthorizedAgentError,
)
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import MockRiskGraph
from cipherweave.server import get_encryption_strategy, inject_components
from tests.conftest import (
    AGENTS,
    ASSETS,
    EDGES,
    ENDPOINTS,
    REGULATIONS,
    THREATS,
)


def _make_full_graph() -> MockRiskGraph:
    g = MockRiskGraph()
    g.seed(
        agents=AGENTS,
        endpoints=ENDPOINTS,
        assets=ASSETS,
        regulations=REGULATIONS,
        threats=THREATS,
        edges=EDGES,
    )
    return g


@pytest.fixture(autouse=True)
def wire_red_team() -> None:
    g = _make_full_graph()
    janitor = CipherJanitor(kms_client=None, master_key_id="local")
    detector = DriftDetector(window_size=100)
    inject_components(g, janitor, detector)


@pytest.mark.asyncio
async def test_rogue_agent_unauthorized_endpoint() -> None:
    """Rogue agent without AUTHORIZED_FOR edge is rejected with UnauthorizedAgentError."""
    with pytest.raises(UnauthorizedAgentError):
        await get_encryption_strategy(
            agent_id="agent-rogue",
            data_metadata={"tags": ["PII"], "classification": "RESTRICTED"},
            destination_url="https://hipaa.store/api",
        )


@pytest.mark.asyncio
async def test_unknown_agent_rejected() -> None:
    """Completely unknown agent_id hitting a real endpoint raises PathNotFoundError or UnauthorizedAgentError."""
    with pytest.raises((UnauthorizedAgentError, PathNotFoundError)):
        await get_encryption_strategy(
            agent_id="agent-phantom-1337",
            data_metadata={"tags": [], "classification": "PUBLIC"},
            destination_url="https://internal.vpc/api",
        )


@pytest.mark.asyncio
async def test_graph_poisoning_threat_indicator() -> None:
    """Injecting a CRITICAL ThreatIndicator near an endpoint upgrades all ops to QUANTUM_SAFE."""
    # Start with no threats
    g = MockRiskGraph()
    g.seed(
        agents=[{"agent_id": "ag-x", "name": "X", "trust_level": "HIGH"}],
        endpoints=[{"endpoint_id": "ep-clean", "url": "https://clean.api/", "region": "us", "vpc_internal": True}],
        assets=[{"asset_id": "asset-clean", "classification": "INTERNAL", "tags": []}],
        regulations=[],
        threats=[],
        edges=[
            ("ag-x", "ACCESSES", "asset-clean"),
            ("asset-clean", "STORED_AT", "ep-clean"),
            ("ag-x", "AUTHORIZED_FOR", "ep-clean"),
        ],
    )

    janitor = CipherJanitor(kms_client=None, master_key_id="local")
    # Pre-load some CHEAP history so new-agent override doesn't fire
    detector = DriftDetector(window_size=100)
    for _ in range(5):
        await detector.log_decision("ag-x", CipherProfile.CHEAP, "ep-clean", 0.1)

    inject_components(g, janitor, detector)

    # Verify baseline is CHEAP
    r1 = await get_encryption_strategy(
        agent_id="ag-x",
        data_metadata={"tags": [], "classification": "INTERNAL"},
        destination_url="https://clean.api/",
    )
    assert r1["cipher_profile"] == "CHEAP"

    # Attacker poisons graph: inject CRITICAL threat near endpoint
    g._threats["threat-evil"] = {"indicator_id": "threat-evil", "severity": "CRITICAL", "ttl_hours": 1}
    g._edges.append(("ep-clean", "EXPOSED_TO", "threat-evil"))

    inject_components(g, janitor, detector)

    r2 = await get_encryption_strategy(
        agent_id="ag-x",
        data_metadata={"tags": [], "classification": "INTERNAL"},
        destination_url="https://clean.api/",
    )
    # After poisoning, must upgrade to QUANTUM_SAFE
    assert r2["cipher_profile"] == "QUANTUM_SAFE"


@pytest.mark.asyncio
async def test_salt_reuse_attack() -> None:
    """Deriving twice with identical (salt, info) raises SaltReuseError."""
    janitor = CipherJanitor(kms_client=None, master_key_id="local")
    salt = os.urandom(32)
    info = b"cipherweave:v1:attack:ep:hash:0000"

    janitor.derive_key(os.urandom(32), salt, info, CipherProfile.BALANCED)

    with pytest.raises(SaltReuseError):
        janitor.derive_key(os.urandom(32), salt, info, CipherProfile.BALANCED)


@pytest.mark.asyncio
async def test_puppet_attack_unfamiliar_endpoint_overridden() -> None:
    """Puppet attack: agent authorized for ep-A requests key for ep-B → DriftDetector overrides to QUANTUM_SAFE."""
    g = MockRiskGraph()
    g.seed(
        agents=[{"agent_id": "ag-puppet", "name": "Puppet", "trust_level": "MEDIUM"}],
        endpoints=[
            {"endpoint_id": "ep-a", "url": "https://ep-a/", "region": "us", "vpc_internal": True},
            {"endpoint_id": "ep-b", "url": "https://ep-b/", "region": "us", "vpc_internal": True},
        ],
        assets=[
            {"asset_id": "asset-a", "classification": "INTERNAL", "tags": []},
            {"asset_id": "asset-b", "classification": "INTERNAL", "tags": []},
        ],
        regulations=[],
        threats=[],
        edges=[
            ("ag-puppet", "ACCESSES", "asset-a"),
            ("asset-a", "STORED_AT", "ep-a"),
            ("ag-puppet", "AUTHORIZED_FOR", "ep-a"),
            # ep-b is in graph, agent is NOT authorized
            ("ag-puppet", "ACCESSES", "asset-b"),
            ("asset-b", "STORED_AT", "ep-b"),
            # Deliberately missing: ("ag-puppet", "AUTHORIZED_FOR", "ep-b")
        ],
    )
    janitor = CipherJanitor(kms_client=None, master_key_id="local")
    detector = DriftDetector(window_size=100)
    # Establish history on ep-a
    for _ in range(5):
        await detector.log_decision("ag-puppet", CipherProfile.CHEAP, "ep-a", 0.1)
    inject_components(g, janitor, detector)

    # Agent requests for ep-b which it's not authorized for
    with pytest.raises(UnauthorizedAgentError):
        await get_encryption_strategy(
            agent_id="ag-puppet",
            data_metadata={"tags": [], "classification": "INTERNAL"},
            destination_url="https://ep-b/",
        )


@pytest.mark.asyncio
async def test_downgrade_attack_pii_to_cheap_overridden() -> None:
    """Attacker attempts to force CHEAP on PII data; DriftDetector upgrades to QUANTUM_SAFE."""
    g = _make_full_graph()
    janitor = CipherJanitor(kms_client=None, master_key_id="local")
    detector = DriftDetector(window_size=100)
    # Give agent-001 history of using BALANCED for ep-vpc-internal
    for _ in range(10):
        await detector.log_decision("agent-001", CipherProfile.BALANCED, "ep-vpc-internal", 0.35)
    inject_components(g, janitor, detector)

    # Even though the risk engine might normally return CHEAP for internal vpc,
    # the HIPAA endpoint path forces QUANTUM_SAFE anyway; on PII + CHEAP history = QUANTUM_SAFE
    result = await get_encryption_strategy(
        agent_id="agent-001",
        data_metadata={"tags": ["PII"], "classification": "RESTRICTED"},
        destination_url="https://hipaa.store/api",
    )
    assert result["cipher_profile"] == "QUANTUM_SAFE"
