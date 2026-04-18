"""Shared pytest fixtures for CipherWeave tests."""

from __future__ import annotations

import pytest

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.drift_detector import DriftDetector
from cipherweave.risk_engine import MockRiskGraph

# ---------------------------------------------------------------------------
# Standard topology used across tests
# ---------------------------------------------------------------------------
AGENTS = [
    {"agent_id": "agent-001", "name": "AnalyticsBot", "trust_level": "MEDIUM"},
    {"agent_id": "agent-002", "name": "ReportingBot", "trust_level": "HIGH"},
    {"agent_id": "agent-rogue", "name": "RogueBot", "trust_level": "LOW"},
]

ENDPOINTS = [
    {"endpoint_id": "ep-vpc-internal", "url": "https://internal.vpc/api", "region": "us-east-1", "vpc_internal": True},
    {"endpoint_id": "ep-hipaa-store", "url": "https://hipaa.store/api", "region": "us-east-1", "vpc_internal": False},
    {"endpoint_id": "ep-public", "url": "https://public.api/data", "region": "us-east-1", "vpc_internal": False},
    {"endpoint_id": "ep-gdpr", "url": "https://gdpr.eu/data", "region": "eu-west-1", "vpc_internal": False},
]

ASSETS = [
    {"asset_id": "asset-pii", "classification": "RESTRICTED", "tags": ["PII"]},
    {"asset_id": "asset-internal", "classification": "INTERNAL", "tags": []},
    {"asset_id": "asset-phi", "classification": "RESTRICTED", "tags": ["PHI"]},
    {"asset_id": "asset-conf", "classification": "CONFIDENTIAL", "tags": ["PCI"]},
]

REGULATIONS = [
    {"reg_id": "reg-hipaa", "name": "HIPAA", "cipher_floor": "QUANTUM_SAFE"},
    {"reg_id": "reg-gdpr", "name": "GDPR", "cipher_floor": "HARDENED"},
]

THREATS = [
    {"indicator_id": "threat-001", "severity": "CRITICAL", "ttl_hours": 24},
]

EDGES: list[tuple[str, str, str]] = [
    # agent-001 accesses PII asset stored at HIPAA endpoint
    ("agent-001", "ACCESSES", "asset-pii"),
    ("asset-pii", "STORED_AT", "ep-hipaa-store"),
    ("asset-pii", "GOVERNED_BY", "reg-hipaa"),
    ("agent-001", "AUTHORIZED_FOR", "ep-hipaa-store"),
    # agent-001 also has access to internal VPC
    ("agent-001", "ACCESSES", "asset-internal"),
    ("asset-internal", "STORED_AT", "ep-vpc-internal"),
    ("agent-001", "AUTHORIZED_FOR", "ep-vpc-internal"),
    # agent-002 accesses GDPR-governed confidential asset
    ("agent-002", "ACCESSES", "asset-conf"),
    ("asset-conf", "STORED_AT", "ep-gdpr"),
    ("asset-conf", "GOVERNED_BY", "reg-gdpr"),
    ("agent-002", "AUTHORIZED_FOR", "ep-gdpr"),
    # threat on public endpoint
    ("ep-public", "EXPOSED_TO", "threat-001"),
    ("agent-001", "AUTHORIZED_FOR", "ep-public"),
    ("agent-001", "ACCESSES", "asset-internal"),
]


@pytest.fixture
def mock_graph() -> MockRiskGraph:
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


@pytest.fixture
def mock_kms() -> None:
    """No-op KMS fixture — CipherJanitor uses os.urandom when kms_client=None."""
    return None


@pytest.fixture
def cipher_janitor(mock_kms: None) -> CipherJanitor:
    return CipherJanitor(kms_client=None, master_key_id="local-mock")


@pytest.fixture
def drift_detector() -> DriftDetector:
    return DriftDetector(window_size=100)
