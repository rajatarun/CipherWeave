"""Pydantic data models for CipherWeave."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from cipherweave.profiles import CipherProfile


class PathRiskResult(BaseModel):
    """Output of RiskGraph.get_path_risk()."""

    path_nodes: list[str]
    regulations_crossed: list[str]
    threat_proximity: int  # hops; use 999 to represent "no threat found"
    data_classification: str
    recommended_profile: CipherProfile
    risk_score: float = Field(ge=0.0, le=1.0)
    justification: str


class DerivedKeyResult(BaseModel):
    """Output of CipherJanitor.derive_key()."""

    model_config = {"arbitrary_types_allowed": True}

    okm: bytes
    salt_used: bytes
    info_used: str
    algorithm: str
    key_length_bits: int
    hash_algo: str


class HybridKeyPair(BaseModel):
    """ML-KEM-768 + X25519 keypair for QUANTUM_SAFE profile."""

    model_config = {"arbitrary_types_allowed": True}

    x25519_private: bytes
    x25519_public: bytes
    mlkem_private: bytes
    mlkem_public: bytes

    def as_public_dict(self) -> dict[str, str]:
        """Return only public keys as base64 strings (safe to include in response)."""
        import base64

        return {
            "x25519_public_b64": base64.b64encode(self.x25519_public).decode(),
            "mlkem_public_b64": base64.b64encode(self.mlkem_public).decode(),
        }


class EncryptionStrategy(BaseModel):
    """Full response returned by the get_encryption_strategy MCP tool."""

    decision_id: str
    timestamp: datetime
    agent_id: str
    destination_url: str
    cipher_profile: CipherProfile
    algorithm: str
    key_length_bits: int
    kdf_algorithm: str
    salt_b64: str
    info_string: str
    regulations_crossed: list[str]
    threat_proximity: int
    path_nodes: list[str]
    risk_score: float = Field(ge=0.0, le=1.0)
    justification: str
    cost_per_operation_usd: float
    ttl_seconds: int
    hybrid_keypair: dict[str, str] | None = None  # public keys only
    audit_log: dict[str, Any]


class SecurityAlert(BaseModel):
    """Emitted by DriftDetector when anomalous behaviour is detected."""

    alert_id: str
    timestamp: datetime
    agent_id: str
    alert_type: str  # "DRIFT_DETECTED" | "UNAUTHORIZED_ENDPOINT" | "NEW_AGENT"
    severity: str    # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    message: str
    recommended_action: str


class AgentDecisionRecord(BaseModel):
    """Historical record stored by DriftDetector per agent decision."""

    agent_id: str
    profile: CipherProfile
    endpoint_id: str
    data_tags: list[str]
    risk_score: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)
