"""Module 5: Cipher Drift Detection — anomaly detection and fail-secure override."""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime

from cipherweave.models import AgentDecisionRecord, SecurityAlert
from cipherweave.profiles import CipherProfile

logger = logging.getLogger(__name__)

# Tags that always require a strong profile
_SENSITIVE_TAGS: frozenset[str] = frozenset({"PII", "PHI", "PCI", "TRADE_SECRET"})

# Minimum acceptable profile for sensitive data
_SENSITIVE_FLOOR = CipherProfile.BALANCED


class DriftDetector:
    """Tracks per-agent cipher decisions and flags anomalies.

    Decision philosophy:
    - New agents have no history → default to QUANTUM_SAFE (fail-secure)
    - A drop from BALANCED/HARDENED/QUANTUM_SAFE to CHEAP on sensitive data = anomaly
    - An endpoint the agent has never used before = suspicious
    """

    def __init__(self, window_size: int = 100) -> None:
        self._window_size = window_size
        # agent_id → deque of AgentDecisionRecord
        self._history: dict[str, deque[AgentDecisionRecord]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

    async def detect_anomaly(
        self,
        agent_id: str,
        requested_profile: CipherProfile,
        data_tags: list[str],
        endpoint_id: str,
    ) -> tuple[bool, SecurityAlert | None]:
        """Detect anomalous cipher profile requests and apply fail-secure override.

        Returns:
            (is_anomalous, alert_or_None)
        """
        history = self._history[agent_id]

        # New agent — no history; default to QUANTUM_SAFE
        if not history:
            alert = _make_alert(
                agent_id=agent_id,
                alert_type="NEW_AGENT",
                severity="HIGH",
                message=(
                    f"No decision history for agent '{agent_id}'. "
                    "Defaulting to QUANTUM_SAFE (fail-secure)."
                ),
                recommended_action="Establish agent baseline before relaxing cipher policy.",
            )
            return True, alert

        # Compute dominant historical profile
        profile_counts: dict[CipherProfile, int] = defaultdict(int)
        seen_endpoints: set[str] = set()
        for record in history:
            profile_counts[record.profile] += 1
            seen_endpoints.add(record.endpoint_id)

        dominant = max(profile_counts, key=lambda p: profile_counts[p])
        has_sensitive = bool(_SENSITIVE_TAGS & set(data_tags))

        # Anomaly: downgrade from BALANCED+ to CHEAP on sensitive data
        if (
            has_sensitive
            and requested_profile == CipherProfile.CHEAP
            and dominant.strength() >= CipherProfile.BALANCED.strength()
        ):
            alert = _make_alert(
                agent_id=agent_id,
                alert_type="DRIFT_DETECTED",
                severity="CRITICAL",
                message=(
                    f"Agent '{agent_id}' requests CHEAP profile for sensitive data "
                    f"(tags: {data_tags}) — typical profile is {dominant.value}. "
                    "Overriding to QUANTUM_SAFE."
                ),
                recommended_action="Investigate agent configuration or potential compromise.",
            )
            return True, alert

        # Anomaly: unfamiliar endpoint
        if endpoint_id not in seen_endpoints and len(seen_endpoints) >= 3:
            alert = _make_alert(
                agent_id=agent_id,
                alert_type="UNAUTHORIZED_ENDPOINT",
                severity="HIGH",
                message=(
                    f"Agent '{agent_id}' requests key for previously-unseen endpoint "
                    f"'{endpoint_id}'. Overriding to QUANTUM_SAFE."
                ),
                recommended_action="Verify agent is authorized for this endpoint.",
            )
            return True, alert

        # Anomaly: significant downgrade (e.g., QUANTUM_SAFE → CHEAP)
        downgrade = dominant.strength() - requested_profile.strength()
        if downgrade >= 2:
            alert = _make_alert(
                agent_id=agent_id,
                alert_type="DRIFT_DETECTED",
                severity="HIGH",
                message=(
                    f"Agent '{agent_id}' profile downgrade: {dominant.value} → "
                    f"{requested_profile.value} (delta={downgrade}). Overriding to QUANTUM_SAFE."
                ),
                recommended_action="Review agent policy and authorization scope.",
            )
            return True, alert

        return False, None

    async def log_decision(
        self,
        agent_id: str,
        profile: CipherProfile,
        endpoint_id: str,
        risk_score: float,
    ) -> None:
        """Record a decision in the agent's history window."""
        record = AgentDecisionRecord(
            agent_id=agent_id,
            profile=profile,
            endpoint_id=endpoint_id,
            data_tags=[],
            risk_score=risk_score,
        )
        self._history[agent_id].append(record)

    def get_history(self, agent_id: str) -> list[AgentDecisionRecord]:
        return list(self._history.get(agent_id, []))


def _make_alert(
    agent_id: str,
    alert_type: str,
    severity: str,
    message: str,
    recommended_action: str,
) -> SecurityAlert:
    return SecurityAlert(
        alert_id=f"cw_alert_{uuid.uuid4().hex[:8]}",
        timestamp=datetime.utcnow(),
        agent_id=agent_id,
        alert_type=alert_type,
        severity=severity,
        message=message,
        recommended_action=recommended_action,
    )
