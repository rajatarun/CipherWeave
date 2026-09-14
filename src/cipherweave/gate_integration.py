"""Propose-time client: what channel must this call run over?

The mcp-observatory gate decides *whether* a tool call may run; CipherWeave
decides *how* the resulting data flow must be protected. This module is the
seam. A gate consumer calls `required_profile()` while it is scoring a
prospective call, gets back the `CipherProfile` that flow requires, and binds
that profile into the HMAC-signed commit token so the executor cannot quietly
downgrade the transport between approval and execution. The contract for the
observatory side is `docs/gate-integration.md`.

Two properties shape everything here.

**One decision path, not two.** `decide_profile()` below *is* the decision path:
endpoint resolution (with JIT registration), authorization, Eq. 1/2 aggregation
over the risk graph, the compliance floor, and the drift override, joined over
the profile lattice. `server.get_encryption_strategy` calls it and then derives
key material from its result. A second implementation of the policy for gate
callers would be a second thing to keep correct, and the first divergence would
be invisible -- the gate would authorize a channel the MCP tool would not have.

**Fail-secure, and the failure is on the record.** Every way this can fail --
graph unreachable, unknown or unauthorized agent, metadata that cannot be
classified, a bug in scoring, a timeout -- yields QUANTUM_SAFE with `fail_secure`
set and `error` naming the cause (ADR-001). The propose-time answer is never
"omit the requirement": an absent profile is a downgrade, and a downgrade is the
one thing this integration exists to prevent. Callers that want to *block* on an
unreachable policy service can test `fail_secure`; what they must not do is
proceed with a weaker channel than the one named here.

What this module deliberately does not do: it does not derive keys (a proposal
may never be committed, and burning a salt per proposal is waste at best), and
it does not write to the drift detector's history. Only a call that actually
executed is an observation about the agent's behaviour, so `log_decision` stays
with `server.get_encryption_strategy`.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from cipherweave.drift_detector import DriftDetector
from cipherweave.models import SecurityAlert
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import RiskGraph, infer_policy_from_metadata
from cipherweave.scoring import combine

logger = logging.getLogger(__name__)

#: The profile returned whenever the policy cannot be evaluated (ADR-001).
FAIL_SECURE_PROFILE: CipherProfile = CipherProfile.QUANTUM_SAFE

#: Default ceiling on a propose-time lookup. A warm graph path answers in a few
#: milliseconds; the budget is generous because the first call for an unknown
#: endpoint pays for JIT policy inference. Exceeding it is a failure like any
#: other and returns FAIL_SECURE_PROFILE rather than blocking the proposer.
DEFAULT_TIMEOUT_SECONDS: float = 5.0

_risk_graph: RiskGraph | None = None
_drift_detector: DriftDetector | None = None
_bedrock_client: object | None = None


@dataclass(frozen=True)
class ProfileDecision:
    """The required channel strength for one prospective call, with its reason.

    The explanation fields are not decoration: the gate writes them into the
    proposal record, so the reason a call was bound to QUANTUM_SAFE survives into
    the audit trail even though only `profile` rides inside the token.
    """

    profile: CipherProfile
    justification: str
    risk_score: float = 0.0
    regulations_crossed: tuple[str, ...] = ()
    threat_proximity: int = 999
    path_nodes: tuple[str, ...] = ()
    evidence_trail: tuple[str, ...] = ()
    endpoint_id: str | None = None
    drift_detected: bool = False
    alert: SecurityAlert | None = field(default=None, repr=False)
    #: True when this decision came from the catch-all rather than from the graph.
    fail_secure: bool = False
    #: Exception type and message when `fail_secure` is set; None otherwise.
    error: str | None = None

    @property
    def token_value(self) -> str:
        """The exact string to place in the token's `required_cipher_profile`."""
        return self.profile.value

    def satisfied_by(self, channel_profile: str | CipherProfile | None) -> bool:
        """Does an actual channel meet this requirement?

        The commit-side check, implemented here so both sides of the integration
        read the same comparison. An unknown or missing channel never satisfies
        anything -- the same fail-secure rule that produced the requirement.
        """
        if channel_profile is None:
            return False
        if isinstance(channel_profile, CipherProfile):
            actual = channel_profile
        else:
            try:
                actual = CipherProfile[str(channel_profile).upper()]
            except KeyError:
                return False
        return actual.strength() >= self.profile.strength()

    def as_audit_dict(self) -> dict:
        """Flat, JSON-safe view for the proposal record."""
        return {
            "required_cipher_profile": self.profile.value,
            "cipher_justification": self.justification,
            "cipher_risk_score": round(self.risk_score, 4),
            "cipher_regulations": list(self.regulations_crossed),
            "cipher_threat_proximity": self.threat_proximity,
            "cipher_path_nodes": list(self.path_nodes),
            "cipher_evidence": list(self.evidence_trail),
            "cipher_drift_detected": self.drift_detected,
            "cipher_alert_type": self.alert.alert_type if self.alert else None,
            "cipher_fail_secure": self.fail_secure,
            "cipher_error": self.error,
        }


def configure(
    risk_graph: RiskGraph,
    drift_detector: DriftDetector,
    bedrock_client: object | None = None,
) -> None:
    """Bind the components this module uses when a caller passes none.

    A host that runs the MCP server does not need this: the server's own
    singletons are picked up automatically. It exists for a process that embeds
    the policy engine without serving the tool.
    """
    global _risk_graph, _drift_detector, _bedrock_client
    _risk_graph = risk_graph
    _drift_detector = drift_detector
    _bedrock_client = bedrock_client


def _resolve_components() -> tuple[RiskGraph, DriftDetector, object | None]:
    """Components configured here, else the running server's, else an error."""
    if _risk_graph is not None and _drift_detector is not None:
        return _risk_graph, _drift_detector, _bedrock_client

    # Imported lazily and by name: server imports this module, so a module-level
    # import would be circular, and a gate consumer that never starts the MCP
    # server should not pay for importing it.
    from cipherweave import server as _server

    if _server._risk_graph is None or _server._drift_detector is None:
        raise RuntimeError(
            "CipherWeave policy components are not initialized; call "
            "gate_integration.configure(risk_graph, drift_detector) first"
        )
    return _server._risk_graph, _server._drift_detector, _server._bedrock_client


def _metadata_for(
    classification: str | None,
    regulations: Sequence[str] | None,
    data_metadata: Mapping | None,
) -> dict:
    """Assemble the metadata dict the decision path validates.

    Explicit arguments win over the same key in `data_metadata`, so a caller can
    pass a rich metadata blob (description, contains_pii -- which sharpen JIT
    inference) and still state the classification it is sure of.
    """
    merged: dict = dict(data_metadata or {})
    if classification is not None:
        merged["classification"] = classification
    if regulations is not None:
        merged["tags"] = list(regulations)
    merged.setdefault("tags", [])
    return merged


async def decide_profile(
    *,
    agent_id: str,
    destination_url: str,
    data_metadata: Mapping,
    risk_graph: RiskGraph,
    drift_detector: DriftDetector,
    bedrock_client: object | None = None,
    model_id: str | None = None,
) -> ProfileDecision:
    """The decision path: resolve, authorize, score, override. Raises on failure.

    This is the single implementation of "which profile does this flow require".
    `server.get_encryption_strategy` calls it for the profile it then derives keys
    against; `required_profile_async` calls it behind a catch-all. Errors are
    raised rather than absorbed so the MCP tool can keep reporting
    `UnauthorizedAgentError` and `MetadataInferenceError` to its caller.

    The final profile is `combine(Pi(r), drift override)`: a join over the profile
    lattice, so it is never weaker than what any single mechanism demanded. The
    compliance floor has already entered the join inside `risk_engine._score`.
    """
    from cipherweave.config import settings

    endpoint_id = await risk_graph.get_endpoint_id_for_url(destination_url)
    if endpoint_id is None:
        classification, regulations, _, _, _ = await infer_policy_from_metadata(
            data_metadata if isinstance(data_metadata, dict) else dict(data_metadata),
            bedrock_client=bedrock_client,
            model_id=model_id or settings.bedrock_inference_model_id,
        )
        endpoint_id = await risk_graph.upsert_jit_path(
            agent_id, destination_url, classification, regulations
        )
        logger.info(
            "JIT registered: agent=%s url=%s classification=%s regs=%s",
            agent_id, destination_url, classification, regulations,
        )

    await risk_graph.validate_agent_authorization(agent_id, endpoint_id)

    data_tags: list[str] = list(data_metadata.get("tags", []) or [])
    path_risk = await risk_graph.get_path_risk(agent_id, destination_url, data_tags)

    is_anomalous, alert = await drift_detector.detect_anomaly(
        agent_id=agent_id,
        requested_profile=path_risk.recommended_profile,
        data_tags=data_tags,
        endpoint_id=endpoint_id,
    )

    final = combine(
        path_risk.recommended_profile,
        FAIL_SECURE_PROFILE if is_anomalous else CipherProfile.CHEAP,
    )
    justification = (
        f"[ANOMALY DETECTED — QUANTUM_SAFE enforced] {path_risk.justification}"
        if is_anomalous
        else path_risk.justification
    )

    return ProfileDecision(
        profile=final,
        justification=justification,
        risk_score=path_risk.risk_score,
        regulations_crossed=tuple(path_risk.regulations_crossed),
        threat_proximity=path_risk.threat_proximity,
        path_nodes=tuple(path_risk.path_nodes),
        evidence_trail=tuple(path_risk.evidence_trail),
        endpoint_id=endpoint_id,
        drift_detected=is_anomalous,
        alert=alert,
    )


def _fail_secure(exc: BaseException, agent_id: str, destination_url: str) -> ProfileDecision:
    reason = f"{type(exc).__name__}: {exc}"
    logger.warning(
        "CipherWeave policy lookup failed for agent=%s url=%s; requiring %s. %s",
        agent_id, destination_url, FAIL_SECURE_PROFILE.value, reason,
    )
    return ProfileDecision(
        profile=FAIL_SECURE_PROFILE,
        justification=(
            f"[FAIL-SECURE — {FAIL_SECURE_PROFILE.value} enforced] Policy could not be "
            f"evaluated for agent '{agent_id}' to '{destination_url}': {reason}. "
            "ADR-001: an unevaluable condition takes the strongest profile."
        ),
        fail_secure=True,
        error=reason,
    )


async def required_profile_async(
    agent_id: str,
    destination_url: str,
    *,
    classification: str | None = None,
    regulations: Sequence[str] | None = None,
    data_metadata: Mapping | None = None,
    risk_graph: RiskGraph | None = None,
    drift_detector: DriftDetector | None = None,
    bedrock_client: object | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> ProfileDecision:
    """Required channel strength for a prospective call. Never raises.

    Args:
        agent_id: The agent that would make the call.
        destination_url: Where the data would go -- the endpoint URL, or any
            stable endpoint identifier the caller has. Unknown destinations are
            JIT-registered (ADR-016) rather than refused.
        classification: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED | TOP_SECRET.
        regulations: Regulatory tags, e.g. ("GDPR", "HIPAA"). Pass an empty
            sequence to state that none apply; passing nothing is not the same
            claim and will be rejected as unclassifiable for a new endpoint.
        data_metadata: Optional richer metadata (data_type, description,
            contains_pii ...) which improves JIT policy inference.
        timeout_seconds: Ceiling on the lookup; exceeding it is a failure.

    Returns:
        A `ProfileDecision`. On any failure, QUANTUM_SAFE with `fail_secure=True`
        and `error` set -- never a weaker profile and never an exception, because
        a proposer that crashes on an unreachable policy service is a proposer
        that will be "temporarily" wired to skip the requirement.
    """
    try:
        if risk_graph is None or drift_detector is None:
            resolved_graph, resolved_drift, resolved_bedrock = _resolve_components()
            risk_graph = risk_graph or resolved_graph
            drift_detector = drift_detector or resolved_drift
            bedrock_client = bedrock_client if bedrock_client is not None else resolved_bedrock

        return await asyncio.wait_for(
            decide_profile(
                agent_id=agent_id,
                destination_url=destination_url,
                data_metadata=_metadata_for(classification, regulations, data_metadata),
                risk_graph=risk_graph,
                drift_detector=drift_detector,
                bedrock_client=bedrock_client,
            ),
            timeout=timeout_seconds,
        )
    except Exception as exc:  # every failure mode is fail-secure by design
        return _fail_secure(exc, agent_id, destination_url)


def required_profile(
    agent_id: str,
    destination_url: str,
    *,
    classification: str | None = None,
    regulations: Sequence[str] | None = None,
    data_metadata: Mapping | None = None,
    risk_graph: RiskGraph | None = None,
    drift_detector: DriftDetector | None = None,
    bedrock_client: object | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> ProfileDecision:
    """Blocking form of `required_profile_async`, for a synchronous proposer.

    When there is no event loop running this is `asyncio.run`. When there *is*
    one -- an async proposer reaching for the sync helper -- the coroutine is run
    on a worker thread with its own loop, because the caller's loop is blocked
    and cannot make progress. That is correct but not free, and a graph driver
    bound to the caller's loop will refuse to be used from another one: an async
    caller should await `required_profile_async` instead. Either way the failure
    is fail-secure, not an exception.
    """
    coro_kwargs = {
        "classification": classification,
        "regulations": regulations,
        "data_metadata": data_metadata,
        "risk_graph": risk_graph,
        "drift_detector": drift_detector,
        "bedrock_client": bedrock_client,
        "timeout_seconds": timeout_seconds,
    }
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(required_profile_async(agent_id, destination_url, **coro_kwargs))

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                required_profile_async(agent_id, destination_url, **coro_kwargs),
            )
            return future.result(timeout=timeout_seconds + 1.0)
    except Exception as exc:  # see required_profile_async
        return _fail_secure(exc, agent_id, destination_url)
