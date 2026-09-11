"""Behavioral drift detection — the override channel of the CipherWeave paper.

Implements Eq. (3):

    delta_a = max( |H_a - mu_H| / max(sigma_H, eps),
                   (lambda_a - mu_lambda)^+ / max(sigma_lambda, eps),
                   D_JS(q_hat_a || q_bar_a) / tau_J )

over a trailing window W_a of duration T, with EWMA baselines, and fires a
fail-secure override when delta_a >= theta.

Three properties are deliberate, not incidental:

* **Input disjointness.** Every input here is per-agent decision history. None of
  it is read from the risk graph. An adversary who poisons graph state does not
  thereby gain influence over delta_a, and vice versa.

* **Combination by max, not weighted sum.** Under a weighted sum an adversary who
  holds two channels at baseline dilutes a strong third-channel signal below
  threshold. Under max every channel keeps unilateral authority to fire, so
  evading detection requires defeating *all* of them.

* **Cold start is drift.** An agent with fewer than `n_min` observations has no
  usable baseline, so delta_a := infinity and it receives the strongest profile
  until a baseline accumulates. Fail-secure, at a cost in warm-up.

Alongside the statistic, a small set of *semantic* rules (a downgrade request on
sensitive data, a large strength drop, a first-seen endpoint) is retained as a
separate raise-only channel. Those catch single-shot events that a distributional
statistic is not designed to see; they are reported distinctly from delta_a so the
two are never confused in an audit record.
"""

from __future__ import annotations

import logging
import math
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime

from cipherweave.models import AgentDecisionRecord, SecurityAlert
from cipherweave.profiles import CipherProfile

logger = logging.getLogger(__name__)

_SENSITIVE_TAGS: frozenset[str] = frozenset({"PII", "PHI", "PCI", "TRADE_SECRET"})

# Defaults (Section VII of the paper)
DEFAULT_THETA: float = 3.0          # override threshold
DEFAULT_ALPHA: float = 0.2          # EWMA decay
DEFAULT_TAU_JS: float = 0.25        # JS-divergence scale (a near-total mix flip clears theta)
DEFAULT_WINDOW_SECONDS: float = 300.0
DEFAULT_N_MIN: int = 20             # cold-start floor
VARIANCE_FLOOR: float = 1e-3        # epsilon

#: Operations exempt from override: side-effect-free and cannot mutate state.
READ_ONLY_OPERATIONS: frozenset[str] = frozenset({"status", "health", "get_status"})

_PROFILES: tuple[CipherProfile, ...] = (
    CipherProfile.CHEAP,
    CipherProfile.BALANCED,
    CipherProfile.HARDENED,
    CipherProfile.QUANTUM_SAFE,
)


def shannon_entropy(counts: dict[str, int]) -> float:
    """H = -sum p log2 p over an empirical frequency map."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


def js_divergence(p: list[float], q: list[float]) -> float:
    """Jensen-Shannon divergence in [0, 1] (log base 2)."""
    if len(p) != len(q):
        raise ValueError("distributions must have equal support")

    def _kl(a: list[float], b: list[float]) -> float:
        total = 0.0
        for ai, bi in zip(a, b):
            if ai > 0 and bi > 0:
                total += ai * math.log2(ai / bi)
        return total

    m = [(pi + qi) / 2.0 for pi, qi in zip(p, q)]
    return max(0.0, min(1.0, 0.5 * _kl(p, m) + 0.5 * _kl(q, m)))


class _Baseline:
    """EWMA mean/variance for a scalar channel."""

    __slots__ = ("mean", "var", "alpha", "n")

    def __init__(self, alpha: float) -> None:
        self.mean = 0.0
        self.var = 0.0
        self.alpha = alpha
        self.n = 0

    def update(self, x: float) -> None:
        if self.n == 0:
            self.mean, self.var = x, 0.0
        else:
            diff = x - self.mean
            self.mean += self.alpha * diff
            self.var = (1.0 - self.alpha) * (self.var + self.alpha * diff * diff)
        self.n += 1

    @property
    def sigma(self) -> float:
        return math.sqrt(max(self.var, 0.0))


class _AgentState:
    def __init__(self, alpha: float) -> None:
        self.records: deque[tuple[float, CipherProfile, str]] = deque(maxlen=4096)
        self.entropy = _Baseline(alpha)
        self.rate = _Baseline(alpha)
        self.profile_mix: list[float] = [1.0 / len(_PROFILES)] * len(_PROFILES)
        self.alpha = alpha

    def update_mix(self, profile: CipherProfile) -> None:
        idx = _PROFILES.index(profile)
        self.profile_mix = [
            (1.0 - self.alpha) * m + (self.alpha if i == idx else 0.0)
            for i, m in enumerate(self.profile_mix)
        ]


class DriftStatistic:
    """The value of Eq. (3) plus the per-channel terms that produced it."""

    __slots__ = ("delta", "z_entropy", "z_rate", "z_mix", "cold_start", "window_size")

    def __init__(self, delta, z_entropy, z_rate, z_mix, cold_start, window_size):
        self.delta = delta
        self.z_entropy = z_entropy
        self.z_rate = z_rate
        self.z_mix = z_mix
        self.cold_start = cold_start
        self.window_size = window_size

    def dominant_channel(self) -> str:
        if self.cold_start:
            return "cold_start"
        return max(
            (("destination_entropy", self.z_entropy),
             ("request_rate", self.z_rate),
             ("profile_mix", self.z_mix)),
            key=lambda kv: kv[1],
        )[0]

    def as_dict(self) -> dict:
        return {
            "delta": None if self.delta == math.inf else round(self.delta, 4),
            "z_entropy": round(self.z_entropy, 4),
            "z_rate": round(self.z_rate, 4),
            "z_mix": round(self.z_mix, 4),
            "cold_start": self.cold_start,
            "window_size": self.window_size,
            "dominant_channel": self.dominant_channel(),
        }


class DriftDetector:
    """Per-agent behavioral drift detection with fail-secure override."""

    def __init__(
        self,
        window_size: int = 100,
        *,
        theta: float = DEFAULT_THETA,
        alpha: float = DEFAULT_ALPHA,
        tau_js: float = DEFAULT_TAU_JS,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        n_min: int = DEFAULT_N_MIN,
    ) -> None:
        self._window_size = window_size
        self._theta = theta
        self._alpha = alpha
        self._tau_js = tau_js
        self._window_seconds = window_seconds
        self._n_min = n_min
        self._state: dict[str, _AgentState] = defaultdict(lambda: _AgentState(alpha))
        self._history: dict[str, deque[AgentDecisionRecord]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

    # --- Eq. (3) ---------------------------------------------------------

    def _window(self, agent_id: str, now: float) -> list[tuple[float, CipherProfile, str]]:
        cutoff = now - self._window_seconds
        return [rec for rec in self._state[agent_id].records if rec[0] >= cutoff]

    def drift_statistic(self, agent_id: str, now: float | None = None) -> DriftStatistic:
        """Compute delta_a from the agent's trailing window against its EWMA baselines."""
        now = time.monotonic() if now is None else now
        st = self._state[agent_id]
        window = self._window(agent_id, now)

        if len(window) < self._n_min:
            return DriftStatistic(math.inf, 0.0, 0.0, 0.0, True, len(window))

        # (i) destination entropy — two-sided
        ep_counts: dict[str, int] = defaultdict(int)
        for _, _, ep in window:
            ep_counts[ep] += 1
        h = shannon_entropy(ep_counts)
        z_h = abs(h - st.entropy.mean) / max(st.entropy.sigma, VARIANCE_FLOOR)

        # (ii) request rate — one-sided (only increases are suspicious).
        # A rate deviation is only meaningful once the window spans enough time to
        # be comparable with the baseline; during warm-up the window is still
        # filling, and scoring it would flag every agent that merely starts up.
        lam = len(window) / self._window_seconds
        span = window[-1][0] - window[0][0]
        if span < 0.5 * self._window_seconds:
            z_lam = 0.0
        else:
            z_lam = max(lam - st.rate.mean, 0.0) / max(st.rate.sigma, VARIANCE_FLOOR)

        # (iii) profile-mix divergence
        mix_counts = [0.0] * len(_PROFILES)
        for _, prof, _ in window:
            mix_counts[_PROFILES.index(prof)] += 1.0
        total = sum(mix_counts) or 1.0
        q_hat = [c / total for c in mix_counts]
        z_mix = js_divergence(q_hat, st.profile_mix) / self._tau_js

        return DriftStatistic(max(z_h, z_lam, z_mix), z_h, z_lam, z_mix, False, len(window))

    # --- Detection -------------------------------------------------------

    async def detect_anomaly(
        self,
        agent_id: str,
        requested_profile: CipherProfile,
        data_tags: list[str],
        endpoint_id: str,
        operation: str | None = None,
        now: float | None = None,
    ) -> tuple[bool, SecurityAlert | None]:
        """Return (override_required, alert). Override forces QUANTUM_SAFE upstream."""
        if operation is not None and operation in READ_ONLY_OPERATIONS:
            return False, None

        stat = self.drift_statistic(agent_id, now=now)

        if stat.cold_start:
            return True, _alert(
                agent_id, "NEW_AGENT", "HIGH",
                f"Agent '{agent_id}' has {stat.window_size} observations in the trailing "
                f"window; {self._n_min} required for a baseline. delta_a := infinity "
                "(fail-secure).",
                "Allow the agent to accumulate a baseline before relaxing policy.",
                stat,
            )

        if stat.delta >= self._theta:
            return True, _alert(
                agent_id, "DRIFT_DETECTED", "CRITICAL",
                f"delta_a={stat.delta:.2f} >= theta={self._theta:.2f} on channel "
                f"'{stat.dominant_channel()}' (z_entropy={stat.z_entropy:.2f}, "
                f"z_rate={stat.z_rate:.2f}, z_mix={stat.z_mix:.2f}). Overriding to QUANTUM_SAFE.",
                "Investigate agent behavior; possible credential compromise.",
                stat,
            )

        # Semantic channel — single-shot events a distributional statistic cannot see.
        semantic = self._semantic_rules(agent_id, requested_profile, data_tags, endpoint_id)
        if semantic is not None:
            return True, _alert(agent_id, semantic[0], semantic[1], semantic[2], semantic[3], stat)

        return False, None

    def _semantic_rules(
        self,
        agent_id: str,
        requested_profile: CipherProfile,
        data_tags: list[str],
        endpoint_id: str,
    ) -> tuple[str, str, str, str] | None:
        history = self._history[agent_id]
        if not history:
            return None

        counts: dict[CipherProfile, int] = defaultdict(int)
        seen_endpoints: set[str] = set()
        for rec in history:
            counts[rec.profile] += 1
            seen_endpoints.add(rec.endpoint_id)
        dominant = max(counts, key=lambda p: counts[p])

        if (
            _SENSITIVE_TAGS & set(data_tags)
            and requested_profile == CipherProfile.CHEAP
            and dominant.strength() >= CipherProfile.BALANCED.strength()
        ):
            return ("DRIFT_DETECTED", "CRITICAL",
                    f"Agent '{agent_id}' requests CHEAP for sensitive data {data_tags}; "
                    f"typical profile is {dominant.value}. Overriding to QUANTUM_SAFE.",
                    "Investigate agent configuration or potential compromise.")

        if endpoint_id not in seen_endpoints:
            return ("UNAUTHORIZED_ENDPOINT", "HIGH",
                    f"Agent '{agent_id}' requests a key for first-seen endpoint "
                    f"'{endpoint_id}'. Overriding to QUANTUM_SAFE.",
                    "Verify the agent is authorized for this endpoint.")

        if dominant.strength() - requested_profile.strength() >= 2:
            return ("DRIFT_DETECTED", "HIGH",
                    f"Agent '{agent_id}' profile downgrade {dominant.value} -> "
                    f"{requested_profile.value}. Overriding to QUANTUM_SAFE.",
                    "Review agent policy and authorization scope.")
        return None

    # --- History ---------------------------------------------------------

    async def log_decision(
        self,
        agent_id: str,
        profile: CipherProfile,
        endpoint_id: str,
        risk_score: float,
        data_tags: list[str] | None = None,
        now: float | None = None,
        update_baseline: bool = True,
    ) -> None:
        """Record a decision and, unless suppressed, fold it into the EWMA baselines.

        Baselines are updated *after* the statistic for this request has been
        computed, so an anomalous observation cannot mask itself. Callers should
        pass ``update_baseline=False`` for a decision that was flagged as drift:
        a detector that learns from the anomaly it just reported will normalise an
        ongoing attack within a few observations.
        """
        now = time.monotonic() if now is None else now
        st = self._state[agent_id]
        st.records.append((now, profile, endpoint_id))

        if not update_baseline:
            self._history[agent_id].append(
                AgentDecisionRecord(
                    agent_id=agent_id, profile=profile, endpoint_id=endpoint_id,
                    data_tags=list(data_tags or []), risk_score=risk_score,
                )
            )
            return

        window = self._window(agent_id, now)
        ep_counts: dict[str, int] = defaultdict(int)
        for _, _, ep in window:
            ep_counts[ep] += 1
        st.entropy.update(shannon_entropy(ep_counts))
        st.rate.update(len(window) / self._window_seconds)
        st.update_mix(profile)

        self._history[agent_id].append(
            AgentDecisionRecord(
                agent_id=agent_id,
                profile=profile,
                endpoint_id=endpoint_id,
                data_tags=list(data_tags or []),
                risk_score=risk_score,
            )
        )

    def get_history(self, agent_id: str) -> list[AgentDecisionRecord]:
        return list(self._history.get(agent_id, []))


def _alert(agent_id, alert_type, severity, message, action, stat=None) -> SecurityAlert:
    if stat is not None:
        message = f"{message} [{stat.as_dict()}]"
    return SecurityAlert(
        alert_id=f"cw_alert_{uuid.uuid4().hex[:8]}",
        timestamp=datetime.utcnow(),
        agent_id=agent_id,
        alert_type=alert_type,
        severity=severity,
        message=message,
        recommended_action=action,
    )
