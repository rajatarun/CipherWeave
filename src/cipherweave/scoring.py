"""Path-risk aggregation — the scoring model of the CipherWeave paper.

Implements, in one driver-agnostic place:

  * Eq. (1)  S(a,d,e) = sum_{n in N(a,d,e)} w(n) * gamma^{l(n)}
  * Eq. (2)  r(a,d,e) = 1 - exp(-S)                       in [0, 1)
  * Algorithm 1 — bounded multi-source BFS collecting evidence nodes, where the
    first visit to a node is its minimum hop distance from the seed set.
  * Pi(.)    — fixed, monotone non-decreasing threshold map r -> CipherProfile.

and the two *raise-only* operators that sit beside the score:

  * compliance_floor(regulations) — mandatory regimes (HIPAA/ITAR ...) impose a
    minimum profile that no amount of low risk elsewhere can lower.
  * (in drift_detector) the drift override.

Why a floor operator exists
---------------------------
A decayed aggregate expresses *graded* evidence well and *mandatory* rules badly:
HIPAA applies or it does not, and it must not be attenuated to HARDENED merely
because the Regulation node sits two hops out. Rather than inflate weights until
mandates happen to clear a threshold — which is fragile and hides the intent —
mandatory regimes are a separate floor. Because every operator only ever raises
the profile, their composition is a join over the profile lattice and the
override-dominance property is preserved (see `combine`).

Exposure is modelled as evidence, not as a discount
---------------------------------------------------
An internet-facing endpoint *adds* evidence; a VPC-internal one adds none. The
equivalent "VPC-internal lowers risk" formulation would make added evidence able
to weaken a profile, breaking monotonicity (Prop. 2). Same policy, monotone form.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from cipherweave.profiles import CipherProfile

# --- Model constants ------------------------------------------------------

DEFAULT_GAMMA: float = 0.6
DEFAULT_HOP_BOUND: int = 3

# Calibration. Weights are set so the aggregate reproduces the intended policy on
# the canonical cases, rather than escalating everything to the strongest profile
# (with gamma=0.6, evidence one hop out contributes 0.6*w; thresholds in terms of S
# are CHEAP<0.357, BALANCED<0.916, HARDENED<1.609, QUANTUM_SAFE>=1.609):
#   INTERNAL + VPC-internal, no evidence      S=0.15  -> CHEAP
#   INTERNAL + internet-facing                S=0.50  -> BALANCED
#   CONFIDENTIAL + internet + GDPR@1hop       S=1.46  -> HARDENED
#   RESTRICTED + internet                     S=1.75  -> QUANTUM_SAFE
#   INTERNAL + internet + HIGH threat@1hop    S=1.70  -> QUANTUM_SAFE
# Mandatory regimes (HIPAA/ITAR) are carried by the compliance floor, not by weight
# inflation, so they hold at any hop distance.

#: w(n) for Regulation evidence nodes, by regime strictness.
REGULATION_WEIGHTS: dict[str, float] = {
    "HIPAA": 1.8,
    "ITAR": 1.8,
    "GDPR": 0.6,
    "PCI_DSS_4": 0.6,
    "SOX": 0.55,
}
DEFAULT_REGULATION_WEIGHT: float = 0.3

#: w(n) for ThreatIndicator evidence nodes, by severity.
THREAT_WEIGHTS: dict[str, float] = {
    "CRITICAL": 2.6,
    "HIGH": 2.0,
    "MEDIUM": 1.2,
    "LOW": 0.6,
}
DEFAULT_THREAT_WEIGHT: float = 2.0

#: w(n) contributed by a DataAsset's classification, at the asset's hop distance.
CLASSIFICATION_WEIGHTS: dict[str, float] = {
    "PUBLIC": 0.0,
    "INTERNAL": 0.15,
    "CONFIDENTIAL": 0.75,
    "RESTRICTED": 1.40,
    "TOP_SECRET": 1.90,
}

#: w(n) contributed by an internet-facing (non-VPC-internal) Endpoint.
EXPOSURE_WEIGHT_INTERNET: float = 0.35
EXPOSURE_WEIGHT_VPC: float = 0.0

#: Regimes imposing a mandatory minimum profile.
QUANTUM_MANDATORY_REGS: frozenset[str] = frozenset({"HIPAA", "ITAR"})
HARDENED_MANDATORY_REGS: frozenset[str] = frozenset({"GDPR", "PCI_DSS_4", "SOX"})

#: Pi(.) — monotone non-decreasing threshold table, strongest first.
PROFILE_THRESHOLDS: tuple[tuple[float, CipherProfile], ...] = (
    (0.80, CipherProfile.QUANTUM_SAFE),
    (0.60, CipherProfile.HARDENED),
    (0.30, CipherProfile.BALANCED),
    (0.00, CipherProfile.CHEAP),
)

EVIDENCE_TYPES: frozenset[str] = frozenset({"Regulation", "ThreatIndicator"})

#: Node types that are scored but never expanded *through*.
#:
#: Two distinct hub problems make this necessary, and both were found by measuring
#: the implementation rather than by reading the model.
#:
#: 1. An Agent is adjacent to every asset it has ever accessed. Expanding through it
#:    joins unrelated flows: scoring a benign INTERNAL/VPC flow would collect the
#:    HIPAA regulation governing some *other* asset and the threat attached to some
#:    *other* endpoint, so every decision for a busy agent converges on QUANTUM_SAFE.
#:
#: 2. Evidence nodes are themselves hubs. A regulation such as GDPR is attached to
#:    every asset it governs, so expanding through it re-enters the whole graph: node
#:    visits grow linearly with |V| (measured: 301 / 3001 / 15001 visits at n = 100 /
#:    1000 / 5000), which destroys the locality Proposition 1 depends on. It is also
#:    semantically wrong — HIPAA governing this asset does not make every other
#:    HIPAA-governed asset relevant to this flow.
#:
#: Evidence is therefore terminal: scored where it is found, never traversed onward.
NON_EXPANDING_TYPES: frozenset[str] = frozenset({"Agent"}) | EVIDENCE_TYPES


# --- Evidence ------------------------------------------------------------

@dataclass(frozen=True)
class Evidence:
    """One evidence contribution: node id, kind, weight w(n), hop distance l(n)."""

    node_id: str
    kind: str
    weight: float
    hops: int

    @property
    def contribution(self) -> float:
        """w(n) * gamma^l(n) is computed against a gamma supplied by the caller."""
        raise NotImplementedError  # contribution is gamma-dependent; see RiskAggregate

    def term(self, gamma: float) -> float:
        return self.weight * (gamma ** self.hops)


@dataclass
class RiskAggregate:
    """Result of Algorithm 1: the score, its inputs, and a reconstructable trail."""

    evidence_mass: float          # S, Eq. (1)
    risk_score: float             # r, Eq. (2)
    evidence: list[Evidence] = field(default_factory=list)
    visited_nodes: int = 0
    edges_relaxed: int = 0
    gamma: float = DEFAULT_GAMMA
    hop_bound: int = DEFAULT_HOP_BOUND

    @property
    def regulations(self) -> list[str]:
        return sorted({e.node_id for e in self.evidence if e.kind == "Regulation"})

    @property
    def threat_proximity(self) -> int:
        """Minimum hop distance to any ThreatIndicator; 999 when none is reachable."""
        hops = [e.hops for e in self.evidence if e.kind == "ThreatIndicator"]
        return min(hops) if hops else 999

    def explain(self) -> list[str]:
        """Per-term breakdown, strongest contribution first — for the audit record."""
        rows = sorted(self.evidence, key=lambda e: e.term(self.gamma), reverse=True)
        return [
            f"{e.kind}:{e.node_id} w={e.weight:.2f} hops={e.hops} "
            f"term={e.term(self.gamma):.4f}"
            for e in rows
        ]


# --- Graph view protocol -------------------------------------------------

#: neighbors(node_id) -> iterable of adjacent node ids
NeighborFn = Callable[[str], Iterable[str]]
#: attributes(node_id) -> mapping with at least {"type": ...}; may carry weight hints
AttrFn = Callable[[str], dict]


def evidence_weight(attrs: dict) -> float:
    """w(n) for an evidence node, from its stored attributes.

    A stored `weight` overrides the table, but only when actually present: graph
    drivers return an explicit None for an absent property, so `.get(k, default)`
    is not sufficient here and the None case must fall through to the table.
    """
    kind = attrs.get("type")
    override = attrs.get("weight")
    if kind == "Regulation":
        if override is not None:
            return float(override)
        name = str(attrs.get("name") or "").upper()
        return REGULATION_WEIGHTS.get(name, DEFAULT_REGULATION_WEIGHT)
    if kind == "ThreatIndicator":
        if override is not None:
            return float(override)
        sev = str(attrs.get("severity") or "").upper()
        return THREAT_WEIGHTS.get(sev, DEFAULT_THREAT_WEIGHT)
    return 0.0


def seed_weight(attrs: dict) -> float:
    """w(n) contributed by a *seed* node's own properties (classification, exposure)."""
    kind = attrs.get("type")
    if kind == "DataAsset":
        cls = str(attrs.get("classification") or "INTERNAL").upper()
        return CLASSIFICATION_WEIGHTS.get(cls, CLASSIFICATION_WEIGHTS["INTERNAL"])
    if kind == "Endpoint":
        return EXPOSURE_WEIGHT_VPC if attrs.get("vpc_internal") else EXPOSURE_WEIGHT_INTERNET
    return 0.0


# --- Algorithm 1 ---------------------------------------------------------

def aggregate_path_risk(
    seeds: Iterable[str],
    neighbors: NeighborFn,
    attributes: AttrFn,
    *,
    hop_bound: int = DEFAULT_HOP_BOUND,
    gamma: float = DEFAULT_GAMMA,
    no_expand: frozenset[str] = NON_EXPANDING_TYPES,
) -> RiskAggregate:
    """Algorithm 1 — bounded multi-source BFS aggregating evidence into S and r.

    The first visit to a node is its minimum hop distance from the seed set, which
    is exactly the min-over-seeds that Eq. (1) requires; later encounters are
    skipped rather than re-scored.

    Nodes whose type is in `no_expand` are scored but not expanded through, so hub
    nodes cannot join unrelated flows into one score (see NON_EXPANDING_TYPES).

    Cost is O(min(|V|, |seeds| * sum_{i<=k} D^i)) node visits for maximum
    out-degree D (Proposition 1), independent of total graph size when D^k << |V|.
    """
    seen: set[str] = set()
    evidence: list[Evidence] = []
    total = 0.0
    edges_relaxed = 0

    queue: deque[tuple[str, int]] = deque()
    for s in seeds:
        if s is not None:
            queue.append((s, 0))

    while queue:
        node_id, hops = queue.popleft()
        if node_id in seen or hops > hop_bound:
            continue
        seen.add(node_id)

        attrs = attributes(node_id) or {}
        kind = attrs.get("type")

        if kind in EVIDENCE_TYPES:
            w = evidence_weight(attrs)
            if w:
                ev = Evidence(node_id=str(attrs.get("name", node_id)), kind=str(kind),
                              weight=w, hops=hops)
                evidence.append(ev)
                total += ev.term(gamma)
        else:
            # Seed-style nodes contribute their own intrinsic properties.
            w = seed_weight(attrs)
            if w:
                ev = Evidence(node_id=node_id, kind=f"{kind}:intrinsic", weight=w, hops=hops)
                evidence.append(ev)
                total += ev.term(gamma)

        if hops < hop_bound and kind not in no_expand:
            for nbr in neighbors(node_id):
                edges_relaxed += 1
                if nbr not in seen:
                    queue.append((nbr, hops + 1))

    return RiskAggregate(
        evidence_mass=total,
        risk_score=normalize(total),
        evidence=evidence,
        visited_nodes=len(seen),
        edges_relaxed=edges_relaxed,
        gamma=gamma,
        hop_bound=hop_bound,
    )


#: Beyond this evidence mass, 1 - exp(-S) rounds to exactly 1.0 in IEEE-754 binary64,
#: because exp(-S) falls below the representable spacing near 1.0 (~1.1e-16).
S_FLOAT_SATURATION: float = 36.7


def normalize(evidence_mass: float) -> float:
    """Eq. (2): r = 1 - exp(-S). Strictly increasing on [0, inf), bounded in [0, 1).

    NUMERICAL CAVEAT: that guarantee holds over the reals, not over binary64. For
    S greater than roughly `S_FLOAT_SATURATION` (~36.7) the result rounds to exactly
    1.0 and strictness is lost — the same saturation failure that motivated rejecting
    `min(1, S)`, merely relocated to a far higher threshold. Reaching it requires
    absurd evidence (dozens of maximum-weight indicators at zero hops), so it does
    not arise in practice, but comparisons that must remain strict should order on
    `RiskAggregate.evidence_mass` (S, unbounded and exact) rather than on r. Profile
    selection is unaffected: everything past S = 1.61 is already QUANTUM_SAFE.
    """
    if evidence_mass < 0:
        raise ValueError("evidence mass must be non-negative")
    return 1.0 - math.exp(-evidence_mass)


# --- Pi(.) and the raise-only operators ----------------------------------

def profile_for_score(risk_score: float) -> CipherProfile:
    """Pi(r) — fixed monotone non-decreasing threshold map."""
    for threshold, profile in PROFILE_THRESHOLDS:
        if risk_score >= threshold:
            return profile
    return CipherProfile.CHEAP


def compliance_floor(regulations: Iterable[str]) -> CipherProfile:
    """Mandatory minimum profile imposed by regime membership (raise-only)."""
    regs = {str(r).upper() for r in regulations}
    if regs & QUANTUM_MANDATORY_REGS:
        return CipherProfile.QUANTUM_SAFE
    if regs & HARDENED_MANDATORY_REGS:
        return CipherProfile.HARDENED
    return CipherProfile.CHEAP


def combine(*profiles: CipherProfile) -> CipherProfile:
    """Join over the profile lattice: the strongest of its arguments.

    Every mechanism that can affect the outcome (Pi(r), the compliance floor, the
    drift override) enters here, so the returned profile is never weaker than any
    individual mechanism demanded. This is the general form of Proposition 3.
    """
    best = CipherProfile.CHEAP
    for p in profiles:
        if p is not None and p.strength() > best.strength():
            best = p
    return best


def justify(aggregate: RiskAggregate, floor: CipherProfile, final: CipherProfile) -> str:
    """One-line human-readable rationale for the audit record."""
    top = sorted(aggregate.evidence, key=lambda e: e.term(aggregate.gamma), reverse=True)[:3]
    drivers = ", ".join(f"{e.kind.split(':')[0]}:{e.node_id}@{e.hops}h" for e in top) or "no evidence"
    base = (
        f"Selected {final.value}: S={aggregate.evidence_mass:.3f} -> "
        f"r={aggregate.risk_score:.3f} (gamma={aggregate.gamma}, "
        f"k={aggregate.hop_bound}); drivers: {drivers}"
    )
    if floor.strength() > profile_for_score(aggregate.risk_score).strength():
        base += f"; raised to {final.value} by mandatory-regime floor"
    return base
