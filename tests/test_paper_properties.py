"""Property tests for the guarantees the CipherWeave paper claims.

Each test names the proposition or equation it exercises. These are the tests that
would have caught the paper/implementation divergence.
"""
from __future__ import annotations

import asyncio
import math
import random

import pytest

from cipherweave.cipher_janitor import (
    _mlkem_decapsulate,
    _mlkem_encapsulate,
    _mlkem_generate_keypair,
    mlkem_backend,
)
from cipherweave.drift_detector import DriftDetector, js_divergence, shannon_entropy
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import MockRiskGraph
from cipherweave.scoring import (
    DEFAULT_GAMMA,
    S_FLOAT_SATURATION,
    aggregate_path_risk,
    combine,
    compliance_floor,
    normalize,
    profile_for_score,
)

# --------------------------------------------------------------------------
# Eq. (2)
# --------------------------------------------------------------------------

def test_eq2_strictly_increasing_and_bounded():
    prev = -1.0
    for i in range(0, 2000):
        s = i * 0.01
        r = normalize(s)
        assert 0.0 <= r < 1.0, "r must stay in [0,1)"
        assert r > prev, "r must be strictly increasing in S"
        prev = r
    # Over the reals r never reaches 1; over binary64 it does. Document the boundary
    # rather than claim a guarantee the float type cannot keep.
    assert normalize(S_FLOAT_SATURATION - 1.0) < 1.0
    assert normalize(50.0) == 1.0, "binary64 saturates past S_FLOAT_SATURATION"


def test_eq2_saturation_boundary_is_far_beyond_any_decision_threshold():
    """Saturation is unreachable in practice: QS is already reached at S = 1.61."""
    qs_threshold_mass = -math.log(1 - 0.80)
    assert qs_threshold_mass < 2.0 < S_FLOAT_SATURATION
    assert profile_for_score(normalize(qs_threshold_mass)) == CipherProfile.QUANTUM_SAFE


def test_eq2_never_saturates_unlike_hard_clipping():
    """The failure the smooth aggregator exists to avoid."""
    a, b = normalize(1.5), normalize(9.0)
    assert a != b, "distinct evidence masses must map to distinct scores"
    assert min(1.0, 1.5) == min(1.0, 9.0), "hard clipping would have collapsed these"


# --------------------------------------------------------------------------
# Proposition 2 / Corollary 1 — evidence monotonicity
# --------------------------------------------------------------------------

def _random_graph(rng, n_evidence):
    adjacency = {"agent": ["asset"], "asset": ["endpoint"], "endpoint": []}
    attributes = {
        "agent": {"type": "Agent"},
        "asset": {"type": "DataAsset", "classification": rng.choice(
            ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "TOP_SECRET"])},
        "endpoint": {"type": "Endpoint", "vpc_internal": rng.choice([True, False])},
    }
    for i in range(n_evidence):
        nid = f"ev{i}"
        attach = rng.choice(["asset", "endpoint"])
        adjacency.setdefault(attach, []).append(nid)
        adjacency[nid] = []
        if rng.random() < 0.5:
            attributes[nid] = {"type": "Regulation", "name": rng.choice(
                ["GDPR", "SOX", "PCI_DSS_4", "OTHER"])}
        else:
            attributes[nid] = {"type": "ThreatIndicator", "severity": rng.choice(
                ["LOW", "MEDIUM", "HIGH", "CRITICAL"])}
    return adjacency, attributes


def _score(adjacency, attributes):
    return aggregate_path_risk(["agent", "asset", "endpoint"],
                               neighbors=lambda n: adjacency.get(n, ()),
                               attributes=lambda n: attributes.get(n, {}))


@pytest.mark.parametrize("trial", range(200))
def test_prop2_adding_evidence_never_lowers_score(trial):
    rng = random.Random(trial)
    adjacency, attributes = _random_graph(rng, rng.randint(0, 6))
    before = _score(adjacency, attributes)

    nid = "extra"
    attach = rng.choice(["asset", "endpoint"])
    adjacency.setdefault(attach, []).append(nid)
    adjacency[nid] = []
    attributes[nid] = {"type": "ThreatIndicator", "severity": "HIGH"}
    after = _score(adjacency, attributes)

    assert after.evidence_mass >= before.evidence_mass
    assert after.risk_score >= before.risk_score
    assert profile_for_score(after.risk_score).strength() >= \
        profile_for_score(before.risk_score).strength(), "Corollary 1 violated"


@pytest.mark.parametrize("trial", range(100))
def test_prop2_shortening_a_path_never_lowers_score(trial):
    """An added edge can only decrease l(n); gamma^l is decreasing, so S cannot fall."""
    rng = random.Random(1000 + trial)
    adjacency = {"agent": ["asset"], "asset": ["endpoint"], "endpoint": ["far"], "far": ["ev"], "ev": []}
    attributes = {
        "agent": {"type": "Agent"},
        "asset": {"type": "DataAsset", "classification": "INTERNAL"},
        "endpoint": {"type": "Endpoint", "vpc_internal": False},
        "far": {"type": "Agent"},
        "ev": {"type": "ThreatIndicator", "severity": rng.choice(["LOW", "HIGH", "CRITICAL"])},
    }
    before = _score(adjacency, attributes)
    adjacency["endpoint"].append("ev")          # shortcut: 2 hops -> 1 hop
    after = _score(adjacency, attributes)
    assert after.evidence_mass >= before.evidence_mass
    assert after.risk_score >= before.risk_score


def test_no_risk_reducing_evidence_exposure_is_additive():
    """VPC-internal adds nothing; internet-facing adds evidence. Never subtractive."""
    adjacency = {"endpoint": []}
    vpc = aggregate_path_risk(["endpoint"], lambda n: adjacency.get(n, ()),
                              lambda n: {"type": "Endpoint", "vpc_internal": True})
    inet = aggregate_path_risk(["endpoint"], lambda n: adjacency.get(n, ()),
                               lambda n: {"type": "Endpoint", "vpc_internal": False})
    assert inet.evidence_mass > vpc.evidence_mass
    assert vpc.evidence_mass >= 0.0


# --------------------------------------------------------------------------
# Proposition 1 — per-request cost independent of graph size
# --------------------------------------------------------------------------

def test_prop1_cost_is_independent_of_graph_size_despite_a_shared_hub():
    """Proposition 1 in its load-bearing form: a shared evidence node must not
    re-enter the graph. Before evidence was made terminal this grew linearly
    (301 / 3001 / 15001 visits at n = 100 / 1000 / 5000)."""
    visits = []
    for n in (100, 1000, 5000):
        g = MockRiskGraph()
        eps, assets, edges = [], [], []
        for i in range(n):
            eps.append({"endpoint_id": f"ep_{i}", "url": f"https://h{i}", "vpc_internal": False})
            assets.append({"asset_id": f"as_{i}", "classification": "CONFIDENTIAL"})
            edges += [(f"ag_{i}", "ACCESSES", f"as_{i}"),
                      (f"as_{i}", "STORED_AT", f"ep_{i}"),
                      (f"as_{i}", "GOVERNED_BY", "r_gdpr")]   # one regulation, degree n
        g.seed(agents=[{"agent_id": f"ag_{i}"} for i in range(n)], endpoints=eps,
               assets=assets, regulations=[{"reg_id": "r_gdpr", "name": "GDPR"}], edges=edges)
        i = n // 2
        r = asyncio.run(g.get_path_risk(f"ag_{i}", f"https://h{i}", []))
        visits.append(r.nodes_visited)
    assert len(set(visits)) == 1, f"traversal cost tracked graph size: {visits}"


@pytest.mark.parametrize("total_nodes", [200, 2000, 20000])
def test_prop1_visits_bounded_independently_of_graph_size(total_nodes):
    """A large graph with bounded local degree must not enlarge the traversal."""
    degree, k = 3, 3
    adjacency = {}
    attributes = {}
    for i in range(total_nodes):
        nid = f"n{i}"
        adjacency[nid] = [f"n{(i * degree + j + 1) % total_nodes}" for j in range(degree)]
        attributes[nid] = {"type": "DataAsset", "classification": "INTERNAL"}
    agg = aggregate_path_risk(["n0"], lambda n: adjacency.get(n, ()),
                              lambda n: attributes.get(n, {}), hop_bound=k)
    bound = sum(degree ** i for i in range(k + 1))
    assert agg.visited_nodes <= bound, f"visited {agg.visited_nodes} > bound {bound}"


# --------------------------------------------------------------------------
# Proposition 3 — override dominance (generalised to the lattice join)
# --------------------------------------------------------------------------

ALL = list(CipherProfile)

@pytest.mark.parametrize("a", ALL)
@pytest.mark.parametrize("b", ALL)
def test_prop3_combine_is_never_weaker_than_any_input(a, b):
    out = combine(a, b)
    assert out.strength() >= a.strength()
    assert out.strength() >= b.strength()


def test_prop3_compliance_floor_raises_and_never_lowers():
    assert compliance_floor(["HIPAA"]) == CipherProfile.QUANTUM_SAFE
    assert compliance_floor(["GDPR"]) == CipherProfile.HARDENED
    assert compliance_floor([]) == CipherProfile.CHEAP
    # A mandatory regime wins even when the aggregate is low.
    assert combine(profile_for_score(0.0), compliance_floor(["HIPAA"])) == CipherProfile.QUANTUM_SAFE


def test_mandatory_regime_survives_distance_decay():
    """The case a pure decayed aggregate gets wrong: HIPAA two hops out."""
    adjacency = {"agent": ["asset"], "asset": ["reg"], "reg": []}
    attributes = {"agent": {"type": "Agent"},
                  "asset": {"type": "DataAsset", "classification": "INTERNAL"},
                  "reg": {"type": "Regulation", "name": "HIPAA"}}
    agg = _score(adjacency, attributes)
    assert profile_for_score(agg.risk_score) != CipherProfile.QUANTUM_SAFE, \
        "precondition: decay alone does not reach the QS threshold here"
    final = combine(profile_for_score(agg.risk_score), compliance_floor(agg.regulations))
    assert final == CipherProfile.QUANTUM_SAFE, "mandatory floor must still force QS"


# --------------------------------------------------------------------------
# Eq. (3) — the three drift channels must each fire on their own
# --------------------------------------------------------------------------

WINDOW = 300.0

def _detector():
    return DriftDetector(theta=3.0, alpha=0.2, window_seconds=WINDOW, n_min=20)


async def _establish(d, agent, t0, eps=("a", "b", "c", "d"),
                     profile=CipherProfile.BALANCED, n=600, dt=1.0):
    t = t0
    for i in range(n):
        await d.log_decision(agent, profile, eps[i % len(eps)], 0.3, now=t)
        t += dt
    return t


def _fires_within(d, agent, feed, limit=400):
    """Feed anomalous events; return True if delta crosses theta within `limit`."""
    async def run():
        t = feed["t"]
        for i in range(limit):
            stat = d.drift_statistic(feed["agent"], now=t)
            if stat.delta >= 3.0:
                return True, stat
            await d.log_decision(feed["agent"], feed["profile"], feed["endpoint"](i),
                                 0.3, now=t, update_baseline=False)
            t += feed["dt"]
        return False, d.drift_statistic(feed["agent"], now=t)
    return asyncio.run(run())


def test_eq3_channel_i_destination_entropy_collapse():
    d = _detector()
    t = asyncio.run(_establish(d, "ag", 0.0))
    fired, stat = _fires_within(d, "ag", {"t": t, "agent": "ag", "dt": 1.0,
                                          "profile": CipherProfile.BALANCED,
                                          "endpoint": lambda i: "a"})
    assert fired, f"entropy collapse not detected (delta={stat.delta:.2f})"
    assert stat.dominant_channel() == "destination_entropy"


def test_eq3_channel_ii_request_rate_spike():
    d = _detector()
    t = asyncio.run(_establish(d, "ag", 0.0))
    fired, stat = _fires_within(d, "ag", {"t": t, "agent": "ag", "dt": 0.02,
                                          "profile": CipherProfile.BALANCED,
                                          "endpoint": lambda i: "abcd"[i % 4]},
                                limit=400)
    assert fired, f"rate spike not detected (delta={stat.delta:.2f})"


def test_eq3_channel_iii_profile_mix_shift():
    d = _detector()
    t = asyncio.run(_establish(d, "ag", 0.0))
    fired, stat = _fires_within(d, "ag", {"t": t, "agent": "ag", "dt": 1.0,
                                          "profile": CipherProfile.QUANTUM_SAFE,
                                          "endpoint": lambda i: "abcd"[i % 4]},
                                limit=400)
    assert fired, f"profile-mix shift not detected (delta={stat.delta:.2f})"


def test_eq3_cold_start_forces_override_without_faking_a_drift_score():
    """Cold start is a policy, not a measurement.

    delta reports observed drift; with no baseline there is no observed drift, so
    it stays 0 and the cold_start flag carries the fail-secure decision. Reporting
    infinity conflated the two and made every benign traffic lull outscore every
    real attack (corpus AUC 0.448, worse than chance).
    """
    d = _detector()
    stat = d.drift_statistic("never_seen")
    assert stat.cold_start and stat.delta == 0.0
    fired, alert = asyncio.run(
        d.detect_anomaly("never_seen", CipherProfile.BALANCED, [], "ep"))
    assert fired and alert.alert_type == "NEW_AGENT"


def test_eq3_max_not_sum_resists_partial_suppression():
    """Two channels held at baseline must not dilute a third below threshold."""
    d = _detector()
    t = asyncio.run(_establish(d, "ag", 0.0))
    # rate and profile mix held exactly at baseline; only entropy departs.
    fired, stat = _fires_within(d, "ag", {"t": t, "agent": "ag", "dt": 1.0,
                                          "profile": CipherProfile.BALANCED,
                                          "endpoint": lambda i: "a"})
    assert fired
    assert stat.z_rate < 3.0 and stat.z_mix < 3.0, "precondition: other channels quiet"
    assert stat.z_entropy >= 3.0, "precondition: entropy is the firing channel"
    assert stat.delta == max(stat.z_entropy, stat.z_rate, stat.z_mix)
    weighted_sum = (stat.z_entropy + stat.z_rate + stat.z_mix) / 3.0
    assert weighted_sum < 3.0, "a mean-combiner would have missed this; max caught it"


def test_read_only_operations_exempt_from_override():
    d = _detector()
    fired, _ = asyncio.run(
        d.detect_anomaly("cold", CipherProfile.BALANCED, [], "ep", operation="status"))
    assert not fired


# --------------------------------------------------------------------------
# SEC-1 — post-quantum must be real or fail closed
# --------------------------------------------------------------------------

def test_sec1_mlkem_backend_present_and_correct():
    assert mlkem_backend() is not None, "no ML-KEM backend; QUANTUM_SAFE cannot be honoured"
    pk, sk = _mlkem_generate_keypair()
    assert (len(pk), len(sk)) == (1184, 2400), "not ML-KEM-768 parameter sizes"
    ct, ss_sender = _mlkem_encapsulate(pk)
    ss_receiver = _mlkem_decapsulate(sk, ct)
    assert len(ct) == 1088 and len(ss_sender) == 32
    assert ss_sender == ss_receiver, "KEM shared secrets must agree"


def test_sec1_two_keypairs_do_not_share_a_secret():
    pk1, _ = _mlkem_generate_keypair()
    _, sk2 = _mlkem_generate_keypair()
    ct, ss1 = _mlkem_encapsulate(pk1)
    assert _mlkem_decapsulate(sk2, ct) != ss1, "unrelated key must not recover the secret"


# --------------------------------------------------------------------------
# End-to-end through the graph
# --------------------------------------------------------------------------

def _graph(classification="CONFIDENTIAL", regs=("GDPR",), threats=(), vpc=False):
    g = MockRiskGraph()
    edges = [("ag", "ACCESSES", "as"), ("as", "STORED_AT", "ep")]
    regulations = []
    for r in regs:
        rid = f"reg_{r.lower()}"
        regulations.append({"reg_id": rid, "name": r})
        edges.append(("as", "GOVERNED_BY", rid))
    threat_nodes = []
    for i, sev in enumerate(threats):
        tid = f"t{i}"
        threat_nodes.append({"indicator_id": tid, "name": f"IND{i}", "severity": sev})
        edges.append(("ep", "EXPOSED_TO", tid))
    g.seed(agents=[{"agent_id": "ag"}],
           endpoints=[{"endpoint_id": "ep", "url": "https://x", "vpc_internal": vpc}],
           assets=[{"asset_id": "as", "classification": classification}],
           regulations=regulations, threats=threat_nodes, edges=edges)
    return g


def test_end_to_end_produces_auditable_trail():
    r = asyncio.run(_graph().get_path_risk("ag", "https://x", []))
    assert r.evidence_trail, "no audit trail"
    assert r.evidence_mass > 0 and 0.0 <= r.risk_score < 1.0
    assert any("Regulation:GDPR" in row for row in r.evidence_trail)
    assert r.compliance_floor == CipherProfile.HARDENED


def test_end_to_end_threat_raises_profile():
    calm = asyncio.run(_graph(threats=()).get_path_risk("ag", "https://x", []))
    hot = asyncio.run(_graph(threats=("CRITICAL",)).get_path_risk("ag", "https://x", []))
    assert hot.risk_score > calm.risk_score
    assert hot.recommended_profile.strength() >= calm.recommended_profile.strength()
    assert hot.threat_proximity == 1


def test_end_to_end_vpc_internal_public_data_is_cheap():
    r = asyncio.run(_graph(classification="PUBLIC", regs=(), vpc=True).get_path_risk("ag", "https://x", []))
    assert r.recommended_profile == CipherProfile.CHEAP


# --------------------------------------------------------------------------
# Flow isolation — a hub node must not join unrelated flows
# --------------------------------------------------------------------------

def test_agent_hub_does_not_leak_unrelated_flow_risk():
    """A benign flow must not inherit risk from a different flow the agent also has.

    The agent accesses two assets: a benign INTERNAL one on a VPC endpoint, and a
    RESTRICTED one governed by HIPAA on an internet endpoint carrying a CRITICAL
    threat. Scoring the benign flow must not collect the other flow's evidence.
    """
    g = MockRiskGraph()
    g.seed(
        agents=[{"agent_id": "ag"}],
        endpoints=[
            {"endpoint_id": "ep_safe", "url": "https://safe", "vpc_internal": True},
            {"endpoint_id": "ep_risky", "url": "https://risky", "vpc_internal": False},
        ],
        assets=[
            {"asset_id": "as_safe", "classification": "INTERNAL"},
            {"asset_id": "as_risky", "classification": "RESTRICTED"},
        ],
        regulations=[{"reg_id": "r_hipaa", "name": "HIPAA"}],
        threats=[{"indicator_id": "t_crit", "name": "APT", "severity": "CRITICAL"}],
        edges=[
            ("ag", "ACCESSES", "as_safe"), ("as_safe", "STORED_AT", "ep_safe"),
            ("ag", "ACCESSES", "as_risky"), ("as_risky", "STORED_AT", "ep_risky"),
            ("as_risky", "GOVERNED_BY", "r_hipaa"), ("ep_risky", "EXPOSED_TO", "t_crit"),
        ],
    )
    safe = asyncio.run(g.get_path_risk("ag", "https://safe", []))
    assert safe.recommended_profile == CipherProfile.CHEAP, (
        f"benign flow inherited unrelated risk: {safe.evidence_trail}")
    assert "HIPAA" not in safe.regulations_crossed
    assert safe.threat_proximity == 999

    risky = asyncio.run(g.get_path_risk("ag", "https://risky", []))
    assert risky.recommended_profile == CipherProfile.QUANTUM_SAFE
    assert "HIPAA" in risky.regulations_crossed
