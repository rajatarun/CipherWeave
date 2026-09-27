"""The extended drift channels, and the evaluation fixes that make their numbers mean something.

Each channel is tested against the attacker it exists for, and against the same
traffic with the extended channels off, so the test shows the channel is what
catches it rather than one of the original three.
"""
from __future__ import annotations

import asyncio
import os
import random
import sys

import pytest

from cipherweave.drift_detector import DriftDetector
from cipherweave.profiles import CipherProfile as P

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evaluation"))

ENDPOINTS = [f"ep{i}" for i in range(5)]


async def _replay(d: DriftDetector, events, agent="a"):
    for t, ep, prof, tags in events:
        await d.log_decision(agent, prof, ep, 0.3, data_tags=tags, now=t)


def _poisson(rng, t0, dur, rate, sensitive_p=0.0):
    out, t = [], t0
    while t < t0 + dur:
        tags = ["PII"] if rng.random() < sensitive_p else []
        out.append((t, rng.choice(ENDPOINTS), rng.choice([P.BALANCED, P.HARDENED]), tags))
        t += rng.expovariate(rate)
    return out


def _peak(d, t0, dur, events, agent="a"):
    peak = 0.0
    for t, ep, prof, tags in events:
        st = d.drift_statistic(agent, now=t)
        if not st.cold_start:
            peak = max(peak, st.delta)
        asyncio.run(d.log_decision(agent, prof, ep, 0.3, data_tags=tags, now=t,
                                   update_baseline=st.delta < 3.0))
    return peak, d.drift_statistic(agent, now=events[-1][0])


def _detectors():
    return (DriftDetector(window_seconds=300, n_min=20),
            DriftDetector(window_seconds=300, n_min=20, extended=True))


def test_a_regular_script_at_the_victims_rate_is_caught_only_by_regularity():
    rng = random.Random(1)
    base = _poisson(rng, 0, 1500, 1.0)
    # Same endpoints, same profiles, same mean rate: only the cadence is a script's.
    attack, t = [], 1500.0
    while t < 2100:
        attack.append((t, rng.choice(ENDPOINTS), rng.choice([P.BALANCED, P.HARDENED]), []))
        t += 1.0 * rng.uniform(0.95, 1.05)
    plain, ext = _detectors()
    asyncio.run(_replay(plain, base))
    asyncio.run(_replay(ext, base))
    p_plain, _ = _peak(plain, 1500, 600, attack)
    p_ext, st = _peak(ext, 1500, 600, attack)
    assert p_plain < 3.0, "the original three channels are blind to this attacker by design"
    assert p_ext >= 3.0
    assert st.dominant_channel() in ("interarrival_regularity", "sensitive_share") or st.z_regularity > 0


def test_a_slow_rise_in_sensitive_share_is_caught_by_the_long_horizon_channel():
    rng = random.Random(2)
    base = _poisson(rng, 0, 1500, 1.0, sensitive_p=0.1)
    attack = _poisson(rng, 1500, 900, 1.0, sensitive_p=0.6)   # organic timing, more PII
    plain, ext = _detectors()
    asyncio.run(_replay(plain, base))
    asyncio.run(_replay(ext, base))
    p_plain, _ = _peak(plain, 1500, 900, attack)
    p_ext, st = _peak(ext, 1500, 900, attack)
    assert p_plain < 3.0
    assert p_ext >= 3.0 and st.z_sensitive > st.z_regularity


def test_benign_poisson_traffic_does_not_fire_the_extended_channels():
    rng = random.Random(3)
    base = _poisson(rng, 0, 1500, 1.0, sensitive_p=0.2)
    more = _poisson(rng, 1500, 900, 1.0, sensitive_p=0.2)
    _, ext = _detectors()
    asyncio.run(_replay(ext, base))
    peak, st = _peak(ext, 1500, 900, more)
    assert st.z_regularity < 3.0 and st.z_sensitive < 3.0


def test_extended_off_reports_zero_for_the_new_terms():
    rng = random.Random(4)
    plain, _ = _detectors()
    asyncio.run(_replay(plain, _poisson(rng, 0, 1500, 1.0, sensitive_p=0.5)))
    st = plain.drift_statistic("a", now=1500)
    assert st.z_regularity == 0.0 and st.z_sensitive == 0.0
    assert set(st.as_dict()) >= {"z_regularity", "z_sensitive"}


def test_a_never_sensitive_agent_gets_a_large_finite_score_not_infinity():
    rng = random.Random(5)
    _, ext = _detectors()
    asyncio.run(_replay(ext, _poisson(rng, 0, 1500, 1.0, sensitive_p=0.0)))
    asyncio.run(_replay(ext, _poisson(rng, 1500, 60, 1.0, sensitive_p=1.0)))
    z = ext.drift_statistic("a", now=1560).z_sensitive
    assert 3.0 < z < float("inf")


# ── evaluation fixes ─────────────────────────────────────────────────────────

def test_split_is_stable_across_processes():
    import subprocess
    code = ("import sys; sys.path.insert(0,'evaluation'); import evaluate_e2 as E;"
            "print(sum(E.in_calibration(f'ag_{i}') for i in range(500)))")
    root = os.path.join(os.path.dirname(__file__), "..")
    outs = {subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True,
                           env={**os.environ, "PYTHONHASHSEED": str(s)}).stdout.strip() for s in (1, 2, 3)}
    assert len(outs) == 1, f"split depends on PYTHONHASHSEED: {outs}"


def test_wilson_interval():
    import evaluate_e2 as E
    lo, hi = E.wilson(5, 100)
    assert 0.02 < lo < 0.03 and 0.10 < hi < 0.12
    assert E.wilson(0, 50)[0] == 0.0


def test_corpus_v1_carries_no_tags_on_benign_and_v2_does():
    from corpus import SENSITIVE_RATES_V2, make_episode
    v1 = make_episode(123, 0, "steady_batch")
    v2 = make_episode(123, 0, "steady_batch", version="v2")
    assert not any(e.tags for e in v1.baseline)
    share = sum(1 for e in v2.baseline if e.tags) / len(v2.baseline)
    assert abs(share - SENSITIVE_RATES_V2["steady_batch"]) < 0.08
    assert [(e.t, e.endpoint) for e in v1.baseline] == [(e.t, e.endpoint) for e in v2.baseline]
    assert not any(e.tags and e.profile == P.CHEAP for e in v2.baseline)


def test_mimicry_full_reuses_the_victims_own_gaps_and_tags():
    from corpus import make_episode
    ep = make_episode(77, 1, "mimicry_full", version="v2")
    gaps = {round(b.t - a.t, 9) for a, b in zip(ep.baseline, ep.baseline[1:])}
    atk = [round(b.t - a.t, 9) for a, b in zip(ep.evaluation, ep.evaluation[1:])]
    assert atk and all(g in gaps for g in atk)


def test_pq_bench_runs_and_reports_sizes():
    pytest.importorskip("oqs")
    import pq_bench
    rep = pq_bench.run(iters=5, warmup=1)
    assert rep["sizes"]["ML-KEM-768"]["public_key_bytes"] == 1184
    assert rep["sizes"]["ML-KEM-768"]["ciphertext_bytes"] == 1088
    assert "X25519+ML-KEM-768 hybrid (CipherJanitor, full)" in rep["timings"]


def test_flow_csv_loader_builds_labelled_host_episodes(tmp_path):
    import flows
    rng = random.Random(9)
    lines = [" Source IP, Destination IP, Destination Port, Timestamp, Label"]
    for host, attack_from in (("10.0.0.1", None), ("10.0.0.2", 2000)):
        t = 0.0
        while t < 3600:
            label = "PortScan" if attack_from is not None and t >= attack_from else "BENIGN"
            port = rng.choice([443, 80, 22])
            stamp = f"{int(t)}"
            lines.append(f"{host},192.168.1.{rng.randint(1, 5)},{port},{stamp},{label}")
            t += rng.expovariate(0.5)
    lines.append("bad,row")
    f = tmp_path / "flows.csv"
    f.write_text("\n".join(lines))
    hosts, skipped = flows.load_flows([str(f)])
    assert set(hosts) == {"10.0.0.1", "10.0.0.2"} and skipped == 1
    eps, small = flows.episodes_from_flows(hosts, 1800, 1800, 40)
    labels = {e.agent_id: e.label for e in eps}
    assert labels == {"host_10.0.0.1": 0, "host_10.0.0.2": 1}
    assert all(ev.profile in (P.HARDENED, P.CHEAP, P.BALANCED) for e in eps for ev in e.evaluation)
    assert flows.evaluate(eps)["episodes"] == 2
