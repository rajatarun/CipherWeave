"""E2 -- detection rates for the drift statistic, over the labelled corpus.

Method
------
Each episode replays its baseline through the detector to establish EWMA
baselines, then replays its evaluation window recording max delta. Baselines are
updated during evaluation only while delta < THETA_LEARN, matching operational
behaviour (a detector that learns from the anomaly it is reporting normalises an
ongoing attack).

Episodes are split 50/50 into calibration and test by hash of agent id. The
operating threshold is chosen on *benign calibration episodes only* -- as the
(1 - target_fpr) quantile of their scores -- and then applied unchanged to the
test split. No threshold is ever tuned on the data it is scored against.

Reported per attack class rather than as a single aggregate, because class
prevalence in this corpus is a design choice and an aggregate over it would mean
whatever mix was chosen.

The split is by a *stable* hash (CRC-32) of the agent id. It used to be
Python's ``hash()``, which is salted per process: the same corpus gave
AUC 0.894 or 0.922 and a measured FPR of 6.9% or 2.1% at a 5% target depending
only on PYTHONHASHSEED. Measured false-positive rates are now reported with a
95% Wilson interval, because on ~100 benign test episodes a 5% target is
consistent with anything from about 2% to 11%, and a single number without that
range invites reading sampling noise as miscalibration.

  --corpus v2    realistic sensitive-data rates on benign traffic, plus two
                 further evasive attackers (see corpus.py)
  --extended     score with the extended detector (inter-arrival regularity and
                 long-horizon sensitive share)
  --json FILE    write the numbers
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import zlib
from collections import defaultdict

sys.path.insert(0, "evaluation")

from corpus import ATTACK_CLASSES, ATTACK_CLASSES_V2, BENIGN_ARCHETYPES, Episode, build_corpus

from cipherweave.drift_detector import DriftDetector

THETA_LEARN = 3.0
WINDOW_SECONDS = 300.0


EXTENDED = False


def _new_detector():
    return DriftDetector(theta=THETA_LEARN, alpha=0.2,
                         window_seconds=WINDOW_SECONDS, n_min=20, extended=EXTENDED)


def in_calibration(agent_id: str) -> bool:
    """Stable 50/50 split. Not hash(): that is salted per process."""
    return zlib.crc32(agent_id.encode()) % 2 == 0


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def score_episode(ep: Episode):
    """Replay an episode once, scoring both combiners.

    Returns (peak_max, dominant_channel, time_to_detect, saw_cold_start, peak_mean).
    """
    d = _new_detector()
    for e in ep.baseline:
        _sync(d.log_decision(ep.agent_id, e.profile, e.endpoint, 0.3,
                             data_tags=e.tags, now=e.t))

    peak, chan, ttd, cold, peak_mean = 0.0, "none", None, False, 0.0
    full_fired = False
    for e in ep.evaluation:
        st = d.drift_statistic(ep.agent_id, now=e.t)
        if st.cold_start:
            # Cold start is a policy override, not a drift measurement; scoring it
            # as infinite made benign traffic lulls dominate the ranking. Counted
            # separately, below.
            cold = True
            val = mean_val = 0.0
        else:
            val = st.delta
            mean_val = (st.z_entropy + st.z_rate + st.z_mix) / 3.0
        if val > peak:
            peak, chan = val, st.dominant_channel()
        peak_mean = max(peak_mean, mean_val)
        if ttd is None and val >= THETA_LEARN and ep.attack_start is not None:
            ttd = e.t - ep.attack_start
        if not full_fired:
            fired, _alert = _result(d.detect_anomaly(
                ep.agent_id, e.profile, e.tags, e.endpoint, now=e.t))
            full_fired = bool(fired)
        _sync(d.log_decision(ep.agent_id, e.profile, e.endpoint, 0.3,
                             data_tags=e.tags, now=e.t,
                             update_baseline=val < THETA_LEARN))
    return peak, chan, ttd, cold, peak_mean, full_fired


def _sync(coro):
    try:
        coro.send(None)
    except StopIteration:
        pass


def _result(coro):
    """Drive a coroutine that completes without awaiting, returning its value."""
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    raise RuntimeError("coroutine did not complete synchronously")


def auc(pos: list[float], neg: list[float]) -> float:
    """Mann-Whitney rank AUC, ties counted as half."""
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else (0.5 if p == n else 0.0)
    return wins / (len(pos) * len(neg))


def quantile(xs: list[float], q: float) -> float:
    if not xs:
        return float("inf")
    s = sorted(xs)
    i = min(len(s) - 1, max(0, int(math.ceil(q * len(s))) - 1))
    return s[i]


def main(argv=None):
    global EXTENDED
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40, help="episodes per class")
    ap.add_argument("--corpus", choices=["v1", "v2"], default="v1")
    ap.add_argument("--extended", action="store_true")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)
    EXTENDED = args.extended
    attack_classes = ATTACK_CLASSES if args.corpus == "v1" else ATTACK_CLASSES_V2

    print(f"Building corpus {args.corpus}: {args.n} episodes per class "
          f"({len(BENIGN_ARCHETYPES)} benign archetypes, {len(attack_classes)} attack classes); "
          f"detector={'extended' if EXTENDED else 'Eq. (3)'}")
    corpus = build_corpus(n_per_class=args.n, version=args.corpus)

    rows = []
    for ep in corpus:
        rows.append((ep,) + score_episode(ep))
    print(f"Scored {len(rows)} episodes.\n")
    report = {"corpus": args.corpus, "extended": EXTENDED, "n_per_class": args.n, "operating_points": {}}

    cal = [r for r in rows if in_calibration(r[0].agent_id)]
    test = [r for r in rows if not in_calibration(r[0].agent_id)]
    cal_benign = [r[1] for r in cal if r[0].label == 0]

    print("=" * 74)
    print("OVERALL DISCRIMINATION (test split)")
    pos = [r[1] for r in test if r[0].label == 1]
    neg = [r[1] for r in test if r[0].label == 0]
    print(f"  AUC = {auc(pos, neg):.3f}   ({len(pos)} attack / {len(neg)} benign episodes)")
    report["auc"] = round(auc(pos, neg), 4)
    print("  Aggregate AUC is reported for completeness only; the per-class rates")
    print("  below are the meaningful numbers, since class prevalence here is chosen.")

    for target in (0.01, 0.05):
        theta = quantile(cal_benign, 1.0 - target)
        print()
        print("=" * 74)
        print(f"OPERATING POINT  target FPR={target:.0%} on benign calibration split "
              f"-> theta={theta:.2f}")
        tb = [r for r in test if r[0].label == 0]
        fp = sum(1 for r in tb if r[1] >= theta)
        lo, hi = wilson(fp, len(tb))
        print(f"  measured FPR on test benign: {fp}/{len(tb)} = {fp/len(tb):.1%}"
              f"   (95% CI {lo:.1%} - {hi:.1%})")
        op = report["operating_points"][f"{target:.2f}"] = {
            "theta": round(theta, 4), "fpr": round(fp / len(tb), 4),
            "fpr_ci": [round(lo, 4), round(hi, 4)], "fp_by_archetype": {}, "tpr_by_attack": {}}

        print("\n  false positives by benign archetype:")
        for arch in BENIGN_ARCHETYPES:
            sub = [r for r in tb if r[0].archetype == arch]
            if not sub:
                continue
            f = sum(1 for r in sub if r[1] >= theta)
            hard = "  <- hard negative" if sub[0][0].is_hard_negative else ""
            fullf = sum(1 for r in sub if r[6]) / len(sub)
            op["fp_by_archetype"][arch] = {"delta": round(f / len(sub), 4), "full": round(fullf, 4)}
            print(f"    {arch:<14} delta {f:>3}/{len(sub):<3} = {f/len(sub):>6.1%}"
                  f" | full detector={fullf:>6.1%}{hard}")

        print("\n  detection rate by attack class:")
        for arch in attack_classes:
            sub = [r for r in test if r[0].archetype == arch]
            if not sub:
                continue
            det = [r for r in sub if r[1] >= theta]
            tprs = len(det) / len(sub)
            ttds = [r[3] for r in det if r[3] is not None]
            med = f"{sorted(ttds)[len(ttds)//2]:6.1f}s" if ttds else "     --"
            chans = defaultdict(int)
            for r in det:
                chans[r[2]] += 1
            top = max(chans, key=lambda k: chans[k]) if chans else "-"
            evade = "  <- designed to evade" if sub[0][0].is_evasive else ""
            full = sum(1 for r in sub if r[6]) / len(sub)
            op["tpr_by_attack"][arch] = {"delta": round(tprs, 4), "full": round(full, 4), "via": top}
            print(f"    {arch:<21} delta TPR={tprs:>6.1%} | full detector={full:>6.1%}"
                  f"  t50={med}  via {top:<20}{evade}")

    print()
    print("=" * 74)
    print("ABLATION  max vs mean combiner (test split AUC)")
    mpos = [r[5] for r in test if r[0].label == 1]
    mneg = [r[5] for r in test if r[0].label == 0]
    print(f"  max  combiner AUC = {auc(pos, neg):.3f}")
    print(f"  mean combiner AUC = {auc(mpos, mneg):.3f}")

    print()
    print("=" * 74)
    print("COLD-START CONTRIBUTION (episodes whose window fell below n_min)")
    for lbl, name in ((0, "benign"), (1, "attack")):
        sub = [r for r in rows if r[0].label == lbl]
        c = sum(1 for r in sub if r[4])
        print(f"  {name}: {c}/{len(sub)} = {c/len(sub):.1%}")
    ch = [r for r in rows if r[0].label == 0 and r[4]]
    if ch:
        by = defaultdict(int)
        for r in ch:
            by[r[0].archetype] += 1
        print(f"  benign cold starts by archetype: {dict(by)}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
    return report


if __name__ == "__main__":
    main()
