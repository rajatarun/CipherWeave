"""Generative traffic corpus for evaluating the drift detector (Eq. 3).

WHAT THIS IS AND IS NOT
=======================
This is a **simulation study with a stated generative model**, not a field
evaluation. No corpus of real agent-to-endpoint cryptographic decisions exists,
so the traffic here is synthetic. Its external validity depends entirely on
whether this generative model resembles production traffic, which is unvalidated.

A synthetic corpus is worthless if it is built to be caught: if the benign model
is easy and every attack violates exactly what the detector measures, the result
is a tautology with an AUC attached. Two deliberate choices are what make the
numbers informative:

* **Hard negatives.** `bursty_etl` and `expanding` are *benign* archetypes that
  superficially resemble attacks -- a legitimate batch job bursts at 20x its
  idle rate, and an agent onboarding new services contacts endpoints it has
  never used. A false-positive rate measured only against placid traffic is not
  a false-positive rate.

* **Adversaries designed to evade.** `low_and_slow` and `mimicry` draw their
  endpoints and profiles from the victim agent's *own* empirical history, at the
  victim's own rate. They are expected to evade a distributional detector. They
  are in the corpus precisely so the evaluation can report that it misses them.

Attack classes are shaped by what a credential-compromise adversary does
(exfiltrate, beacon to C2, enumerate, weaken protection), not by what the three
channels of Eq. (3) happen to measure.

Every episode is seeded and reproducible.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from cipherweave.profiles import CipherProfile as P

BENIGN_ARCHETYPES = ("steady_batch", "interactive", "crawler", "bursty_etl", "expanding")
HARD_NEGATIVES = ("bursty_etl", "expanding")
ATTACK_CLASSES = ("exfil_burst", "beacon", "scan", "downgrade", "low_and_slow", "mimicry")
EVASIVE_ATTACKS = ("low_and_slow", "mimicry")

SENSITIVE_TAGS = ["PII", "PHI"]


@dataclass
class Event:
    t: float
    endpoint: str
    profile: P
    tags: list[str] = field(default_factory=list)


@dataclass
class Episode:
    agent_id: str
    label: int                 # 0 benign, 1 attack
    archetype: str
    baseline: list[Event]      # used to establish EWMA baselines
    evaluation: list[Event]    # scored window
    attack_start: float | None = None

    @property
    def is_hard_negative(self) -> bool:
        return self.label == 0 and self.archetype in HARD_NEGATIVES

    @property
    def is_evasive(self) -> bool:
        return self.label == 1 and self.archetype in EVASIVE_ATTACKS


# --- benign profile mixes, by archetype -----------------------------------
_MIXES = {
    "steady_batch": [(P.BALANCED, .75), (P.HARDENED, .20), (P.QUANTUM_SAFE, .05)],
    "interactive":  [(P.BALANCED, .55), (P.HARDENED, .30), (P.CHEAP, .10), (P.QUANTUM_SAFE, .05)],
    "crawler":      [(P.BALANCED, .60), (P.CHEAP, .35), (P.HARDENED, .05)],
    "bursty_etl":   [(P.HARDENED, .60), (P.BALANCED, .35), (P.QUANTUM_SAFE, .05)],
    "expanding":    [(P.BALANCED, .70), (P.HARDENED, .25), (P.QUANTUM_SAFE, .05)],
}


def _pick(rng: random.Random, mix):
    r, acc = rng.random(), 0.0
    for prof, p in mix:
        acc += p
        if r <= acc:
            return prof
    return mix[0][0]


def _zipf_endpoint(rng: random.Random, pool: list[str]) -> str:
    """Skewed endpoint choice -- real traffic is not uniform over destinations."""
    weights = [1.0 / (i + 1) for i in range(len(pool))]
    total = sum(weights)
    r, acc = rng.random() * total, 0.0
    for ep, w in zip(pool, weights):
        acc += w
        if r <= acc:
            return ep
    return pool[0]


def _benign_stream(rng, archetype, pool, t0, duration):
    """Emit benign events for `duration` seconds starting at t0."""
    events, t = [], t0
    mix = _MIXES[archetype]
    end = t0 + duration

    if archetype == "bursty_etl":
        # Long idle stretches punctuated by intense bursts: a legitimate rate spike.
        while t < end:
            idle = rng.uniform(40, 90)
            t += idle
            if t >= end:
                break
            burst_n = rng.randint(40, 120)
            burst_rate = rng.uniform(5.0, 20.0)
            for _ in range(burst_n):
                if t >= end:
                    break
                events.append(Event(t, _zipf_endpoint(rng, pool), _pick(rng, mix)))
                t += 1.0 / burst_rate
        return events

    if archetype == "expanding":
        # Legitimately onboards new endpoints over time: looks like enumeration.
        local = list(pool[:3])
        rate = rng.uniform(0.8, 1.5)
        i = 0
        while t < end:
            if i and i % rng.randint(25, 45) == 0 and len(local) < len(pool):
                local.append(pool[len(local)])
            events.append(Event(t, _zipf_endpoint(rng, local), _pick(rng, mix)))
            t += rng.expovariate(rate)
            i += 1
        return events

    rate = {"steady_batch": 1.0, "interactive": 0.7, "crawler": 2.0}[archetype]
    while t < end:
        if archetype == "interactive" and rng.random() < 0.10:
            t += rng.uniform(20, 60)          # think-time gaps
            continue
        events.append(Event(t, _zipf_endpoint(rng, pool), _pick(rng, mix)))
        t += rng.expovariate(rate)
    return events


def _attack_stream(rng, attack, hist: list[Event], pool, t0, duration):
    """Emit attack events, some of which deliberately imitate `hist`."""
    events, t = [], t0
    end = t0 + duration
    hist_eps = [e.endpoint for e in hist]
    hist_profs = [e.profile for e in hist]
    # victim's own observed inter-arrival, for the evasive classes
    gaps = [b.t - a.t for a, b in zip(hist, hist[1:])] or [1.0]
    median_gap = sorted(gaps)[len(gaps) // 2]

    if attack == "exfil_burst":
        target = rng.sample(pool, k=min(2, len(pool)))
        rate = rng.uniform(12.0, 25.0)
        while t < end:
            events.append(Event(t, rng.choice(target), P.BALANCED, list(SENSITIVE_TAGS)))
            t += 1.0 / rate

    elif attack == "beacon":
        ep = rng.choice(hist_eps)             # a KNOWN endpoint: only cadence changes
        interval = rng.uniform(2.0, 5.0)
        while t < end:
            events.append(Event(t, ep, P.BALANCED))
            t += interval * rng.uniform(0.97, 1.03)

    elif attack == "scan":
        i = 0
        while t < end:
            events.append(Event(t, f"scan_{i}", P.CHEAP))
            t += rng.expovariate(3.0)
            i += 1

    elif attack == "downgrade":
        while t < end:
            events.append(Event(t, rng.choice(hist_eps), P.CHEAP, list(SENSITIVE_TAGS)))
            t += rng.expovariate(1.0)

    elif attack == "low_and_slow":
        # Victim's own endpoints, own profile mix, own cadence. Exfiltration
        # hidden inside the shape of normal traffic.
        while t < end:
            events.append(Event(t, rng.choice(hist_eps), rng.choice(hist_profs),
                                list(SENSITIVE_TAGS)))
            t += median_gap * rng.uniform(0.85, 1.15)

    elif attack == "mimicry":
        # As low_and_slow, but resampling the empirical joint distribution.
        while t < end:
            src = rng.choice(hist)
            events.append(Event(t, src.endpoint, src.profile, list(SENSITIVE_TAGS)))
            t += median_gap * rng.uniform(0.9, 1.1)

    return events


def make_episode(seed: int, label: int, archetype: str,
                 baseline_seconds: float = 1200.0,
                 eval_seconds: float = 600.0) -> Episode:
    rng = random.Random(seed)
    benign_kind = archetype if label == 0 else rng.choice(BENIGN_ARCHETYPES)
    pool_size = {"crawler": 45, "expanding": 20}.get(benign_kind, rng.randint(4, 9))
    pool = [f"ep_{seed}_{i}" for i in range(pool_size)]

    baseline = _benign_stream(rng, benign_kind, pool, 0.0, baseline_seconds)
    if not baseline:
        baseline = [Event(0.0, pool[0], P.BALANCED)]

    if label == 0:
        evaluation = _benign_stream(rng, benign_kind, pool, baseline_seconds, eval_seconds)
        return Episode(f"ag_{seed}", 0, archetype, baseline, evaluation)

    evaluation = _attack_stream(rng, archetype, baseline, pool, baseline_seconds, eval_seconds)
    return Episode(f"ag_{seed}", 1, archetype, baseline, evaluation, attack_start=baseline_seconds)


def build_corpus(n_per_class: int = 60, seed0: int = 10_000) -> list[Episode]:
    """Balanced over archetypes; prevalence is a property of this corpus, not of reality."""
    episodes, s = [], seed0
    for arch in BENIGN_ARCHETYPES:
        for _ in range(n_per_class):
            episodes.append(make_episode(s, 0, arch)); s += 1
    for arch in ATTACK_CLASSES:
        for _ in range(n_per_class):
            episodes.append(make_episode(s, 1, arch)); s += 1
    return episodes
