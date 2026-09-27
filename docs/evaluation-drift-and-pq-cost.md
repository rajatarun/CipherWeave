# Drift detection against quiet attackers, and what post-quantum actually costs

Two open problems from the CipherWeave paper, measured on this code.
Raw numbers: `evaluation/results/*.json`. Reproduce:

```bash
python evaluation/evaluate_e2.py --n 40 --corpus v1            [--extended] --json out.json
python evaluation/evaluate_e2.py --n 40 --corpus v2            [--extended] --json out.json
python evaluation/pq_bench.py --iters 1000 --json e3.json
python evaluation/flows.py --csv <CIC-IDS2017 CSV> [--extended]   # recorded traffic
```

## 1. The reported false-positive rate was partly the split

`evaluate_e2.py` split calibration from test episodes with Python's `hash()`,
which is salted per process. The same corpus and code gave:

| PYTHONHASHSEED | AUC | measured FPR at a 5% target |
|---|---|---|
| 1 | 0.894 | 6.9% |
| 2 | 0.922 | 2.1% |

So the paper's "7.6% when tuned for 5%" is one draw of a number that moves by a
factor of three with the process's hash salt. The split is now a CRC-32 of the
agent id (stable), and every measured FPR is reported with a 95% Wilson
interval: on ~100 benign test episodes, a 5% target is consistent with
anything from about 2% to 11%. Reading a single number as miscalibration was
reading noise.

## 2. Two longer-horizon channels (`DriftDetector(extended=True)`)

The evasive attackers draw endpoints and profiles from the victim's own
history at the victim's own rate, so entropy, rate and mix do not move. What
they usually cannot also hide:

- **Inter-arrival regularity** — a script sleeping a fixed interval has gap
  CV near 0; organic traffic is near 1 or burstier. One-sided z on the gap CV.
- **Long-horizon sensitive share** — exfiltration raises the share of PII/PHI
  requests; invisible in five minutes, plain in ten. One-sided z with the
  binomial standard error, over a window of 2× the short window, against a
  baseline fed *only* by events that have left that window. The first version
  let the baseline learn from the window it tested, and a sustained attack
  became the baseline before the window could show it; a test caught that.

Both enter the same max, so each keeps unilateral authority to fire.

### Why v1 cannot judge them, and what v2 changes

On corpus v1 benign traffic never carries a sensitive tag and every evasive
attack does, so the sensitive-share channel wins trivially (AUC 1.000 below).
Corpus v2 closes that gap before measuring: benign archetypes carry sensitive
data at 2–45% (with a non-CHEAP profile), and two attackers are added —
`low_and_slow_jittered` (Poisson timing, so regularity cannot see it) and
`mimicry_full` (resamples the victim's joint endpoint/profile/tags *and* its
gaps: indistinguishable in distribution, the bound for any detector that sees
only this traffic).

### Results (n = 40 per class, test split, threshold set on benign calibration)

| Detector | Corpus | AUC | FPR @ 5% target (95% CI) |
|---|---|---|---|
| Eq. (3) | v1 | 0.909 | 4.0% (1.6–9.8%) |
| extended | v1 | 1.000 | 4.0% (1.6–9.8%) — trivial, see above |
| Eq. (3) | v2 | 0.788 | 7.0% (3.4–13.8%) |
| extended | v2 | 0.923 | **11.0% (6.3–18.6%)** |

Detection rate of the statistic δ on v2 at that operating point:

| Attack | Eq. (3) | extended |
|---|---|---|
| exfil_burst, scan | 100% | 100% |
| beacon | 100% | 95% |
| downgrade | 10% | 100% |
| low_and_slow | 30% | 100% |
| mimicry | 50% | 100% |
| low_and_slow_jittered | 0% | 100% |
| mimicry_full | 10% | 10% |

What this says:

- The extended channels answer the open problem for every attacker that is
  either a script or there for the sensitive data. v2's harder benign traffic
  costs Eq. (3) itself 0.12 AUC; the extended detector recovers it and more.
- `mimicry_full` is not caught, and should not be: it is the victim's own
  distribution. Catching it needs information this detector does not have
  (payload, identity, destination authorization) — which is the authorization
  check in `RiskGraph.validate_agent_authorization`, not a statistic.
- **The cost is false positives.** At the same 5% target the extended
  detector's test FPR is 11% (interval 6–19%), with new false alarms on
  `expanding` (15%) and `steady_batch` (5%). The threshold is calibrated on
  100 benign episodes and the extended score has a heavier benign tail, so it
  transfers worse. That is why `extended` is **off by default**: the deployed
  statistic stays Eq. (3) until that cost is accepted or reduced (a larger
  calibration set, a per-channel threshold, or a longer baseline for the
  sensitive share are the obvious next steps).
- v2's sensitive rates are assumptions, not measurements. `evaluation/flows.py`
  runs the same detector on recorded network flows (CIC-IDS2017 and other
  CICFlowMeter CSVs); flow records carry no data-sensitivity label, so there
  the sensitive-share channel is inert by construction and only the
  regularity channel is tested.

## 3. What each profile costs (E3, liboqs 0.16.0)

Linux x86_64, Python 3.12.3, OpenSSL 4.0.2, liboqs 0.16.0; median / p99 µs
over 1000 iterations after warm-up.

| Operation | median µs | p99 µs |
|---|---|---|
| X25519 keygen + exchange (both sides) | 95.9 | 150.9 |
| ECDH P-256 keygen + exchange (both sides) | 78.9 | 122.7 |
| ML-KEM-768 keygen / encaps / decaps | 8.6 / 9.7 / 10.2 | 20.9 / 24.2 / 22.9 |
| ML-KEM-768 full round trip | 36.7 | 65.3 |
| ML-KEM-1024 full round trip | 44.7 | 69.3 |
| X25519 + ML-KEM-768 hybrid (CipherJanitor, full) | 218.7 | 305.8 |
| HKDF-SHA256 → 32 B (BALANCED) | 3.8 | 9.0 |
| HKDF-SHA512 → 32 B (QUANTUM_SAFE) | 5.3 | 16.7 |
| AES-256-GCM encrypt 64 KiB | 7.2 | 30.1 |

| KEM | public key | ciphertext |
|---|---|---|
| X25519 | 32 B | — |
| ML-KEM-768 | 1184 B | 1088 B |
| ML-KEM-1024 | 1568 B | 1568 B |

- **ML-KEM is not the expensive part.** A full ML-KEM-768 round trip is
  cheaper than one X25519 exchange here. QUANTUM_SAFE's real cost is ~2.2 KB
  more on the wire per key establishment.
- The janitor's hybrid path (219 µs) costs more than its two primitives
  together (~37 + ~96 µs): model construction and key re-parsing around the
  crypto. Worth trimming if QUANTUM_SAFE becomes the default for more traffic,
  but at a fifth of a millisecond it does not threaten the 10 ms p99 budget.
- Symmetric cost differences between profiles are a few microseconds.
