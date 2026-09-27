"""E2 on public network-flow data (CIC-IDS2017 and other CICFlowMeter CSVs).

The synthetic corpus says what the detector does under a stated generative
model. This runs the same detector on recorded traffic, where nobody chose the
benign model. It is a proxy, and the mapping says exactly how:

  agent       the flow's source IP
  endpoint    destination IP and port
  time        the flow's start timestamp
  profile     derived from the destination port (443/8443/993/995 -> HARDENED,
              22 -> BALANCED, 80/8080/21/23 -> CHEAP, everything else ->
              BALANCED). Flow records carry no cipher choice, so the mix channel
              sees protocol mix, not cipher mix.
  tags        none. Flow records do not say whether a payload was sensitive,
              so the sensitive-share channel is inert here by construction.

An episode is one source host: its first ``--baseline`` seconds establish the
baselines and the next ``--eval`` seconds are scored. It is an attack episode if
any flow in its evaluation window carries a non-BENIGN label. Hosts with fewer
than ``--min-flows`` flows in either part are skipped (and counted).

The operating threshold is set on benign calibration hosts and applied to test
hosts, split by stable hash, exactly as for the synthetic corpus.

Usage (CIC-IDS2017 "MachineLearningCVE" CSVs, from the Canadian Institute for
Cybersecurity; not redistributed here):

  python evaluation/flows.py --csv Tuesday-WorkingHours.pcap_ISCX.csv \\
      --csv Wednesday-workingHours.pcap_ISCX.csv --extended
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import evaluate_e2 as E
from corpus import Episode, Event

from cipherweave.profiles import CipherProfile as P

_PORT_PROFILE = {443: P.HARDENED, 8443: P.HARDENED, 993: P.HARDENED, 995: P.HARDENED,
                 22: P.BALANCED, 80: P.CHEAP, 8080: P.CHEAP, 21: P.CHEAP, 23: P.CHEAP}

_TS_FORMATS = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S",
               "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M %p")


def _col(row: dict, *names: str) -> str | None:
    for n in names:
        if n in row:
            return row[n]
    return None


def _ts(value: str) -> float | None:
    value = (value or "").strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    try:
        return float(value)
    except ValueError:
        return None


def load_flows(paths: list[str]) -> tuple[dict[str, list[tuple[float, str, P, bool]]], int]:
    """host -> sorted [(t, endpoint, profile, is_attack)]; plus rows skipped as unreadable."""
    hosts: dict[str, list[tuple[float, str, P, bool]]] = defaultdict(list)
    skipped = 0
    for path in paths:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            reader.fieldnames = [f.strip() for f in reader.fieldnames or []]
            for row in reader:
                src = _col(row, "Source IP", "Src IP", "srcip")
                dst = _col(row, "Destination IP", "Dst IP", "dstip")
                port = _col(row, "Destination Port", "Dst Port", "dsport")
                t = _ts(_col(row, "Timestamp", "stime") or "")
                label = (_col(row, "Label", "label") or "").strip()
                if not src or not dst or port is None or t is None:
                    skipped += 1
                    continue
                try:
                    p = int(float(port))
                except ValueError:
                    skipped += 1
                    continue
                attack = label not in ("", "BENIGN", "0", "Normal")
                hosts[src.strip()].append((t, f"{dst.strip()}:{p}", _PORT_PROFILE.get(p, P.BALANCED), attack))
    for v in hosts.values():
        v.sort(key=lambda x: x[0])
    return hosts, skipped


def episodes_from_flows(hosts, baseline_s: float, eval_s: float, min_flows: int) -> tuple[list[Episode], int]:
    eps, too_small = [], 0
    for host, flows in hosts.items():
        t0 = flows[0][0]
        base = [f for f in flows if f[0] < t0 + baseline_s]
        ev = [f for f in flows if t0 + baseline_s <= f[0] < t0 + baseline_s + eval_s]
        if len(base) < min_flows or len(ev) < min_flows:
            too_small += 1
            continue
        attack = any(f[3] for f in ev)
        first_attack = next((f[0] for f in ev if f[3]), None)
        # Re-zero time so the detector's clock starts at the host's first flow.
        mk = lambda fs: [Event(f[0] - t0, f[1], f[2]) for f in fs]  # noqa: E731
        eps.append(Episode(f"host_{host}", int(attack), "attack" if attack else "benign",
                           mk(base), mk(ev), None if first_attack is None else first_attack - t0))
    return eps, too_small


def evaluate(episodes: list[Episode], target_fpr: float = 0.05) -> dict:
    rows = [(ep,) + E.score_episode(ep) for ep in episodes]
    cal = [r for r in rows if E.in_calibration(r[0].agent_id)]
    test = [r for r in rows if not E.in_calibration(r[0].agent_id)]
    theta = E.quantile([r[1] for r in cal if r[0].label == 0], 1.0 - target_fpr)
    tb = [r for r in test if r[0].label == 0]
    ta = [r for r in test if r[0].label == 1]
    fp = sum(1 for r in tb if r[1] >= theta)
    tp = sum(1 for r in ta if r[1] >= theta)
    return {
        "episodes": len(rows), "test_benign": len(tb), "test_attack": len(ta),
        "auc": round(E.auc([r[1] for r in ta], [r[1] for r in tb]), 4) if ta and tb else None,
        "theta": theta, "fpr": round(fp / len(tb), 4) if tb else None,
        "fpr_ci": [round(x, 4) for x in E.wilson(fp, len(tb))] if tb else None,
        "tpr": round(tp / len(ta), 4) if ta else None,
        "tpr_ci": [round(x, 4) for x in E.wilson(tp, len(ta))] if ta else None,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--csv", action="append", required=True)
    ap.add_argument("--baseline", type=float, default=1800.0)
    ap.add_argument("--eval", type=float, default=1800.0)
    ap.add_argument("--min-flows", type=int, default=40)
    ap.add_argument("--target-fpr", type=float, default=0.05)
    ap.add_argument("--extended", action="store_true")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)
    E.EXTENDED = args.extended
    hosts, skipped = load_flows(args.csv)
    eps, small = episodes_from_flows(hosts, args.baseline, args.eval, args.min_flows)
    print(f"{len(hosts)} source hosts, {skipped} unreadable rows, {small} hosts below --min-flows, "
          f"{len(eps)} episodes ({sum(e.label for e in eps)} attack)")
    result = evaluate(eps, args.target_fpr)
    result.update({"extended": args.extended, "hosts_skipped_small": small, "rows_skipped": skipped})
    print(json.dumps(result, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
