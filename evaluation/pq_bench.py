"""E3 -- what each cipher profile actually costs, measured with liboqs.

The paper argues the QUANTUM_SAFE profile is affordable enough to be the
fail-secure default. That is a claim about latency and bytes on the wire, and it
was stated from the literature rather than measured on this code. This script
measures it, on the machine it runs on, through the same primitives
``cipher_janitor.py`` uses:

  key establishment   X25519, ECDH P-256, ML-KEM-512/768/1024 (keygen, encaps,
                      decaps), and the X25519 + ML-KEM-768 hybrid exactly as
                      ``CipherJanitor.generate_hybrid_keypair`` /
                      ``hybrid_shared_secret`` do it
  key derivation      HKDF with each profile's hash (``CipherJanitor.derive_key``)
  bulk encryption     AES-128-GCM and AES-256-GCM on 1 KiB and 64 KiB messages
  wire size           public key and ciphertext bytes per KEM

Reported as median and p99 in microseconds over ``--iters`` runs after a warm-up,
with the platform, Python, OpenSSL and liboqs versions, because a latency number
without the machine it came from cannot be compared with anything.

  python evaluation/pq_bench.py --iters 2000 --json e3.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from collections.abc import Callable

from cryptography.hazmat.backends.openssl.backend import backend as _ossl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")


def _time(fn: Callable[[], object], iters: int, warmup: int) -> dict:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1000.0)
    samples.sort()
    return {
        "median_us": round(statistics.median(samples), 2),
        "p99_us": round(samples[min(len(samples) - 1, int(0.99 * len(samples)))], 2),
        "mean_us": round(statistics.fmean(samples), 2),
    }


def bench_classical(iters: int, warmup: int) -> dict:
    out = {}

    def x25519():
        a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        a.exchange(b.public_key())

    def p256():
        a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        a.exchange(ec.ECDH(), b.public_key())

    out["X25519 keygen+exchange (both sides)"] = _time(x25519, iters, warmup)
    out["ECDH P-256 keygen+exchange (both sides)"] = _time(p256, iters, warmup)
    return out


def bench_kems(iters: int, warmup: int) -> tuple[dict, dict]:
    import oqs

    timings, sizes = {}, {}
    for alg in KEMS:
        if alg not in oqs.get_enabled_kem_mechanisms():
            continue
        with oqs.KeyEncapsulation(alg) as kem:
            pk = kem.generate_keypair()
            ct, _ = kem.encap_secret(pk)
            sizes[alg] = {"public_key_bytes": len(pk), "ciphertext_bytes": len(ct),
                          "shared_secret_bytes": kem.details["length_shared_secret"]}
            timings[f"{alg} keygen"] = _time(kem.generate_keypair, iters, warmup)
            timings[f"{alg} encaps"] = _time(lambda: kem.encap_secret(pk), iters, warmup)
            timings[f"{alg} decaps"] = _time(lambda: kem.decap_secret(ct), iters, warmup)

        def roundtrip(alg=alg):
            with oqs.KeyEncapsulation(alg) as server:
                pk_ = server.generate_keypair()
                with oqs.KeyEncapsulation(alg) as client:
                    ct_, _ = client.encap_secret(pk_)
                server.decap_secret(ct_)

        timings[f"{alg} full round trip"] = _time(roundtrip, max(iters // 4, 50), warmup)
    return timings, sizes


def bench_hybrid(iters: int, warmup: int) -> dict:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from cipherweave import cipher_janitor as CJ

    j = CJ.CipherJanitor(kms_client=None, master_key_id="local")

    def hybrid():
        server = j.generate_hybrid_keypair()
        peer = X25519PrivateKey.generate()
        ct, _ = CJ._mlkem_encapsulate(server.mlkem_public)
        j.hybrid_shared_secret(server.x25519_private, peer.public_key().public_bytes_raw(),
                               ct, server.mlkem_private)

    return {"X25519+ML-KEM-768 hybrid (CipherJanitor, full)": _time(hybrid, max(iters // 4, 50), warmup)}


def bench_symmetric(iters: int, warmup: int) -> dict:
    out = {}
    ikm = os.urandom(32)
    for label, algo, length in (("HKDF-SHA256 -> 16B (CHEAP)", hashes.SHA256, 16),
                                ("HKDF-SHA256 -> 32B (BALANCED)", hashes.SHA256, 32),
                                ("HKDF-SHA384 -> 32B (HARDENED)", hashes.SHA384, 32),
                                ("HKDF-SHA512 -> 32B (QUANTUM_SAFE)", hashes.SHA512, 32)):
        out[label] = _time(lambda a=algo, n=length: HKDF(a(), n, os.urandom(32), b"bench").derive(ikm),
                           iters, warmup)
    for bits in (128, 256):
        key = AESGCM.generate_key(bits)
        aes = AESGCM(key)
        for size in (1024, 65536):
            msg = os.urandom(size)
            out[f"AES-{bits}-GCM encrypt {size // 1024} KiB"] = _time(
                lambda a=aes, m=msg: a.encrypt(os.urandom(12), m, None), iters, warmup)
    return out


def environment() -> dict:
    env = {"platform": platform.platform(), "machine": platform.machine(),
           "processor": platform.processor() or None, "python": platform.python_version(),
           "openssl": _ossl.openssl_version_text()}
    try:
        import oqs
        env["liboqs"] = oqs.oqs_version()
        env["liboqs_python"] = oqs.oqs_python_version()
    except Exception as exc:  # pragma: no cover
        env["liboqs"] = f"unavailable: {exc}"
    return env


def run(iters: int = 1000, warmup: int = 50) -> dict:
    kem_t, kem_sizes = bench_kems(iters, warmup)
    report = {
        "environment": environment(),
        "iters": iters,
        "timings": {**bench_classical(iters, warmup), **kem_t, **bench_hybrid(iters, warmup),
                    **bench_symmetric(iters, warmup)},
        "sizes": {**kem_sizes, "X25519": {"public_key_bytes": 32}, "ECDH P-256": {"public_key_bytes": 65}},
    }
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--iters", type=int, default=1000)
    ap.add_argument("--warmup", type=int, default=50)
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)
    report = run(args.iters, args.warmup)
    env = report["environment"]
    print(f"{env['platform']} | Python {env['python']} | {env['openssl']} | liboqs {env.get('liboqs')}")
    print(f"\n{'operation':<52}{'median µs':>12}{'p99 µs':>12}")
    for name, t in report["timings"].items():
        print(f"{name:<52}{t['median_us']:>12.1f}{t['p99_us']:>12.1f}")
    print(f"\n{'KEM':<16}{'pk bytes':>10}{'ct bytes':>10}")
    for name, sz in report["sizes"].items():
        print(f"{name:<16}{sz.get('public_key_bytes', ''):>10}{sz.get('ciphertext_bytes', ''):>10}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
