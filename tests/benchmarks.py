"""Latency benchmarks — validate < 10ms p99 for get_encryption_strategy."""

from __future__ import annotations

import statistics
import time

import pytest

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.drift_detector import DriftDetector
from cipherweave.profiles import CipherProfile
from cipherweave.risk_engine import MockRiskGraph
from cipherweave.server import get_encryption_strategy, inject_components
from tests.conftest import AGENTS, ASSETS, EDGES, ENDPOINTS, REGULATIONS, THREATS


def _wire() -> tuple[MockRiskGraph, CipherJanitor, DriftDetector]:
    g = MockRiskGraph()
    g.seed(
        agents=AGENTS,
        endpoints=ENDPOINTS,
        assets=ASSETS,
        regulations=REGULATIONS,
        threats=THREATS,
        edges=EDGES,
    )
    janitor = CipherJanitor(kms_client=None, master_key_id="local")
    detector = DriftDetector(window_size=100)
    inject_components(g, janitor, detector)
    return g, janitor, detector


@pytest.mark.asyncio
async def test_benchmark_get_encryption_strategy() -> None:
    """Full tool invocation (MockRiskGraph + HKDF) must complete < 10ms p99 over 200 runs."""
    # Warm up: pre-populate detector history and JIT-warm the call path
    detector = DriftDetector(window_size=100)
    for _ in range(20):
        await detector.log_decision("agent-001", CipherProfile.QUANTUM_SAFE, "ep-hipaa-store", 0.9)
    g, janitor, _ = _wire()
    inject_components(g, janitor, detector)

    # Warmup iterations: primes Python internals and HKDF code paths
    WARMUP = 20
    for _ in range(WARMUP):
        await get_encryption_strategy(
            agent_id="agent-001",
            data_metadata={"tags": ["PHI"], "classification": "RESTRICTED"},
            destination_url="https://hipaa.store/api",
        )

    latencies_ms: list[float] = []
    N = 200

    for _ in range(N):
        start = time.perf_counter()
        await get_encryption_strategy(
            agent_id="agent-001",
            data_metadata={"tags": ["PHI"], "classification": "RESTRICTED"},
            destination_url="https://hipaa.store/api",
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies_ms.append(elapsed_ms)

    latencies_ms.sort()
    mean_ms = statistics.mean(latencies_ms)
    p50 = latencies_ms[int(N * 0.50)]
    p95 = latencies_ms[int(N * 0.95)]
    p99 = latencies_ms[int(N * 0.99)]

    print(f"\nLatency over {N} runs (MockRiskGraph + HKDF):")
    print(f"  mean={mean_ms:.3f}ms  p50={p50:.3f}ms  p95={p95:.3f}ms  p99={p99:.3f}ms")

    # Budget: p99 < 10ms (mock graph, no network I/O)
    assert p99 < 10.0, f"p99 latency {p99:.3f}ms exceeds 10ms budget"


@pytest.mark.asyncio
async def test_benchmark_graph_traversal_vs_dict() -> None:
    """Compare MockRiskGraph path lookup overhead vs a simple dict lookup."""
    g, janitor, detector = _wire()

    # Warm up detector history
    for _ in range(5):
        await detector.log_decision("agent-001", CipherProfile.QUANTUM_SAFE, "ep-hipaa-store", 0.9)
    inject_components(g, janitor, detector)

    N = 500

    # Graph traversal (MockRiskGraph — in-memory)
    graph_latencies: list[float] = []
    for _ in range(N):
        start = time.perf_counter()
        await g.get_path_risk("agent-001", "https://hipaa.store/api", ["PHI"])
        graph_latencies.append((time.perf_counter() - start) * 1000)

    # Dict lookup baseline
    simple_dict = {"agent-001": {"profile": "QUANTUM_SAFE", "risk": 0.9}}
    dict_latencies: list[float] = []
    for _ in range(N):
        start = time.perf_counter()
        _ = simple_dict.get("agent-001", {})
        dict_latencies.append((time.perf_counter() - start) * 1000)

    graph_p99 = sorted(graph_latencies)[int(N * 0.99)]
    dict_p99 = sorted(dict_latencies)[int(N * 0.99)]

    print(f"\nGraph traversal p99={graph_p99:.4f}ms vs dict lookup p99={dict_p99:.4f}ms")
    print(f"Overhead ratio: {graph_p99 / max(dict_p99, 0.0001):.1f}x")

    # Graph traversal must be < 5ms p99 for the mock (leaves budget for HKDF)
    assert graph_p99 < 5.0, f"Graph p99 {graph_p99:.3f}ms too slow"


def benchmark_get_encryption_strategy(benchmark: pytest.fixture) -> None:
    """pytest-benchmark integration for CI reporting."""
    import asyncio

    _wire()
    detector = DriftDetector(window_size=100)

    async def _setup() -> None:
        for _ in range(5):
            await detector.log_decision("agent-001", CipherProfile.QUANTUM_SAFE, "ep-hipaa-store", 0.9)

    asyncio.get_event_loop().run_until_complete(_setup())
    g, janitor, _ = _wire()
    inject_components(g, janitor, detector)

    async def _run() -> dict:
        return await get_encryption_strategy(
            agent_id="agent-001",
            data_metadata={"tags": ["PHI"], "classification": "RESTRICTED"},
            destination_url="https://hipaa.store/api",
        )

    benchmark(lambda: asyncio.get_event_loop().run_until_complete(_run()))
