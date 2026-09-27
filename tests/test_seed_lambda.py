"""The seed Lambda names an unreachable Memgraph at once instead of timing out.

Before the connectivity check every statement discovered the outage on its own,
each waiting out the driver's connect timeout, so the function ran into its
300 s limit and the deploy saw only a dropped connection.
"""
from __future__ import annotations

import sys
import types

import pytest

from cipherweave import seed_lambda as S


class FakeSession:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, stmt):
        self.calls.append(stmt)


class FakeDriver:
    def __init__(self, reachable, calls, kwargs):
        self.reachable, self.calls, self.kwargs, self.closed = reachable, calls, kwargs, False

    def verify_connectivity(self):
        if not self.reachable:
            raise OSError("Couldn't connect to 172.31.7.181:7687")

    def session(self):
        return FakeSession(self.calls)

    def close(self):
        self.closed = True


@pytest.fixture
def fake_neo4j(monkeypatch):
    state = {"reachable": True, "calls": [], "drivers": []}

    def driver(uri, **kwargs):
        d = FakeDriver(state["reachable"], state["calls"], kwargs)
        state["drivers"].append(d)
        return d

    mod = types.ModuleType("neo4j")
    mod.GraphDatabase = types.SimpleNamespace(driver=driver)
    monkeypatch.setitem(sys.modules, "neo4j", mod)
    return state


def test_unreachable_memgraph_is_an_error_before_any_statement(fake_neo4j):
    fake_neo4j["reachable"] = False
    out = S._seed_graph()
    assert out["status"] == "error" and "unreachable" in out["message"]
    assert fake_neo4j["calls"] == [], "no statement may run against a host that did not answer"
    assert fake_neo4j["drivers"][0].closed
    assert fake_neo4j["drivers"][0].kwargs["connection_timeout"] == S.MEMGRAPH_CONNECT_TIMEOUT_S


def test_reachable_memgraph_runs_every_statement(fake_neo4j):
    out = S._seed_graph()
    assert out["status"] == "success" and out["statements_executed"] == len(fake_neo4j["calls"]) > 0


def test_cloudformation_hears_failed_for_an_unreachable_host(fake_neo4j, monkeypatch):
    fake_neo4j["reachable"] = False
    sent = []
    monkeypatch.setattr(S, "_cfn_send", lambda event, ctx, status, data, reason="": sent.append((status, reason)))
    out = S.handler({"RequestType": "Create", "ResponseURL": "https://example.invalid"}, None)
    assert out["status"] == "error" and sent and sent[0][0] == "FAILED" and "unreachable" in sent[0][1]
