"""Lambda entry point — wraps the FastMCP ASGI app with Mangum.

Cold-start flow:
  1. Module loads; Mangum+FastMCP app are created immediately (no I/O).
  2. First request triggers _ensure_init(), which connects Memgraph + KMS.
  3. Subsequent warm invocations skip init entirely.

Deferred init means an import-time Memgraph timeout no longer returns 500
for every request — the first request may be slow, but it will produce a
real error message rather than a silent Lambda crash.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=os.environ.get("CIPHERWEAVE_LOG_LEVEL", "INFO"),
    format="%(levelname)s %(name)s %(message)s",
)

try:
    from mangum import Mangum
except ImportError as exc:
    raise RuntimeError("mangum is required: pip install mangum") from exc

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.config import settings
from cipherweave.drift_detector import DriftDetector
from cipherweave.risk_engine import RiskGraph
from cipherweave.server import inject_components, mcp

# ---------------------------------------------------------------------------
# Persistent event loop — created once, reused by both _ensure_init and Mangum.
# asyncio.run() destroys the loop after use; Mangum's get_event_loop() then
# raises RuntimeError on Python 3.12. A module-level loop avoids this.
# ---------------------------------------------------------------------------
_loop = asyncio.new_event_loop()
asyncio.set_event_loop(_loop)

# ---------------------------------------------------------------------------
# Deferred initialization state
# ---------------------------------------------------------------------------
_initialized = False
_init_error: Exception | None = None


async def _async_init() -> None:
    risk_graph = RiskGraph(
        memgraph_host=settings.memgraph_host,
        memgraph_port=settings.memgraph_port,
    )
    await risk_graph.connect()
    await risk_graph.initialize_schema()

    kms_client = None
    if not settings.use_local_kms and settings.kms_key_id:
        import boto3
        kms_client = boto3.client("kms", region_name=settings.aws_region)

    inject_components(
        risk_graph,
        CipherJanitor(kms_client=kms_client, master_key_id=settings.kms_key_id),
        DriftDetector(window_size=settings.drift_window_size),
    )
    logger.info(
        "CipherWeave initialized — Memgraph=%s:%s KMS=%s",
        settings.memgraph_host,
        settings.memgraph_port,
        "LOCAL" if settings.use_local_kms else (settings.kms_key_id or "none")[:20],
    )


def _ensure_init() -> None:
    global _initialized, _init_error
    if _initialized:
        return
    try:
        _loop.run_until_complete(_async_init())
        _initialized = True
        _init_error = None
    except Exception as exc:
        _init_error = exc
        logger.exception("CipherWeave init failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# ASGI app + Mangum handler
# ---------------------------------------------------------------------------
_asgi_app = mcp.http_app()
_mangum = Mangum(_asgi_app, lifespan="off")


def handler(event: dict, context: object) -> dict:
    """Lambda handler — ensures init before delegating to Mangum."""
    try:
        _ensure_init()
    except Exception as exc:
        logger.error("Initialization error: %s", exc)
        return {
            "statusCode": 503,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "service_unavailable", "detail": str(exc)}),
        }
    return _mangum(event, context)
