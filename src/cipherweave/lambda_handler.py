"""Lambda entry point — wraps the FastMCP ASGI app with Mangum.

Cold-start flow:
  1. Module loads; persistent event loop + ASGI app created (no I/O).
  2. First request calls _ensure_init():
     a. Connects Memgraph + wires KMS/DriftDetector.
     b. Manually fires the ASGI lifespan startup so FastMCP's internal
        task group is initialized before Mangum handles any HTTP request.
  3. Warm invocations skip init entirely.
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
# Persistent event loop — module-level so both init and Mangum share it.
# asyncio.run() destroys the loop; Mangum's get_event_loop() then raises
# RuntimeError on Python 3.12. A single persistent loop avoids this.
# ---------------------------------------------------------------------------
_loop = asyncio.new_event_loop()
asyncio.set_event_loop(_loop)

# Build the ASGI app once at module load (no I/O here)
_asgi_app = mcp.http_app(stateless_http=True)

# ---------------------------------------------------------------------------
# Deferred initialization state
# ---------------------------------------------------------------------------
_initialized = False


async def _start_lifespan(app) -> None:
    """Send ASGI lifespan.startup to app and wait for startup.complete.

    FastMCP 3.x requires the ASGI lifespan to run before it will handle
    HTTP requests (its internal anyio task group is created during startup).
    Mangum's built-in lifespan support is unreliable in the Lambda Python
    3.12 runtime, so we drive it manually here once per cold start.
    """
    startup_done = asyncio.Event()
    receive_queue: asyncio.Queue = asyncio.Queue()
    await receive_queue.put({"type": "lifespan.startup"})

    async def receive():
        return await receive_queue.get()

    async def send(message):
        if message["type"] == "lifespan.startup.complete":
            startup_done.set()

    # Run lifespan as a background task so it stays alive during requests
    _loop.create_task(
        app({"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"}}, receive, send)
    )
    await asyncio.wait_for(startup_done.wait(), timeout=15)
    logger.info("FastMCP ASGI lifespan started")


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
    await _start_lifespan(_asgi_app)


def _ensure_init() -> None:
    global _initialized
    if _initialized:
        return
    _loop.run_until_complete(_async_init())
    _initialized = True


# Mangum wraps the ASGI app; lifespan is driven manually above
_mangum = Mangum(_asgi_app, lifespan="off")


def handler(event: dict, context: object) -> dict:
    """Lambda handler — ensures init before delegating to Mangum."""
    try:
        _ensure_init()
    except Exception as exc:
        logger.exception("Initialization error")
        return {
            "statusCode": 503,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "service_unavailable", "detail": str(exc)}),
        }
    return _mangum(event, context)
