"""Lambda entry point — wraps the FastMCP ASGI app with Mangum.

Cold-start flow:
  1. _init() connects RiskGraph to Memgraph (TCP, same VPC)
  2. KMS client created (real AWS KMS in Lambda, mock in local dev)
  3. FastMCP HTTP app created once; Mangum wraps it for API Gateway events

Warm invocation:
  - All module singletons already initialized; only the MCP request is processed
"""

from __future__ import annotations

import asyncio
import logging
import os

logger = logging.getLogger(__name__)

# Mangum bridges ASGI ↔ API Gateway HTTP payload format v2
try:
    from mangum import Mangum
except ImportError as exc:
    raise RuntimeError("mangum is required for Lambda deployment: pip install mangum") from exc

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.config import settings
from cipherweave.drift_detector import DriftDetector
from cipherweave.risk_engine import RiskGraph
from cipherweave.server import inject_components, mcp

# ---------------------------------------------------------------------------
# Cold-start initialization (runs once per Lambda execution environment)
# ---------------------------------------------------------------------------
_initialized = False


def _sync_init() -> None:
    """Synchronous wrapper so Lambda bootstrap can call async init."""
    global _initialized
    if _initialized:
        return
    asyncio.get_event_loop().run_until_complete(_async_init())
    _initialized = True


async def _async_init() -> None:
    """Connect to Memgraph + KMS and wire module singletons."""
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

    cipher_janitor = CipherJanitor(
        kms_client=kms_client,
        master_key_id=settings.kms_key_id,
    )
    drift_detector = DriftDetector(window_size=settings.drift_window_size)

    inject_components(risk_graph, cipher_janitor, drift_detector)
    logger.info(
        "CipherWeave Lambda initialized: Memgraph=%s:%s KMS=%s",
        settings.memgraph_host,
        settings.memgraph_port,
        "LOCAL" if settings.use_local_kms else settings.kms_key_id[:20] + "...",
    )


# Run init at module load (Lambda execution environment)
_sync_init()

# Build ASGI app from FastMCP and wrap with Mangum
_asgi_app = mcp.http_app()
handler = Mangum(_asgi_app, lifespan="off")
