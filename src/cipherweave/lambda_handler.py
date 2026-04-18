"""Lambda entry point — minimal async API GW v2 → ASGI adapter for FastMCP 3.x.

Why no Mangum:
  Mangum is synchronous and calls loop.run_until_complete() internally.
  When our handler already runs inside loop.run_until_complete(), Mangum's
  nested call raises "This event loop is already running" on Python 3.12.

Why lifespan per-invocation:
  FastMCP 3.x uses contextvars internally. __aenter__() tokens must be
  reset in the same Context they were created in. Running lifespan startup
  once at cold-start and dispatch in subsequent run_until_complete() calls
  puts them in different Contexts → ValueError on token.reset().
  Per-invocation async-with keeps everything in one Context per call.
  Memgraph / KMS / DriftDetector singletons are module-level and survive
  across Lambda invocations, so there is no reconnect overhead.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from io import BytesIO

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=os.environ.get("CIPHERWEAVE_LOG_LEVEL", "INFO"),
    format="%(levelname)s %(name)s %(message)s",
)

from cipherweave.cipher_janitor import CipherJanitor
from cipherweave.config import settings
from cipherweave.drift_detector import DriftDetector
from cipherweave.risk_engine import RiskGraph
from cipherweave.server import inject_components, mcp

# ---------------------------------------------------------------------------
# Persistent event loop — one loop for the lifetime of the Lambda container.
# ---------------------------------------------------------------------------
_loop = asyncio.new_event_loop()
asyncio.set_event_loop(_loop)

# Build the ASGI app once (no I/O)
_asgi_app = mcp.http_app(stateless_http=True)

# ---------------------------------------------------------------------------
# Deferred Memgraph / KMS initialization (cached across warm invocations)
# ---------------------------------------------------------------------------
_initialized = False


async def _async_init() -> None:
    from cipherweave.risk_engine import MockRiskGraph

    risk_graph: RiskGraph
    try:
        risk_graph = RiskGraph(
            memgraph_host=settings.memgraph_host,
            memgraph_port=settings.memgraph_port,
        )
        await risk_graph.connect()
        await risk_graph.initialize_schema()
        logger.info("Connected to Memgraph at %s:%s", settings.memgraph_host, settings.memgraph_port)
    except Exception as exc:
        logger.warning(
            "Memgraph unavailable (%s:%s — %s); falling back to MockRiskGraph",
            settings.memgraph_host, settings.memgraph_port, exc,
        )
        risk_graph = MockRiskGraph()

    kms_client = None
    bedrock_client = None
    if not settings.use_local_kms and settings.kms_key_id:
        import boto3
        kms_client = boto3.client("kms", region_name=settings.aws_region)
        bedrock_client = boto3.client("bedrock-runtime", region_name=settings.aws_region)
        logger.info("Bedrock policy inference enabled (model=%s)", settings.bedrock_inference_model_id)

    inject_components(
        risk_graph,
        CipherJanitor(kms_client=kms_client, master_key_id=settings.kms_key_id),
        DriftDetector(window_size=settings.drift_window_size),
        bedrock_client=bedrock_client,
    )
    logger.info(
        "CipherWeave initialized — Memgraph=%s:%s",
        settings.memgraph_host,
        settings.memgraph_port,
    )


def _ensure_init() -> None:
    global _initialized
    if _initialized:
        return
    _loop.run_until_complete(_async_init())
    _initialized = True


# ---------------------------------------------------------------------------
# Minimal API Gateway HTTP v2 → ASGI adapter
# ---------------------------------------------------------------------------
async def _dispatch(event: dict) -> dict:
    """Convert an API GW HTTP v2 payload-format-2.0 event to ASGI and run it.

    The FastMCP lifespan is entered and exited within this single coroutine so
    all ContextVar tokens live in exactly one asyncio Context.
    """
    http_ctx = event.get("requestContext", {}).get("http", {})
    method = http_ctx.get("method", "GET").upper()
    path = event.get("rawPath", "/")

    # HTTP API with a named stage includes the stage prefix in rawPath
    # (e.g. /prod/mcp). Strip it so FastMCP sees /mcp.
    stage = event.get("requestContext", {}).get("stage", "")
    if stage and stage != "$default":
        prefix = f"/{stage}"
        if path.startswith(prefix):
            path = path[len(prefix):] or "/"
    query_string = event.get("rawQueryString", "").encode()
    raw_headers = event.get("headers", {}) or {}

    headers = [(k.lower().encode(), v.encode()) for k, v in raw_headers.items()]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string,
        "root_path": "",
        "headers": headers,
        "server": ("lambda", 443),
    }

    raw_body = event.get("body") or ""
    body_bytes: bytes = (
        base64.b64decode(raw_body)
        if event.get("isBase64Encoded")
        else (raw_body.encode() if isinstance(raw_body, str) else raw_body)
    )

    body_sent = False
    response_complete = asyncio.Event()

    async def receive():
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        # Hold here until the response is fully sent, then signal disconnect.
        # Returning http.disconnect immediately causes FastMCP to terminate the
        # SSE session before it sends the response body.
        await response_complete.wait()
        return {"type": "http.disconnect"}

    resp_status = 200
    resp_headers: dict[str, str] = {}
    resp_body = BytesIO()

    async def send(message: dict) -> None:
        nonlocal resp_status, resp_headers
        if message["type"] == "http.response.start":
            resp_status = message["status"]
            resp_headers = {
                k.decode(): v.decode()
                for k, v in message.get("headers", [])
            }
        elif message["type"] == "http.response.body":
            resp_body.write(message.get("body", b""))
            if not message.get("more_body", False):
                response_complete.set()

    async with _asgi_app.lifespan(_asgi_app):
        await _asgi_app(scope, receive, send)

    return {
        "statusCode": resp_status,
        "headers": resp_headers,
        "body": resp_body.getvalue().decode("utf-8", errors="replace"),
        "isBase64Encoded": False,
    }


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------
def handler(event: dict, context: object) -> dict:
    # Temporary debug probe — remove once path routing is confirmed
    raw = event.get("rawPath", "")
    if raw.rstrip("/").endswith("/_debug"):
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "rawPath": event.get("rawPath"),
                "routeKey": event.get("routeKey"),
                "version": event.get("version"),
                "http_path": event.get("requestContext", {}).get("http", {}).get("path"),
                "stage": event.get("requestContext", {}).get("stage"),
            }),
        }

    try:
        _ensure_init()
    except Exception as exc:
        logger.exception("Initialization error")
        return {
            "statusCode": 503,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "service_unavailable", "detail": str(exc)}),
        }

    try:
        return _loop.run_until_complete(_dispatch(event))
    except Exception as exc:
        logger.exception("Dispatch error")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "internal_error", "detail": str(exc)}),
        }
