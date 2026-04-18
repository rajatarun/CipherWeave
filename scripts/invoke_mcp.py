#!/usr/bin/env python3
"""
JSON-RPC over HTTP — CipherWeave MCP tool invocation.

FastMCP 2.x uses Streamable HTTP transport: POST /mcp may return
text/event-stream. We read line-by-line and stop at the first data: event
so the connection is not held open indefinitely.

Usage:
    python scripts/invoke_mcp.py
    python scripts/invoke_mcp.py --agent agent-analytics --classification CONFIDENTIAL
"""

import argparse
import http.client
import json
import ssl
import sys
import urllib.parse

import os

BASE_URL = os.environ.get(
    "CIPHERWEAVE_URL",
    "https://mt0otvflba.execute-api.us-east-1.amazonaws.com/prod",
).rstrip("/")
MCP_PATH = "/mcp"
HOST = BASE_URL.removeprefix("https://").split("/")[0]


def rpc(method: str, params: dict, req_id: int) -> dict:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    ).encode()

    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, timeout=30, context=ctx)
    try:
        conn.request(
            "POST",
            MCP_PATH,
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Content-Length": str(len(payload)),
            },
        )
        resp = conn.getresponse()

        if resp.status >= 400:
            body = resp.read().decode()
            print(f"HTTP {resp.status}: {body}", file=sys.stderr)
            sys.exit(1)

        content_type = resp.getheader("Content-Type", "")

        # SSE stream — read line-by-line, stop at first data: event
        if "text/event-stream" in content_type:
            result_json = None
            while True:
                line = resp.readline()
                if not line:
                    break
                line = line.decode().rstrip("\r\n")
                if line.startswith("data:"):
                    result_json = line[len("data:"):].strip()
                    break
            if result_json is None:
                print("SSE stream ended without data event", file=sys.stderr)
                sys.exit(1)
            return json.loads(result_json)

        # Plain JSON response
        return json.loads(resp.read().decode())

    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Invoke CipherWeave MCP tool")
    parser.add_argument("--agent", default="agent-analytics")
    parser.add_argument(
        "--url",
        default="https://56u86rj4qk.execute-api.us-east-1.amazonaws.com/prod/query",
    )
    parser.add_argument(
        "--classification",
        default="CONFIDENTIAL",
        choices=["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "TOP_SECRET"],
    )
    parser.add_argument(
        "--tags",
        nargs="*",
        default=["GDPR"],
        help="Regulatory tags e.g. HIPAA GDPR PCI",
    )
    args = parser.parse_args()

    print(f"Endpoint : {BASE_URL}/mcp")
    print(f"Agent    : {args.agent}")
    print(f"Target   : {args.url}")
    print(f"Class    : {args.classification}")
    print(f"Tags     : {args.tags}")
    print()

    # ── 1. initialize ────────────────────────────────────────────────────────
    print("── initialize ──────────────────────────────────────────")
    init_resp = rpc(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "cipherweave-cli", "version": "0.1"},
        },
        req_id=1,
    )
    print(json.dumps(init_resp, indent=2))
    print()

    # ── 2. tools/list ────────────────────────────────────────────────────────
    print("── tools/list ──────────────────────────────────────────")
    list_resp = rpc("tools/list", {}, req_id=2)
    tools = list_resp.get("result", {}).get("tools", [])
    for t in tools:
        print(f"  • {t['name']}: {t.get('description', '')}")
    print()

    # ── 3. tools/call → get_encryption_strategy ──────────────────────────────
    print("── tools/call: get_encryption_strategy ─────────────────")
    call_resp = rpc(
        "tools/call",
        {
            "name": "get_encryption_strategy",
            "arguments": {
                "agent_id": args.agent,
                "destination_url": args.url,
                "data_metadata": {
                    "classification": args.classification,
                    "tags": args.tags,
                },
            },
        },
        req_id=3,
    )
    print(json.dumps(call_resp, indent=2))


if __name__ == "__main__":
    main()
