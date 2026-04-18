#!/usr/bin/env python3
"""
JSON-RPC over HTTP — CipherWeave MCP tool invocation.

Usage:
    python scripts/invoke_mcp.py
    python scripts/invoke_mcp.py --agent agent-analytics --classification CONFIDENTIAL
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

BASE_URL = "https://mt0otvflba.execute-api.us-east-1.amazonaws.com/prod"
MCP_ENDPOINT = f"{BASE_URL}/mcp"

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def rpc(method: str, params: dict, req_id: int) -> dict:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    ).encode()

    req = urllib.request.Request(MCP_ENDPOINT, data=payload, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        print(f"HTTP {exc.code}: {body}", file=sys.stderr)
        sys.exit(1)

    # Streamable HTTP may return SSE lines; extract the JSON data line if so
    if raw.startswith("data:") or "\ndata:" in raw:
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                raw = line[len("data:"):].strip()
                break

    return json.loads(raw)


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


    print(f"Endpoint : {MCP_ENDPOINT}")
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
