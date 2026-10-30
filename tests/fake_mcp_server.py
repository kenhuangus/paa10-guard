"""A tiny downstream MCP server used to test the gating proxy. It 'sends email' by echoing."""
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:
        continue
    if method == "initialize":
        res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "0"}}
    elif method == "tools/list":
        res = {"tools": [{"name": "send_email", "description": "Send an email",
                          "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
                         {"name": "list_messages", "description": "List messages", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        p = msg["params"]
        res = {"content": [{"type": "text", "text": "EXECUTED " + p["name"] + " " + json.dumps(p.get("arguments", {}), sort_keys=True)}]}
    else:
        res = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}) + "\n")
    sys.stdout.flush()
