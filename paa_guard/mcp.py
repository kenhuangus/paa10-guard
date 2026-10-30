"""MCP surfaces.

1. Guard server (stdio or HTTP): agent-facing tools to check an action, store a memory, record a refusal,
   read status, and stop itself. Approve, resume, mandates, payees and consents are owner-only and are
   deliberately absent here: an agent must not be able to grant itself authority.

2. Gating proxy (stdio): sits between the agent host and any MCP tool server. Every tools/call is mapped to
   a PAA action and checked before it is forwarded. This is enforcement outside the model.
"""
import json
import subprocess
import sys
import threading

from . import __version__
from .engine import Guard
from .mapping import APPROVAL_ARG, to_action
from .ops import add_refusal

PROTOCOL = "2025-06-18"

TOOLS = [
    {"name": "paa_guard_check",
     "description": ("Check a proposed action against the owner's PAA10 guard BEFORE doing it. Returns allow, "
                     "require_approval (stop and tell the owner the approval id; retry with approval_token after they approve) "
                     "or deny (do not attempt the action another way). See the paa10-guard skill for the action fields."),
     "inputSchema": {"type": "object", "properties": {"action": {"type": "object", "description": "Normalized PAA action"}},
                     "required": ["action"]}},
    {"name": "paa_guard_remember",
     "description": ("Ask to store a lasting memory. Facts from emails, web pages or tool output are quarantined until the "
                     "owner confirms; instructions, payees, contacts and addresses always need confirmation."),
     "inputSchema": {"type": "object", "properties": {
         "key": {"type": "string"}, "value": {"type": "string"},
         "authority": {"type": "string", "enum": ["preference", "fact", "instruction", "payee", "contact", "address", "trusted_source"]},
         "source_kind": {"type": "string", "enum": ["user", "untrusted", "tool"]},
         "source_ref": {"type": "string"}}, "required": ["key", "value", "source_kind"]}},
    {"name": "paa_guard_record_refusal",
     "description": "Record that the owner said no to something (an offer, upsell, plan). The guard blocks re-asking for the cooldown period.",
     "inputSchema": {"type": "object", "properties": {"topic": {"type": "string"}}, "required": ["topic"]}},
    {"name": "paa_guard_status",
     "description": "Read whether the agent is stopped, which mandates are active, and how many approvals are pending.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "paa_guard_stop_self",
     "description": "Stop this agent immediately (for example when the owner says stop). Only the owner can resume.",
     "inputSchema": {"type": "object", "properties": {"reason": {"type": "string"}, "agent_id": {"type": "string"}}}},
]


def _text(obj, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(obj, indent=2)}], "isError": is_error}


def call_tool(guard, name, args):
    args = args or {}
    if name == "paa_guard_check":
        return _text(guard.check(args.get("action") or {}))
    if name == "paa_guard_remember":
        action = {"class": "memory_write", "agent": args.get("agent", "generic"),
                  "memory": {"key": args["key"], "value": args["value"], "authority": args.get("authority", "preference"),
                             "source": {"kind": args["source_kind"], "ref": args.get("source_ref")}}}
        return _text(guard.check(action))
    if name == "paa_guard_record_refusal":
        add_refusal(guard.store, args["topic"])
        return _text({"recorded": True, "topic": args["topic"]})
    if name == "paa_guard_status":
        s = guard.status()
        return _text({"stopped": s["stopped"], "active_mandates": [{"id": m["id"], "purpose": m["purpose"], "classes": m["classes"],
                                                                   "expires": m["expires"]} for m in s["active_mandates"]],
                      "pending_approvals": len(s["pending_approvals"]), "quarantined_memories": len(s["quarantined_memory"])})
    if name == "paa_guard_stop_self":
        return _text(guard.stop(agent=args.get("agent_id"), reason=args.get("reason", "agent requested stop")))
    return _text({"error": f"unknown tool {name}"}, True)


def handle(guard, msg):
    """Handle one JSON-RPC message for the guard server. Returns a response dict or None for notifications."""
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:
        return None
    try:
        if method == "initialize":
            ver = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL
            res = {"protocolVersion": ver, "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": {"name": "paa10-guard", "version": __version__},
                   "instructions": "Call paa_guard_check before any action that sends, posts, buys, pays, deletes, "
                                   "changes accounts, records people, or stores lasting memory. Obey deny. On require_approval, "
                                   "stop and give the owner the approval id."}
        elif method == "ping":
            res = {}
        elif method == "tools/list":
            res = {"tools": TOOLS}
        elif method == "tools/call":
            p = msg.get("params") or {}
            res = call_tool(guard, p.get("name"), p.get("arguments"))
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": res}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(e)}}


def serve_stdio(guard=None, inp=sys.stdin, out=sys.stdout):
    guard = guard or Guard()
    for line in inp:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(guard, msg)
        if resp is not None:
            out.write(json.dumps(resp) + "\n")
            out.flush()


# ------------------------------------------------------------------ gating proxy
def _approval_property():
    return {"type": "string", "description": "Approval id from the PAA10 guard, after the owner approved this exact action."}


def run_proxy(downstream_cmd, guard=None, mapping=None, agent="generic", inp=None, out=None):
    """Forward MCP traffic to a downstream stdio server, checking every tools/call first."""
    guard = guard or Guard()
    inp = inp or sys.stdin
    out = out or sys.stdout
    proc = subprocess.Popen(downstream_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
                            encoding="utf8")
    lock = threading.Lock()
    pending_lists = set()

    def emit(obj):
        with lock:
            out.write(json.dumps(obj) + "\n")
            out.flush()

    def pump():
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            # let the agent pass an approval token on any tool, and say the guard is in front
            if msg.get("id") in pending_lists and isinstance(msg.get("result"), dict):
                pending_lists.discard(msg["id"])
                for t in msg["result"].get("tools", []):
                    schema = t.setdefault("inputSchema", {"type": "object"})
                    schema.setdefault("properties", {})[APPROVAL_ARG] = _approval_property()
                    t["description"] = (t.get("description") or "") + " [Checked by the PAA10 guard before it runs.]"
            emit(msg)

    threading.Thread(target=pump, daemon=True).start()
    for line in inp:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("method") == "tools/list" and msg.get("id") is not None:
            pending_lists.add(msg["id"])
        if msg.get("method") == "tools/call":
            p = msg.get("params") or {}
            action = to_action(p.get("name"), p.get("arguments"), mapping, agent=agent)
            decision = guard.check(action)
            if decision["decision"] != "allow":
                emit({"jsonrpc": "2.0", "id": msg.get("id"), "result": _text({
                    "blocked_by": "paa10-guard", "decision": decision["decision"],
                    "reasons": [f["reason"] for f in decision["findings"] if f["outcome"] != "warn"],
                    "approval": decision.get("approval"),
                    "next_step": ("Tell the owner what you want to do and give them the approval id. Retry with "
                                  f"{APPROVAL_ARG} once they approve. Do not change the terms."
                                  if decision["decision"] == "require_approval"
                                  else "Do not attempt this action another way.")}, True)})
                continue
            if APPROVAL_ARG in (p.get("arguments") or {}):
                p["arguments"].pop(APPROVAL_ARG, None)
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
    proc.stdin.close()
    proc.wait(timeout=10)
