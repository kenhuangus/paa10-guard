"""Hook adapters.

Claude Code / Claude Agent SDK PreToolUse hook: reads the hook JSON on stdin and answers with a permission
decision. allow -> no output (normal permissions continue); require_approval -> "ask", which shows the owner a
native confirmation prompt (the owner's answer in that prompt is the protected approval); deny -> "deny".

Any other host that can run a command before a tool call can use `paa-guard check` the same way
(exit 0 allow, exit 3 require approval, exit 2 deny).
"""
import json
import sys

from .engine import Guard
from .mapping import from_claude_code


def _emit(stdout, perm, reason):
    stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": perm,
                                                    "permissionDecisionReason": reason}}))
    stdout.flush()


def claude_pretooluse(stdin=sys.stdin, stdout=sys.stdout, guard=None, mapping=None):
    raw = stdin.read().lstrip("﻿")  # Windows tools often prepend a byte-order mark
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # fail closed: an unreadable request must not be waved through
        _emit(stdout, "deny", "PAA10 guard: could not read the tool call, so it was blocked.")
        return 0
    guard = guard or Guard()
    action = from_claude_code(payload, mapping)
    d = guard.check(action)
    if d["decision"] == "allow":
        return 0
    reasons = "; ".join(f["reason"] for f in d["findings"] if f["outcome"] != "warn")
    _emit(stdout, "ask" if d["decision"] == "require_approval" else "deny", f"PAA10 guard: {reasons}")
    return 0
