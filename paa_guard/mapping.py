"""Map a platform tool call (name + arguments) to a normalized PAA action.

Explicit mappings come from a JSON file; unknown tools fall back to name heuristics. Unknown tools that
look like they change something are classed conservatively (as `modify`), never as `read`.

Mapping file example (tool-map.json):
{
  "tools": {
    "gmail_send_email": {"class": "send", "fields": {"recipients": "to", "content.text": "body",
                                                     "context.target_context": "=work"}},
    "shop_checkout":    {"class": "purchase", "fields": {"payment.amount": "total", "payment.currency": "currency",
                                                         "payment.merchant_domain": "site"}}
  }
}
A field value starting with "=" is a constant; otherwise it is a dotted path into the tool arguments.
"""
import json
import re

APPROVAL_ARG = "_paa_approval_token"

_READ_VERBS = {"get", "list", "search", "read", "fetch", "find", "query", "lookup", "view", "show", "describe", "check", "summarize"}
_RULES = [  # (class, token prefixes); first match wins
    ("account_security", ["password", "passkey", "2fa", "mfa", "recovery", "reset", "oauth", "authorize"]),
    ("credential_entry", ["login", "signin", "credential", "autofill"]),
    ("transfer", ["wire", "transfer", "zelle", "venmo", "withdraw"]),
    ("payment", ["pay", "invoice", "bill"]),
    ("purchase", ["buy", "purchase", "checkout", "order", "book", "subscribe", "reserve"]),
    ("memory_write", ["remember", "memorize", "memory"]),
    ("draft", ["draft"]),
    ("post", ["post", "publish", "tweet", "comment"]),
    ("send", ["send", "reply", "forward", "message", "email", "sms", "text", "dm", "invite", "notify"]),
    ("share", ["share"]),
    ("delete", ["delete", "remove", "trash", "purge", "archive", "unsubscribe", "cancel"]),
    ("record", ["record", "transcribe"]),
    ("download", ["download"]),
    ("execute", ["exec", "run", "shell", "bash", "terminal", "command", "script"]),
]
_ARG_HINTS = {
    "recipients": ["to", "recipients", "recipient", "emails", "email", "phone", "contacts", "attendees", "channel"],
    "content.text": ["body", "text", "message", "content", "comment", "note", "subject", "html"],
    "payment.amount": ["amount", "total", "price", "cost", "sum"],
    "payment.currency": ["currency"],
    "payment.payee": ["payee", "merchant", "vendor", "recipient_name", "seller"],
    "payment.payee_account": ["account", "iban", "account_number", "wallet", "address_to"],
    "payment.merchant_domain": ["merchant_domain", "site", "store_url", "domain", "url"],
    "payment.recurring": ["recurring", "subscription", "auto_renew"],
    "target_domain": ["login_url", "page_url", "url", "domain"],
    "command": ["command", "cmd", "script"],
    "resource": ["path", "file", "file_path", "resource", "id", "message_id", "event_id"],
    "visibility": ["visibility", "privacy", "audience"],
}


def classify(tool_name):
    """Classify by name tokens: sendEmail / send_email / mcp__gmail__send_email all give `send`."""
    name = (tool_name or "").split("__")[-1]  # mcp__server__tool -> tool
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", name) if t]
    if not tokens:
        return "modify"
    if tokens[0] in _READ_VERBS:
        return "read"
    for cls, prefixes in _RULES:
        if any(t.startswith(p) for t in tokens for p in prefixes):
            return cls
    return "modify"


def _get(args, path):
    cur = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _set(obj, path, value):
    parts = path.split(".")
    for p in parts[:-1]:
        obj = obj.setdefault(p, {})
    obj[parts[-1]] = value


def _domain(v):
    m = re.match(r"(?i)^(?:https?://)?([^/:?#]+)", str(v or ""))
    return m.group(1).lower() if m else None


def to_action(tool_name, arguments, mapping=None, agent="generic", defaults=None):
    args = dict(arguments or {})
    token = args.pop(APPROVAL_ARG, None)
    spec = ((mapping or {}).get("tools") or {}).get(tool_name)
    a = {"agent": agent, "tool": tool_name, "class": (spec or {}).get("class") or classify(tool_name)}
    fields = (spec or {}).get("fields")
    if fields:
        for target, src in fields.items():
            val = src[1:] if isinstance(src, str) and src.startswith("=") else _get(args, src)
            if val is not None:
                _set(a, target, val)
    else:
        for target, keys in _ARG_HINTS.items():
            for k in keys:
                if k in args and args[k] not in (None, ""):
                    _set(a, target, args[k])
                    break
    # tidy up shapes
    rec = a.get("recipients")
    if rec is not None:
        if isinstance(rec, str):
            rec = [x.strip() for x in re.split(r"[,;]", rec) if x.strip()]
        a["recipients"] = [r if isinstance(r, dict) else {"id": str(r), "relation": "unknown"} for r in rec]
    if isinstance(a.get("content"), dict) and not isinstance(a["content"].get("text"), str):
        a["content"]["text"] = json.dumps(a["content"].get("text"))
    if a.get("payment"):
        p = a["payment"]
        if "merchant_domain" in p:
            p["merchant_domain"] = _domain(p["merchant_domain"])
        if "amount" in p:
            try:
                p["amount"] = float(str(p["amount"]).replace("$", "").replace(",", ""))
            except ValueError:
                p["amount"] = None
    if a["class"] != "credential_entry":
        a.pop("target_domain", None)
    elif a.get("target_domain"):
        a["target_domain"] = _domain(a["target_domain"])
    if a["class"] != "execute":
        a.pop("command", None)
    if a["class"] in {"purchase", "payment", "transfer"}:
        a.setdefault("payment", {})
    for k, v in (defaults or {}).items():
        a.setdefault(k, v)
    if token:
        a["approval_token"] = token
    # keep raw arguments so secret/sensitivity detectors see everything the tool would send
    raw = json.dumps(args, ensure_ascii=False)[:20000]
    a.setdefault("content", {})
    a["content"]["text"] = (a["content"].get("text") or "") + ("\n" + raw if raw not in (a["content"].get("text") or "") else "")
    return a


def from_claude_code(hook_input, mapping=None):
    """PreToolUse payload from Claude Code (and Agent SDK-style hosts) -> action."""
    name = hook_input.get("tool_name", "")
    ti = hook_input.get("tool_input") or {}
    base = {"agent": "claude", "actor": {"agent_id": hook_input.get("session_id", "claude")}}
    if name == "Bash":
        return {**base, "class": "execute", "tool": "Bash", "command": ti.get("command", ""),
                "content": {"text": ti.get("command", "")}}
    if name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return {**base, "class": "modify", "tool": name, "resource": ti.get("file_path") or ti.get("notebook_path"),
                "reversible": True, "content": {"text": str(ti.get("content") or ti.get("new_string") or "")[:20000]}}
    if name in ("Read", "Glob", "Grep", "WebSearch", "WebFetch", "LS", "TodoWrite", "Task"):
        return {**base, "class": "read", "tool": name}
    a = to_action(name, ti, mapping, agent="claude")
    a["actor"] = base["actor"]
    return a


def load_mapping(path):
    if not path:
        return None
    with open(path, encoding="utf8") as f:
        return json.load(f)
