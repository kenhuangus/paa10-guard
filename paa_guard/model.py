"""Normalized action schema and helpers.

Every adapter (MCP proxy, hook, HTTP, platform packs) converts its native event into this shape:

{
  "id": "optional caller id",
  "agent": "muse | grok | dots | duet | claude-code | generic",
  "actor": {"agent_id": "...", "parent_agent_id": "...", "delegation_depth": 0},
  "mandate_id": "standing authorization this action claims to act under",
  "class": "read | draft | send | post | share | purchase | payment | transfer | delete | modify |
            account_security | credential_entry | download | execute | memory_write | recommend |
            message_to_user | record | model_call",
  "tool": "gmail.send", "resource": "gmail:inbox", "reversible": true,
  "content": {"text": "...", "attachments": [{"name": "...", "context": "private", "sensitivity": "finance"}],
              "agent_labeled": true, "inferred_attributes": ["health"]},
  "recipients": [{"id": "pat@example.com", "relation": "self | household | contact | colleague | public | unknown"}],
  "recipients_source": "user | recent_contacts | contact_list",
  "visibility": "private | public",
  "context": {"target_context": "work", "source_contexts": ["work", "private"]},
  "data_subjects": [{"id": "partner", "relation": "partner", "category": "location"}],
  "participants": [{"id": "guest", "is_user": false}],
  "payment": {"payee": "...", "payee_account": "...", "amount": 31.43, "currency": "USD", "recurring": false,
              "merchant_domain": "walmart.com", "idempotency_key": "..."},
  "target_domain": "login page domain for credential_entry",
  "memory": {"key": "...", "value": "...", "authority": "preference | instruction | payee | contact | address",
             "source": {"kind": "user | untrusted | tool", "ref": "email:123"}, "confirmed": false},
  "uses_memory": ["keys this action relies on"],
  "recommendation": {"topic": "...", "items": [{"id": "...", "price": 9, "sponsored": false, "disclosed": false}],
                     "criteria": {"max_price": 20}},
  "topic": "solicitation topic, for refusal tracking",
  "cost_usd": 0.0,
  "connector": {"id": "...", "version_hash": "..."},
  "command": "shell command text for execute",
  "provenance": {"triggered_by": "user | schedule | untrusted_content | agent", "untrusted_text": "..."},
  "approval_token": "approval request id issued earlier"
}
"""
import copy
import datetime as dt
import hashlib
import json

OUTBOUND = {"send", "post", "share"}
MONEY = {"purchase", "payment", "transfer"}


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def parse_time(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    t = dt.datetime.fromisoformat(s)
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def iso(t):
    return t.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def normalize(action):
    a = copy.deepcopy(action or {})
    a.setdefault("agent", "generic")
    a.setdefault("class", "read")
    a["class"] = str(a["class"]).lower()
    a.setdefault("actor", {})
    a["actor"].setdefault("delegation_depth", 0)
    a.setdefault("content", {})
    a["content"].setdefault("text", "")
    a["content"].setdefault("attachments", [])
    a.setdefault("recipients", [])
    a["recipients"] = [r if isinstance(r, dict) else {"id": str(r), "relation": "unknown"} for r in a["recipients"]]
    a.setdefault("provenance", {})
    a["provenance"].setdefault("triggered_by", "user")
    a.setdefault("data_subjects", [])
    a.setdefault("participants", [])
    for k in ("data_subjects", "participants"):
        if not isinstance(a[k], list):
            a[k] = [a[k]]
        a[k] = [x if isinstance(x, dict) else {"id": str(x), "relation": "unknown"} for x in a[k]]
    a.setdefault("uses_memory", [])
    return a


def all_text(a):
    """Text the guard inspects for secrets, sensitive categories, and pressure tactics."""
    parts = [a.get("content", {}).get("text", ""), a.get("command", "") or ""]
    for att in a.get("content", {}).get("attachments", []):
        parts.append(att.get("name", ""))
        parts.append(att.get("text", ""))
    return "\n".join(p for p in parts if p)


def material_terms(a):
    """The terms an approval is bound to. If any of these change, the approval no longer applies."""
    p = a.get("payment") or {}
    return {
        "class": a.get("class"),
        "tool": a.get("tool"),
        "resource": a.get("resource"),
        "recipients": sorted(r.get("id", "") for r in a.get("recipients", [])),
        "visibility": a.get("visibility"),
        "text_sha256": hashlib.sha256(all_text(a).encode("utf8")).hexdigest(),
        "payee": p.get("payee"),
        "payee_account": p.get("payee_account"),
        "amount": p.get("amount"),
        "currency": p.get("currency"),
        "recurring": p.get("recurring"),
        "merchant_domain": p.get("merchant_domain"),
        "target_domain": a.get("target_domain"),
        "memory_key": (a.get("memory") or {}).get("key"),
        "memory_value": (a.get("memory") or {}).get("value"),
    }


def digest(a):
    return hashlib.sha256(json.dumps(material_terms(a), sort_keys=True).encode("utf8")).hexdigest()


def fingerprint(a):
    """Identity of an action for loop detection (same tool, target and payload)."""
    raw = json.dumps([a.get("class"), a.get("tool"), a.get("resource"), material_terms(a)["text_sha256"],
                      sorted(r.get("id", "") for r in a.get("recipients", []))], sort_keys=True)
    return hashlib.sha256(raw.encode("utf8")).hexdigest()[:24]


def summarize(a):
    """One-line human summary shown on approval requests, built from fields, never from model prose."""
    c = a.get("class")
    p = a.get("payment") or {}
    bits = [c]
    if a.get("tool"):
        bits.append(f"via {a['tool']}")
    if p:
        bits.append(f"{p.get('amount')} {p.get('currency')} to {p.get('payee') or p.get('merchant_domain')}"
                    + (" (recurring)" if p.get("recurring") else ""))
    if a.get("recipients"):
        ids = [r.get("id", "") for r in a["recipients"]]
        bits.append("to " + ", ".join(ids[:5]) + (f" +{len(ids) - 5} more" if len(ids) > 5 else ""))
    if a.get("visibility") == "public":
        bits.append("PUBLIC")
    if a.get("memory"):
        bits.append(f"remember {a['memory'].get('key')}={a['memory'].get('value')!r}")
    if a.get("target_domain"):
        bits.append(f"on {a['target_domain']}")
    return " ".join(str(b) for b in bits)
