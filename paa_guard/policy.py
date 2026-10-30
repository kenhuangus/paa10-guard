"""Policy: the owner's limits. Defaults are conservative; override with a JSON file (PAA_GUARD_POLICY or --policy)."""
import copy
import json
import os

DEFAULT_POLICY = {
    "version": 1,
    # actions that change the world or speak for the owner
    "consequential_classes": ["send", "post", "share", "purchase", "payment", "transfer", "delete", "modify",
                              "account_security", "credential_entry", "download", "execute", "memory_write", "record"],
    # PAA01: these need a standing mandate, otherwise a one-off approval
    "require_mandate_for": ["send", "post", "purchase", "payment", "transfer", "delete", "account_security"],
    # never delegated to the agent (OpenAI Dots and Claude Duet document similar carve-outs)
    "never_allowed": ["trade_securities"],
    "always_require_approval": ["account_security", "transfer", "credential_entry"],
    # PAA06
    "spending": {"currency": "USD", "per_action_max": 100, "daily_max": 200, "monthly_max": 1000,
                 "approval_threshold": 0, "recurring_requires_approval": True},
    "model_budget": {"daily_usd": 20},
    "loop": {"window_minutes": 10, "max_identical": 5},
    # PAA05
    "verified_merchants": ["amazon.com", "walmart.com", "instacart.com", "apple.com", "target.com", "bestbuy.com",
                           "booking.com", "expedia.com", "airbnb.com", "uber.com", "doordash.com"],
    "account_domains": ["google.com", "accounts.google.com", "microsoft.com", "apple.com", "wellsfargo.com",
                        "chase.com", "bankofamerica.com", "paypal.com", "perplexity.ai", "openai.com",
                        "meta.com", "facebook.com", "x.com", "anthropic.com", "claude.ai"],
    # PAA07
    "messaging": {"max_recipients_without_approval": 3, "per_recipient_per_minute": 5,
                  "public_requires_approval": True, "warn_if_not_agent_labeled": True},
    # PAA03
    "contexts": {"work": ["work"], "private": ["private", "family"], "family": ["family", "private"],
                 "public": []},
    "sensitive_categories": ["health", "finance", "relationship", "location", "religion", "sexuality", "legal",
                             "biometric", "government_id", "children"],
    # PAA04
    "memory": {"authority_kinds": ["instruction", "payee", "contact", "address", "trusted_source"],
               "default_ttl_days": 180},
    # PAA08
    "subject_consent_required_for": ["location", "messages", "health", "photos", "voice", "contacts", "finance"],
    # PAA09
    "persuasion": {"refusal_cooldown_hours": 72},
    # PAA02: connectors/skills/MCP servers allowed to run, pinned by version hash (empty = no pinning)
    "pin_connectors": False,
}


def deep_merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_policy(path=None):
    path = path or os.environ.get("PAA_GUARD_POLICY")
    if path and os.path.exists(path):
        with open(path, encoding="utf8") as f:
            return deep_merge(DEFAULT_POLICY, json.load(f))
    home = os.environ.get("PAA_GUARD_HOME") or os.path.join(os.path.expanduser("~"), ".paa-guard")
    p = os.path.join(home, "policy.json")
    if os.path.exists(p):
        with open(p, encoding="utf8") as f:
            return deep_merge(DEFAULT_POLICY, json.load(f))
    return copy.deepcopy(DEFAULT_POLICY)
