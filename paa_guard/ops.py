"""Owner operations on guard state. These are deliberately NOT exposed through the agent-facing MCP tools."""
import fnmatch
import json

from .model import iso, parse_time, utcnow


class OwnerError(ValueError):
    pass


def add_mandate(store, mid, purpose, classes, resources=None, expires=None, parent=None, max_delegation_depth=0):
    """PAA01: a mandate binds authority to purpose, action classes, resources, expiry, and delegation depth.
    A child mandate must be equal or narrower than its parent."""
    classes = sorted(set(classes))
    resources = list(resources or [])
    with store.transaction() as st:
        if mid in st["mandates"]:
            raise OwnerError(f"Mandate {mid!r} already exists")
        if parent:
            p = st["mandates"].get(parent)
            if not p or p.get("revoked"):
                raise OwnerError(f"Parent mandate {parent!r} is missing or withdrawn")
            if not set(classes) <= set(p["classes"]):
                raise OwnerError("A delegated mandate cannot add action classes its parent lacks")
            if p.get("resources"):
                if not resources:
                    resources = list(p["resources"])
                for r in resources:
                    if not any(fnmatch.fnmatch(r, pr) for pr in p["resources"]):
                        raise OwnerError(f"Resource {r!r} is wider than the parent's scope")
            pe, ce = parse_time(p.get("expires")), parse_time(expires)
            if pe and (not ce or ce > pe):
                expires = p["expires"]
            if max_delegation_depth > max(0, p.get("max_delegation_depth", 0) - 1):
                max_delegation_depth = max(0, p.get("max_delegation_depth", 0) - 1)
        st["mandates"][mid] = {"id": mid, "purpose": purpose, "classes": classes, "resources": resources,
                               "expires": expires, "parent": parent, "max_delegation_depth": max_delegation_depth,
                               "created": iso(utcnow()), "revoked": False}
        m = st["mandates"][mid]
    store.audit({"type": "mandate_add", "id": mid, "classes": classes, "expires": expires, "parent": parent})
    return m


def revoke_mandate(store, mid):
    """Withdrawal cascades to every mandate delegated from this one."""
    with store.transaction() as st:
        if mid not in st["mandates"]:
            raise OwnerError(f"No mandate {mid!r}")
        todo, done = [mid], []
        while todo:
            cur = todo.pop()
            st["mandates"][cur]["revoked"] = True
            st["mandates"][cur]["revoked_at"] = iso(utcnow())
            done.append(cur)
            todo += [k for k, v in st["mandates"].items() if v.get("parent") == cur and not v.get("revoked")]
    store.audit({"type": "mandate_revoke", "ids": done})
    return done


def add_payee(store, name, account, verified_via):
    """PAA05: payees are recorded only after verification through an independently established channel."""
    if not verified_via:
        raise OwnerError("Say how the payee was verified (for example: 'called the number on my last invoice')")
    with store.transaction() as st:
        st["payees"][name] = {"account": account, "verified_via": verified_via, "added": iso(utcnow())}
    store.audit({"type": "payee_add", "name": name})


def add_merchant(store, domain):
    with store.transaction() as st:
        if domain not in st["merchants"]:
            st["merchants"].append(domain.lower())
    store.audit({"type": "merchant_add", "domain": domain})


def add_consent(store, subject, category, audience="", expires=None, evidence=""):
    """PAA08: recorded permission from the person the data is about (not from the agent's owner)."""
    with store.transaction() as st:
        st["consents"].append({"subject": subject, "category": category, "audience": audience,
                               "expires": expires, "evidence": evidence, "added": iso(utcnow())})
    store.audit({"type": "consent_add", "subject": subject, "category": category})


def revoke_consent(store, subject, category=None):
    with store.transaction() as st:
        before = len(st["consents"])
        st["consents"] = [c for c in st["consents"] if not (c["subject"] == subject and (category is None or c["category"] == category))]
        n = before - len(st["consents"])
    store.audit({"type": "consent_revoke", "subject": subject, "category": category, "removed": n})
    return n


def add_refusal(store, topic):
    """PAA09: an explicit 'no' ends solicitation on that topic for the cooldown period."""
    with store.transaction() as st:
        st["refusals"].append({"topic": topic, "at": iso(utcnow())})
    store.audit({"type": "refusal", "topic": topic})


def pin_connector(store, cid, version_hash):
    with store.transaction() as st:
        st["connectors"][cid] = version_hash
    store.audit({"type": "connector_pin", "id": cid, "hash": version_hash})


def memory_set_status(store, key, status):
    with store.transaction() as st:
        if key not in st["memory"]:
            raise OwnerError(f"No memory {key!r}")
        if status == "deleted":
            del st["memory"][key]
        else:
            st["memory"][key]["status"] = status
    store.audit({"type": "memory_" + status, "key": key})


def export(store, path):
    """PAA10: the owner can take their records with them."""
    st = store.load()
    data = {"exported_at": iso(utcnow()), "state": st, "audit": store.tail(10 ** 9)}
    with open(path, "w", encoding="utf8") as f:
        json.dump(data, f, indent=2)
    store.audit({"type": "export", "path": path})
    return path
