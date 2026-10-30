"""Decision engine: runs every PAA check, applies bound approvals, updates ledgers, writes the audit log."""
import secrets as _secrets

from . import checks
from .model import MONEY, digest, fingerprint, iso, normalize, summarize, utcnow
from .policy import load_policy
from .state import Store

RANK = {"warn": 0, "approve": 1, "quarantine": 1, "deny": 2}


class Guard:
    def __init__(self, store=None, policy=None):
        self.store = store or Store()
        self.policy = policy or load_policy()

    def check(self, action, now=None, record=True):
        """Evaluate one proposed action. Returns a decision dict; never raises for bad input."""
        now = now or utcnow()
        a = normalize(action)
        with self.store.transaction() as st:
            findings = []
            for fn in checks.ALL:
                try:
                    findings.extend(fn(a, st, self.policy, now))
                except Exception as e:  # a broken check must fail closed, not open
                    findings.append(checks.F(f"{fn.__name__.upper()}.check_error", "deny", f"Check failed: {e}"))
            worst = max([RANK[f["outcome"]] for f in findings] or [0])
            decision = {0: "allow", 1: "require_approval", 2: "deny"}[worst]
            quarantine = any(f["outcome"] == "quarantine" for f in findings)
            d = digest(a)
            result = {"decision": decision, "class": a["class"], "summary": summarize(a), "findings": findings, "digest": d}

            # A bound approval converts require_approval into allow, once, and only for identical terms.
            if decision == "require_approval" and a.get("approval_token"):
                ap = st["approvals"].get(a["approval_token"])
                if ap and ap["status"] == "approved" and not ap.get("used") and ap["digest"] == d:
                    ap["used"] = True
                    ap["used_at"] = iso(now)
                    decision = "allow"
                    result["decision"] = "allow"
                    result["approval"] = {"id": ap["id"], "status": "consumed"}
                elif ap and ap["digest"] != d:
                    result["findings"].append(checks.F("PAA06.terms_changed", "approve",
                                                       "Terms changed since approval (payee, amount, recipients, or content); approval no longer applies."))
                elif ap and ap.get("used"):
                    result["findings"].append(checks.F("PAA06.approval_used", "approve", "That approval was already used once."))
                elif ap and ap["status"] != "approved":
                    result["findings"].append(checks.F("PAA06.approval_pending", "approve", f"Approval {ap['id']} is {ap['status']}."))

            if result["decision"] == "require_approval":
                rid = "apr_" + _secrets.token_hex(6)
                st["approvals"][rid] = {"id": rid, "status": "pending", "digest": d, "created": iso(now),
                                        "summary": result["summary"], "class": a["class"],
                                        "memory_key": (a.get("memory") or {}).get("key") if a["class"] == "memory_write" else None,
                                        "reasons": [f["reason"] for f in findings if f["outcome"] in ("approve", "quarantine")]}
                result["approval"] = {"id": rid, "status": "pending",
                                      "how": f"Owner runs: paa-guard approve {rid}   (then the agent retries with approval_token={rid})"}

            if a["class"] == "memory_write" and result["decision"] != "deny" and a.get("memory"):
                m = a["memory"]
                status = "quarantined" if quarantine else ("active" if result["decision"] == "allow" else "pending")
                st["memory"][m.get("key")] = {"value": m.get("value"), "authority": m.get("authority", "preference"),
                                              "source": m.get("source"), "status": status, "created": iso(now)}
                result["memory_status"] = status

            if record and result["decision"] == "allow":
                st["fingerprints"].append({"at": iso(now), "fp": fingerprint(a)})
                if a["class"] in MONEY and a.get("payment"):
                    p = a["payment"]
                    st["spend"].append({"at": iso(now), "amount": float(p.get("amount") or 0), "currency": p.get("currency"),
                                        "payee": p.get("payee") or p.get("merchant_domain"), "key": p.get("idempotency_key")})
                if a["class"] in {"send", "post"}:
                    for r in a["recipients"]:
                        st["sends"].append({"at": iso(now), "to": r.get("id")})
                if a["class"] == "model_call" and a.get("cost_usd"):
                    st["costs"].append({"at": iso(now), "usd": float(a["cost_usd"])})
            # bound ledgers so the state file stays small
            for k in ("fingerprints", "sends", "costs"):
                st[k] = st[k][-2000:]

        result["audit_seq"] = self.store.audit({
            "type": "decision", "agent": a.get("agent"), "actor": a.get("actor"), "class": a["class"], "tool": a.get("tool"),
            "decision": result["decision"], "rules": [f["rule"] for f in result["findings"]], "digest": d,
            "summary": result["summary"]})
        return result

    # ---- owner operations (never exposed to the agent)
    def approve(self, rid, approve=True, note=""):
        with self.store.transaction() as st:
            ap = st["approvals"].get(rid)
            if not ap:
                raise KeyError(f"No approval request {rid}")
            if ap["status"] != "pending":
                raise ValueError(f"{rid} is already {ap['status']}")
            ap["status"] = "approved" if approve else "denied"
            ap["decided_at"] = iso(utcnow())
            ap["note"] = note
            # approving a held memory write is the owner's confirmation of that memory
            key = ap.get("memory_key")
            if key and key in st["memory"]:
                st["memory"][key]["status"] = "active" if approve else "rejected"
                if approve:
                    st["memory"][key]["confirmed_by_owner"] = ap["decided_at"]
                    ap["used"] = True
        self.store.audit({"type": "approval", "id": rid, "status": ap["status"]})
        return ap

    def stop(self, agent=None, reason=""):
        with self.store.transaction() as st:
            if agent:
                if agent not in st["stopped"]["agents"]:
                    st["stopped"]["agents"].append(agent)
            else:
                st["stopped"]["global"] = True
            st["stopped"]["reason"] = reason
            st["stopped"]["at"] = iso(utcnow())
            # outstanding approvals die with the stop, so queued work cannot resume on old consent
            cancelled = 0
            for ap in st["approvals"].values():
                if ap["status"] in ("pending", "approved") and not ap.get("used"):
                    ap["status"] = "cancelled_by_stop"
                    cancelled += 1
            snap = dict(st["stopped"])
        self.store.audit({"type": "stop", "agent": agent, "reason": reason, "cancelled_approvals": cancelled})
        # "enforced" means every later check will deny; the agent's own acknowledgment is not relied on
        return {"enforced": True, "scope": agent or "all agents", "cancelled_approvals": cancelled, "state": snap}

    def resume(self, agent=None):
        with self.store.transaction() as st:
            if agent:
                st["stopped"]["agents"] = [x for x in st["stopped"]["agents"] if x != agent]
            else:
                st["stopped"] = {"global": False, "agents": [], "reason": "", "at": None}
        self.store.audit({"type": "resume", "agent": agent})

    def status(self):
        st = self.store.load()
        now = utcnow()
        from .model import parse_time
        active = [m for m in st["mandates"].values() if not m.get("revoked") and not (parse_time(m.get("expires")) and parse_time(m["expires"]) < now)]
        ok, n, bad = self.store.verify_audit()
        return {"stopped": st["stopped"], "active_mandates": active,
                "pending_approvals": [a for a in st["approvals"].values() if a["status"] == "pending"],
                "quarantined_memory": {k: v for k, v in st["memory"].items() if v.get("status") != "active"},
                "payees": st["payees"], "consents": st["consents"],
                "audit": {"intact": ok, "records": n, "first_bad_seq": bad}}
