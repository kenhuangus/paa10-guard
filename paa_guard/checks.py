"""One check per PAA10 entry. Each returns findings: (rule, outcome, reason).

Outcomes: "deny" (blocked; an approval cannot override), "approve" (needs the owner's bound approval),
"quarantine" (PAA04 memory held for review), "warn" (reported only).
Rules are named after the entry's provider requirement so a decision can be traced back to the Top 10 text.
"""
import datetime as dt
import fnmatch

from . import detectors as det
from .model import MONEY, OUTBOUND, all_text, fingerprint, parse_time, utcnow


def F(rule, outcome, reason):
    return {"rule": rule, "paa": rule.split(".")[0], "outcome": outcome, "reason": reason}


def _consequential(a, pol):
    return a["class"] in pol["consequential_classes"]


def _recent(items, minutes, now, key="at"):
    cut = now - dt.timedelta(minutes=minutes)
    return [i for i in items if parse_time(i[key]) >= cut]


# ---------------------------------------------------------------- PAA01 Personal Mandate Drift
def _mandate_chain(st, mid):
    chain, seen = [], set()
    while mid and mid not in seen:
        seen.add(mid)
        m = st["mandates"].get(mid)
        if not m:
            return None
        chain.append(m)
        mid = m.get("parent")
    return chain


def paa01(a, st, pol, now):
    out = []
    cls = a["class"]
    mid = a.get("mandate_id")
    if mid:
        chain = _mandate_chain(st, mid)
        if chain is None:
            return [F("PAA01.unknown_mandate", "deny", f"Mandate {mid!r} does not exist; authority cannot be assumed.")]
        for m in chain:
            if m.get("revoked"):
                out.append(F("PAA01.withdrawn", "deny", f"Mandate {m['id']!r} was withdrawn by the owner."))
            exp = parse_time(m.get("expires"))
            if exp and now > exp:
                out.append(F("PAA01.expired", "deny", f"Mandate {m['id']!r} expired at {m['expires']}; it cannot be replayed."))
            if cls not in m.get("classes", []):
                out.append(F("PAA01.outside_scope", "deny",
                             f"Action class {cls!r} is outside mandate {m['id']!r} (allows {', '.join(m.get('classes', []))})."))
            res = a.get("resource")
            if m.get("resources") and res and not any(fnmatch.fnmatch(res, p) for p in m["resources"]):
                out.append(F("PAA01.outside_resources", "deny", f"Resource {res!r} is outside mandate {m['id']!r}."))
        top = chain[0]
        depth = a["actor"].get("delegation_depth", 0)
        if depth > top.get("max_delegation_depth", 0):
            out.append(F("PAA01.delegation_depth", "deny",
                         f"Delegation depth {depth} exceeds what mandate {top['id']!r} allows ({top.get('max_delegation_depth', 0)})."))
    elif cls in pol["require_mandate_for"]:
        if a["provenance"]["triggered_by"] == "schedule":
            out.append(F("PAA01.scheduled_without_mandate", "deny",
                         "A scheduled job tried a consequential action without an active mandate."))
        else:
            out.append(F("PAA01.no_mandate", "approve",
                         f"No standing mandate covers {cls!r}; the owner must approve this one action."))
    if _consequential(a, pol) and a["provenance"]["triggered_by"] == "untrusted_content":
        out.append(F("PAA01.untrusted_trigger", "approve",
                     "This action was proposed while processing untrusted content; read-only work must not silently become action."))
    return out


# ---------------------------------------------------------------- PAA02 Account and Recovery Takeover
def paa02(a, st, pol, now):
    out = []
    cls = a["class"]
    text = all_text(a)
    to_self_only = a["recipients"] and all(r.get("relation") == "self" for r in a["recipients"])
    if cls in OUTBOUND and not to_self_only:
        secrets = det.find_secrets(text)
        if secrets:
            out.append(F("PAA02.secret_egress", "deny",
                         f"Outbound content contains {', '.join(secrets)}; codes and secrets never leave through the agent."))
    if cls == "account_security":
        if a["provenance"]["triggered_by"] == "untrusted_content":
            out.append(F("PAA02.recovery_change_from_untrusted", "deny",
                         "Account or recovery changes requested by untrusted content are refused."))
        else:
            out.append(F("PAA02.protected_flow", "approve",
                         "Recovery, password, 2FA and connected-app changes need the owner, through the provider's own flow."))
    if cls == "execute" and det.credential_exfil(a.get("command", "")):
        out.append(F("PAA02.credential_exfiltration", "deny", "Command reads a credential store and sends data over the network."))
    if pol.get("pin_connectors") and a.get("connector"):
        c = a["connector"]
        pinned = st["connectors"].get(c.get("id"))
        if not pinned:
            out.append(F("PAA02.unpinned_connector", "deny", f"Connector {c.get('id')!r} is not on the owner's allowlist."))
        elif c.get("version_hash") and pinned != c.get("version_hash"):
            out.append(F("PAA02.connector_changed", "deny",
                         f"Connector {c.get('id')!r} changed since it was pinned; re-review before use."))
    return out


# ---------------------------------------------------------------- PAA03 Private Life Context Exposure
def paa03(a, st, pol, now):
    out = []
    if a["class"] not in OUTBOUND:
        return out
    to_self_only = a["recipients"] and all(r.get("relation") == "self" for r in a["recipients"])
    if to_self_only:
        return out
    ctx = a.get("context") or {}
    target = ctx.get("target_context")
    allowed = pol["contexts"].get(target) if target else None
    if allowed is not None:
        sources = set(ctx.get("source_contexts", [])) | {att.get("context") for att in a["content"]["attachments"] if att.get("context")}
        crossing = sorted(s for s in sources if s not in allowed)
        if crossing:
            out.append(F("PAA03.context_crossing", "approve",
                         f"Content from the {', '.join(crossing)} context is going to a {target} audience; preview before sending."))
    cats = set(det.sensitive_categories(all_text(a)))
    cats |= {att["sensitivity"] for att in a["content"]["attachments"] if att.get("sensitivity")}
    cats &= set(pol["sensitive_categories"])
    if cats:
        out.append(F("PAA03.sensitive_disclosure", "approve",
                     f"Outbound content includes {', '.join(sorted(cats))} information; the owner previews it first."))
    inferred = a["content"].get("inferred_attributes") or []
    if inferred:
        out.append(F("PAA03.inference_disclosure", "approve",
                     f"Content reveals inferred attributes ({', '.join(inferred)}); inferences get the same protection as source data."))
    if a.get("visibility") == "public" and a["class"] == "share":
        out.append(F("PAA03.public_share", "approve", "Sharing makes this conversation or file public and possibly searchable."))
    return out


# ---------------------------------------------------------------- PAA04 Memory and Preference Corruption
def paa04(a, st, pol, now):
    out = []
    if a["class"] == "memory_write":
        m = a.get("memory") or {}
        src = (m.get("source") or {}).get("kind")
        if not src:
            return [F("PAA04.no_provenance", "deny", "Memory writes must record where the fact came from.")]
        authority = m.get("authority", "preference")
        if src != "user":
            if authority in pol["memory"]["authority_kinds"] or det.instruction_like(str(m.get("value", ""))):
                out.append(F("PAA04.untrusted_authority", "quarantine",
                             f"Content from {src} tried to store a lasting {authority}; held for the owner to confirm."))
            else:
                out.append(F("PAA04.untrusted_fact", "quarantine",
                             f"Fact from {src} content is kept separate from the owner's explicit instructions until confirmed."))
        elif authority in pol["memory"]["authority_kinds"] and not m.get("confirmed"):
            out.append(F("PAA04.confirm_authority", "approve",
                         f"Storing a lasting {authority} changes what the agent may do later; the owner confirms it."))
    if a.get("uses_memory") and _consequential(a, pol):
        ttl = dt.timedelta(days=pol["memory"]["default_ttl_days"])
        for key in a["uses_memory"]:
            rec = st["memory"].get(key)
            if not rec:
                out.append(F("PAA04.unknown_memory", "approve", f"Action relies on memory {key!r}, which has no recorded provenance."))
            elif rec.get("status") != "active":
                out.append(F("PAA04.unconfirmed_memory", "deny", f"Action relies on memory {key!r}, which is {rec.get('status')}."))
            elif parse_time(rec["created"]) + ttl < now:
                out.append(F("PAA04.stale_memory", "approve", f"Memory {key!r} is older than the review period; confirm it is still true."))
    return out


# ---------------------------------------------------------------- PAA05 Counterparty Deception and Scams
def paa05(a, st, pol, now):
    out = []
    cls = a["class"]
    trusted_merchants = list(pol["verified_merchants"]) + list(st["merchants"])
    if cls in MONEY:
        p = a.get("payment") or {}
        payee = p.get("payee")
        rec = st["payees"].get(payee) if payee else None
        if payee and rec and p.get("payee_account") and rec.get("account") and rec["account"] != p["payee_account"]:
            out.append(F("PAA05.changed_payment_details", "deny",
                         f"Payment details for {payee!r} differ from the independently verified record; verify by a known channel."))
        elif payee and not rec and not p.get("merchant_domain"):
            out.append(F("PAA05.new_payee", "approve", f"{payee!r} is a new payee; the owner approves new payees."))
        dom = p.get("merchant_domain")
        if dom:
            imitates = det.lookalike_of(dom, trusted_merchants)
            if imitates:
                out.append(F("PAA05.lookalike_merchant", "deny", f"{dom!r} imitates {imitates}; the listing matching the request is not proof."))
            elif not det.domain_trusted(dom, trusted_merchants):
                out.append(F("PAA05.unverified_merchant", "approve", f"{dom!r} is not a verified merchant."))
        urgency = det.pressure_phrases(a["provenance"].get("untrusted_text", "") + "\n" + all_text(a))
        if a["provenance"]["triggered_by"] == "untrusted_content" or urgency:
            out.append(F("PAA05.external_claim", "approve",
                         "The payment request came from an external party" + (f" with pressure ({', '.join(urgency)})" if urgency else "")
                         + "; an incoming request cannot supply its own proof of authority."))
    if cls == "credential_entry":
        dom = a.get("target_domain")
        imitates = det.lookalike_of(dom, list(pol["account_domains"]) + trusted_merchants) if dom else None
        if not dom:
            out.append(F("PAA05.unknown_login_page", "deny", "Credential entry without a known destination domain."))
        elif imitates:
            out.append(F("PAA05.phishing_page", "deny", f"Login page {dom!r} imitates {imitates}."))
        elif not det.domain_trusted(dom, pol["account_domains"]):
            out.append(F("PAA05.unknown_login_page", "deny", f"{dom!r} is not a known account domain for this owner."))
    if cls in {"download", "execute"} and a["provenance"]["triggered_by"] == "untrusted_content":
        out.append(F("PAA05.untrusted_instruction", "deny",
                     "A web page or message told the agent to download or run something; the owner did not ask for it."))
    return out


# ---------------------------------------------------------------- PAA06 Spending and Commitments
def paa06(a, st, pol, now):
    out = []
    cls = a["class"]
    sp = pol["spending"]
    if cls in MONEY:
        p = a.get("payment") or {}
        amt, cur = p.get("amount"), p.get("currency")
        if amt is None or not cur:
            return [F("PAA06.unknown_terms", "deny", "Amount or currency is unknown; uncertainty about material terms blocks execution.")]
        amt = float(amt)
        if cur != sp["currency"]:
            out.append(F("PAA06.currency", "approve", f"Charge is in {cur}, not the owner's {sp['currency']}."))
        if p.get("idempotency_key") and any(s.get("key") == p["idempotency_key"] for s in st["spend"]):
            out.append(F("PAA06.duplicate_charge", "deny", "A charge with this idempotency key was already made; check status instead of retrying."))
        if amt > sp["per_action_max"]:
            out.append(F("PAA06.per_action_cap", "deny", f"{amt} exceeds the per-action cap of {sp['per_action_max']}."))
        day = sum(s["amount"] for s in _recent(st["spend"], 24 * 60, now))
        month = sum(s["amount"] for s in _recent(st["spend"], 30 * 24 * 60, now))
        if day + amt > sp["daily_max"]:
            out.append(F("PAA06.daily_cap", "deny", f"Would bring today's agent spending to {day + amt:.2f} (cap {sp['daily_max']})."))
        if month + amt > sp["monthly_max"]:
            out.append(F("PAA06.monthly_cap", "deny", f"Would bring 30-day agent spending to {month + amt:.2f} (cap {sp['monthly_max']})."))
        if p.get("recurring") and sp["recurring_requires_approval"]:
            out.append(F("PAA06.recurring", "approve", "This creates a recurring charge or subscription."))
        if amt > sp["approval_threshold"]:
            out.append(F("PAA06.bound_approval", "approve",
                         f"Spending {amt} {cur} needs approval bound to payee, amount, currency and recurrence."))
    if cls == "model_call" and a.get("cost_usd"):
        used = sum(c["usd"] for c in _recent(st["costs"], 24 * 60, now))
        if used + float(a["cost_usd"]) > pol["model_budget"]["daily_usd"]:
            out.append(F("PAA06.model_budget", "deny", f"Daily model/API budget of {pol['model_budget']['daily_usd']} USD reached."))
    if cls == "delete" or (cls == "execute" and det.destructive(a.get("command", ""))):
        if a.get("reversible") is not True:
            out.append(F("PAA06.irreversible", "approve", "Irreversible or bulk destructive action; the owner confirms the exact target."))
    return out


# ---------------------------------------------------------------- PAA07 Social Representation
def paa07(a, st, pol, now):
    out = []
    if a["class"] not in {"send", "post"}:
        return out
    msg = pol["messaging"]
    others = [r for r in a["recipients"] if r.get("relation") != "self"]
    if len(others) > msg["max_recipients_without_approval"]:
        out.append(F("PAA07.audience_expansion", "approve", f"Message goes to {len(others)} recipients; confirm the audience."))
    if a.get("recipients_source") in {"recent_contacts", "contact_list"}:
        out.append(F("PAA07.derived_recipients", "approve",
                     f"Recipients were taken from {a['recipients_source']}, not chosen by the owner."))
    for r in others:
        n = len([s for s in _recent(st["sends"], 1, now) if s["to"] == r.get("id")])
        if n >= msg["per_recipient_per_minute"]:
            out.append(F("PAA07.rate_limit", "deny", f"Already sent {n} messages to {r.get('id')} in the last minute; possible loop."))
            break
    if a.get("visibility") == "public" or any(r.get("relation") == "public" for r in a["recipients"]) or a["class"] == "post":
        if msg["public_requires_approval"]:
            out.append(F("PAA07.public_statement", "approve", "Publishing in the owner's name needs the owner's review."))
    c = det.commitments(all_text(a))
    if c:
        out.append(F("PAA07.commitment", "approve", f"Message makes a commitment in the owner's name ({', '.join(c)})."))
    if msg.get("warn_if_not_agent_labeled") and not a["content"].get("agent_labeled"):
        out.append(F("PAA07.unlabeled", "warn", "Message is not marked as agent-originated."))
    return out


# ---------------------------------------------------------------- PAA08 Household and Bystander Consent
def _consented(st, subject, category, now):
    for c in st["consents"]:
        if c["subject"] == subject and c["category"] in (category, "*"):
            exp = parse_time(c.get("expires"))
            if not exp or exp > now:
                return True
    return False


def paa08(a, st, pol, now):
    out = []
    for s in a["data_subjects"]:
        if s.get("relation") in (None, "self"):
            continue
        cat = s.get("category")
        if cat in pol["subject_consent_required_for"] and not _consented(st, s.get("id"), cat, now):
            out.append(F("PAA08.no_subject_consent", "deny",
                         f"{s.get('id')}'s {cat} data is used without their recorded consent; owning the agent is not their permission."))
    if a["class"] == "record":
        missing = [p.get("id") for p in a["participants"] if not p.get("is_user") and not _consented(st, p.get("id"), "voice", now)]
        if missing:
            out.append(F("PAA08.recording_consent", "deny", f"Recording people who have not agreed: {', '.join(missing)}."))
    return out


# ---------------------------------------------------------------- PAA09 Manipulation of Personal Choice
def paa09(a, st, pol, now):
    out = []
    text = all_text(a)
    if a["class"] in {"recommend", "message_to_user"}:
        rec = a.get("recommendation") or {}
        undisclosed = [i.get("id") for i in rec.get("items", []) if i.get("sponsored") and not i.get("disclosed")]
        if undisclosed:
            out.append(F("PAA09.undisclosed_incentive", "deny", f"Paid placement not disclosed: {', '.join(map(str, undisclosed))}."))
        crit = rec.get("criteria") or {}
        items = rec.get("items") or []
        if items and crit.get("max_price") is not None:
            top = items[0]
            fits = [i for i in items if i.get("price") is not None and i["price"] <= crit["max_price"]]
            if top.get("price") is not None and top["price"] > crit["max_price"] and fits:
                out.append(F("PAA09.criteria_override", "deny",
                             f"Top pick costs {top['price']} although the owner's limit is {crit['max_price']} and {len(fits)} option(s) fit."))
        p = det.pressure_phrases(text)
        if p:
            out.append(F("PAA09.false_urgency", "deny", f"Pressure language aimed at the owner: {', '.join(p)}."))
        g = det.guilt_phrases(text)
        if g:
            out.append(F("PAA09.emotional_pressure", "deny", f"Emotional pressure aimed at the owner: {', '.join(g)}."))
        topic = a.get("topic") or rec.get("topic")
        if topic:
            hours = pol["persuasion"]["refusal_cooldown_hours"]
            for r in _recent(st["refusals"], hours * 60, now):
                if r["topic"].lower() == str(topic).lower():
                    out.append(F("PAA09.refusal_respected", "deny", f"The owner declined {topic!r}; no re-solicitation for {hours} hours."))
                    break
    return out


# ---------------------------------------------------------------- PAA10 Control and Continuity
def paa10(a, st, pol, now):
    out = []
    stop = st["stopped"]
    agent_id = a["actor"].get("agent_id") or a.get("agent")
    if stop.get("global") or agent_id in stop.get("agents", []) or a["actor"].get("parent_agent_id") in stop.get("agents", []):
        out.append(F("PAA10.stopped", "deny", f"The owner stopped this agent ({stop.get('reason') or 'no reason given'}). Queued and delegated work is halted too."))
    if a["class"] in pol["never_allowed"]:
        out.append(F("PAA10.never_delegated", "deny", f"{a['class']!r} is never delegated to the agent."))
    if a["class"] in pol["always_require_approval"]:
        out.append(F("PAA10.owner_only_step", "approve", f"{a['class']!r} always needs the owner."))
    lp = pol["loop"]
    fp = fingerprint(a)
    n = len([f for f in _recent(st["fingerprints"], lp["window_minutes"], now) if f["fp"] == fp])
    if _consequential(a, pol) and n >= lp["max_identical"]:
        out.append(F("PAA10.loop_breaker", "deny",
                     f"Identical action repeated {n} times in {lp['window_minutes']} minutes; stopping a likely runaway loop."))
    return out


ALL = [paa01, paa02, paa03, paa04, paa05, paa06, paa07, paa08, paa09, paa10]
