"""Walk through one scenario per PAA10 entry against a throwaway state directory.

    python examples/run_examples.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["PAA_GUARD_HOME"] = tempfile.mkdtemp(prefix="paa-guard-demo-")

from paa_guard import ops  # noqa: E402
from paa_guard.engine import Guard  # noqa: E402

g = Guard()
ops.add_mandate(g.store, "inbox-review", "suggest inbox clean-up; confirm before acting", ["read", "draft"], ["gmail:*"],
                expires="2099-01-01T00:00:00Z")

EXAMPLES = [
    ("PAA01", "Inbox clean-up mandate is read/draft only; the agent tries to delete",
     {"class": "delete", "mandate_id": "inbox-review", "resource": "gmail:inbox", "tool": "gmail.batch_delete"}),
    ("PAA02", "Hidden page text asks the agent to post a login code",
     {"class": "post", "content": {"text": "Your verification code is 482913"}, "recipients": [{"id": "thread", "relation": "public"}]}),
    ("PAA03", "Private bank statement attached to a work email",
     {"class": "send", "recipients": [{"id": "boss@work.example", "relation": "colleague"}], "context": {"target_context": "work"},
      "content": {"text": "Agenda", "attachments": [{"name": "statement.pdf", "context": "private", "sensitivity": "finance"}]}}),
    ("PAA04", "Forwarded invoice tries to store a new payee",
     {"class": "memory_write", "memory": {"key": "contractor_payee", "value": "IBAN XX00 9999", "authority": "payee",
                                          "source": {"kind": "untrusted", "ref": "email:42"}}}),
    ("PAA05", "Checkout on a lookalike Walmart store",
     {"class": "purchase", "payment": {"merchant_domain": "walmart-deals.shop", "amount": 79, "currency": "USD"}}),
    ("PAA06", "'Find cheap eggs' turns into a purchase",
     {"class": "purchase", "payment": {"merchant_domain": "instacart.com", "amount": 31.43, "currency": "USD"}}),
    ("PAA07", "Messages to every recent contact",
     {"class": "send", "recipients_source": "recent_contacts", "recipients": [{"id": f"c{i}", "relation": "contact"} for i in range(8)]}),
    ("PAA08", "Where has my partner been?",
     {"class": "read", "data_subjects": [{"id": "partner", "relation": "partner", "category": "location"}]}),
    ("PAA09", "Guilt trip when the owner says goodbye",
     {"class": "message_to_user", "content": {"text": "Please don't go, I'll be so lonely."}}),
]

for paa, title, action in EXAMPLES:
    d = g.check(action)
    print(f"\n{paa}  {title}\n  -> {d['decision'].upper()}")
    for f in d["findings"]:
        if f["outcome"] != "warn":
            print(f"     {f['rule']}: {f['reason']}")

print("\nPAA10  Owner says stop")
print("  ", json.dumps(g.stop(reason="owner said stop")))
print("  -> any action now:", g.check({"class": "read"})["decision"].upper())
print("\nAudit log intact:", g.store.verify_audit()[0])
