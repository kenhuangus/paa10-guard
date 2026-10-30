"""Owner-controlled state: mandates, approvals, payees, consents, memory ledger, ledgers, stop switch, audit log.

State lives in a directory (default ~/.paa-guard, override with PAA_GUARD_HOME). Writes are atomic and
serialized with a lock file so a hook, a proxy, and the CLI can share it.
"""
import contextlib
import hashlib
import json
import os
import time

from .model import iso, utcnow

EMPTY = {
    "stopped": {"global": False, "agents": [], "reason": "", "at": None},
    "mandates": {},
    "approvals": {},
    "payees": {},
    "merchants": [],
    "consents": [],
    "memory": {},
    "refusals": [],
    "spend": [],
    "sends": [],
    "fingerprints": [],
    "costs": [],
    "connectors": {},
}


def home():
    return os.environ.get("PAA_GUARD_HOME") or os.path.join(os.path.expanduser("~"), ".paa-guard")


class Store:
    def __init__(self, root=None):
        self.root = root or home()
        os.makedirs(self.root, exist_ok=True)
        self.path = os.path.join(self.root, "state.json")
        self.audit_path = os.path.join(self.root, "audit.jsonl")
        self.lock_path = os.path.join(self.root, ".lock")

    @contextlib.contextmanager
    def lock(self, timeout=10.0):
        deadline = time.time() + timeout
        while True:
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                # a lock older than 30s is stale (crashed writer)
                try:
                    if time.time() - os.path.getmtime(self.lock_path) > 30:
                        os.remove(self.lock_path)
                        continue
                except OSError:
                    pass
                if time.time() > deadline:
                    raise TimeoutError("paa-guard state is locked")
                time.sleep(0.02)
        try:
            yield
        finally:
            os.close(fd)
            try:
                os.remove(self.lock_path)
            except OSError:
                pass

    def load(self):
        if not os.path.exists(self.path):
            return json.loads(json.dumps(EMPTY))
        with open(self.path, encoding="utf8") as f:
            data = json.load(f)
        for k, v in EMPTY.items():
            data.setdefault(k, json.loads(json.dumps(v)))
        return data

    def save(self, data):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    @contextlib.contextmanager
    def transaction(self):
        with self.lock():
            data = self.load()
            yield data
            self.save(data)

    # ---- audit log (append-only, hash-chained so tampering is detectable)
    def _last_hash(self):
        if not os.path.exists(self.audit_path):
            return "0" * 64, 0
        last = None
        with open(self.audit_path, encoding="utf8") as f:
            for line in f:
                if line.strip():
                    last = line
        if not last:
            return "0" * 64, 0
        rec = json.loads(last)
        return rec["hash"], rec["seq"]

    def audit(self, event):
        prev, seq = self._last_hash()
        rec = {"seq": seq + 1, "ts": iso(utcnow()), "prev": prev, "event": event}
        rec["hash"] = hashlib.sha256((prev + json.dumps(rec["event"], sort_keys=True) + rec["ts"]).encode("utf8")).hexdigest()
        with open(self.audit_path, "a", encoding="utf8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec["seq"]

    def verify_audit(self):
        prev = "0" * 64
        n = 0
        if not os.path.exists(self.audit_path):
            return True, 0, None
        with open(self.audit_path, encoding="utf8") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                expect = hashlib.sha256((prev + json.dumps(rec["event"], sort_keys=True) + rec["ts"]).encode("utf8")).hexdigest()
                if rec["prev"] != prev or rec["hash"] != expect:
                    return False, n, rec["seq"]
                prev = rec["hash"]
                n += 1
        return True, n, None

    def tail(self, n=20):
        if not os.path.exists(self.audit_path):
            return []
        with open(self.audit_path, encoding="utf8") as f:
            lines = [l for l in f if l.strip()]
        return [json.loads(l) for l in lines[-n:]]
