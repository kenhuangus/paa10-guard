"""paa-guard command line. Owner commands (approve, stop, resume, mandate, payee, consent, memory) live here and
in the owner HTTP endpoints only; the agent-facing MCP tools cannot call them."""
import argparse
import json
import os
import sys

from . import __version__, ops
from .engine import Guard
from .mapping import load_mapping
from .policy import DEFAULT_POLICY
from .rules import render
from .state import Store

EXIT = {"allow": 0, "deny": 2, "require_approval": 3}


def _print(obj):
    print(json.dumps(obj, indent=2))


def main(argv=None):
    # MCP, hooks and check all speak UTF-8 JSON; Windows would otherwise use the locale code page
    for s in (sys.stdin, sys.stdout):
        try:
            s.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog="paa-guard", description="Reference guard for the OWASP Top 10 for Personal AI Agents.")
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--home", help="state directory (default ~/.paa-guard or PAA_GUARD_HOME)")
    ap.add_argument("--policy", help="policy JSON (merged over defaults)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the state directory and write the default policy for editing")
    c = sub.add_parser("check", help="check one action (JSON from a file or stdin); exit 0 allow, 3 approval, 2 deny")
    c.add_argument("file", nargs="?", default="-")
    a = sub.add_parser("approve", help="approve a pending request (owner)")
    a.add_argument("id")
    a.add_argument("--note", default="")
    d = sub.add_parser("reject", help="reject a pending request (owner)")
    d.add_argument("id")
    sub.add_parser("pending", help="list pending approval requests")
    s = sub.add_parser("stop", help="stop all agents, or one with --agent")
    s.add_argument("--agent")
    s.add_argument("--reason", default="")
    r = sub.add_parser("resume", help="resume after a stop (owner)")
    r.add_argument("--agent")
    sub.add_parser("status", help="show stop state, mandates, approvals, quarantined memory, audit integrity")

    m = sub.add_parser("mandate", help="standing authorizations (PAA01)")
    ms = m.add_subparsers(dest="mcmd", required=True)
    madd = ms.add_parser("add")
    madd.add_argument("id")
    madd.add_argument("--purpose", required=True)
    madd.add_argument("--classes", required=True, help="comma list, e.g. read,draft")
    madd.add_argument("--resources", default="", help="comma list of glob patterns, e.g. gmail:*,calendar:*")
    madd.add_argument("--expires", help="ISO time, e.g. 2026-11-06T23:59:00Z")
    madd.add_argument("--parent")
    madd.add_argument("--max-delegation-depth", type=int, default=0)
    mrev = ms.add_parser("revoke")
    mrev.add_argument("id")
    ms.add_parser("list")

    p = sub.add_parser("payee", help="verified payees (PAA05)")
    ps = p.add_subparsers(dest="pcmd", required=True)
    padd = ps.add_parser("add")
    padd.add_argument("name")
    padd.add_argument("--account", required=True)
    padd.add_argument("--verified-via", required=True)
    ps.add_parser("list")
    mer = sub.add_parser("merchant", help="add a verified merchant domain (PAA05)")
    mer.add_argument("domain")

    cs = sub.add_parser("consent", help="consent recorded from another person (PAA08)")
    css = cs.add_subparsers(dest="ccmd", required=True)
    cadd = css.add_parser("add")
    cadd.add_argument("subject")
    cadd.add_argument("--category", required=True)
    cadd.add_argument("--audience", default="")
    cadd.add_argument("--expires")
    cadd.add_argument("--evidence", default="")
    crev = css.add_parser("revoke")
    crev.add_argument("subject")
    crev.add_argument("--category")

    mem = sub.add_parser("memory", help="inspect and correct agent memory (PAA04)")
    mems = mem.add_subparsers(dest="memcmd", required=True)
    mems.add_parser("list")
    for name in ("confirm", "delete"):
        x = mems.add_parser(name)
        x.add_argument("key")

    rf = sub.add_parser("refusal", help="record that you said no to something (PAA09)")
    rf.add_argument("topic")
    pin = sub.add_parser("pin", help="pin a connector or skill version (PAA02)")
    pin.add_argument("connector")
    pin.add_argument("version_hash")

    au = sub.add_parser("audit", help="verify or show the hash-chained audit log (PAA10)")
    au.add_argument("action", choices=["verify", "tail"])
    au.add_argument("-n", type=int, default=20)
    ex = sub.add_parser("export", help="export state and audit log (PAA10)")
    ex.add_argument("path")

    ru = sub.add_parser("rules", help="print a rule pack for a platform")
    ru.add_argument("--platform", choices=["dots", "grok", "muse", "claude"], default="dots")

    sv = sub.add_parser("serve", help="HTTP API + MCP over HTTP for hosted agents")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8787)
    sub.add_parser("mcp", help="MCP server over stdio (agent-facing guard tools)")
    px = sub.add_parser("proxy", help="gate a downstream stdio MCP server: paa-guard proxy [--map f] -- cmd args...")
    px.add_argument("--map")
    px.add_argument("--agent", default="generic")
    px.add_argument("downstream", nargs=argparse.REMAINDER)
    hk = sub.add_parser("hook", help="host hook adapters")
    hk.add_argument("host", choices=["claude-code"])
    hk.add_argument("--map")

    args = ap.parse_args(argv)
    if args.home:
        os.environ["PAA_GUARD_HOME"] = args.home
    if args.policy:
        os.environ["PAA_GUARD_POLICY"] = args.policy
    store = Store()
    guard = Guard(store)

    if args.cmd == "init":
        path = os.path.join(store.root, "policy.json")
        if not os.path.exists(path):
            with open(path, "w", encoding="utf8") as f:
                json.dump(DEFAULT_POLICY, f, indent=2)
        print(f"State: {store.root}\nPolicy: {path} (edit limits, merchants and account domains here)")
        return 0
    if args.cmd == "check":
        raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf8").read()
        res = guard.check(json.loads(raw.lstrip("﻿")))
        _print(res)
        return EXIT[res["decision"]]
    if args.cmd == "approve":
        _print(guard.approve(args.id, True, args.note))
        return 0
    if args.cmd == "reject":
        _print(guard.approve(args.id, False))
        return 0
    if args.cmd == "pending":
        _print(guard.status()["pending_approvals"])
        return 0
    if args.cmd == "stop":
        _print(guard.stop(args.agent, args.reason))
        return 0
    if args.cmd == "resume":
        guard.resume(args.agent)
        print("resumed", args.agent or "all agents")
        return 0
    if args.cmd == "status":
        _print(guard.status())
        return 0
    if args.cmd == "mandate":
        if args.mcmd == "add":
            res = [r for r in args.resources.split(",") if r]
            _print(ops.add_mandate(store, args.id, args.purpose, [c.strip() for c in args.classes.split(",") if c.strip()],
                                   res, args.expires, args.parent, args.max_delegation_depth))
        elif args.mcmd == "revoke":
            print("withdrawn:", ", ".join(ops.revoke_mandate(store, args.id)))
        else:
            _print(store.load()["mandates"])
        return 0
    if args.cmd == "payee":
        if args.pcmd == "add":
            ops.add_payee(store, args.name, args.account, args.verified_via)
            print("payee recorded")
        else:
            _print(store.load()["payees"])
        return 0
    if args.cmd == "merchant":
        ops.add_merchant(store, args.domain)
        print("merchant verified:", args.domain)
        return 0
    if args.cmd == "consent":
        if args.ccmd == "add":
            ops.add_consent(store, args.subject, args.category, args.audience, args.expires, args.evidence)
            print("consent recorded")
        else:
            print("removed", ops.revoke_consent(store, args.subject, args.category))
        return 0
    if args.cmd == "memory":
        if args.memcmd == "list":
            _print(store.load()["memory"])
        else:
            ops.memory_set_status(store, args.key, "active" if args.memcmd == "confirm" else "deleted")
            print(args.memcmd + "ed", args.key)
        return 0
    if args.cmd == "refusal":
        ops.add_refusal(store, args.topic)
        print("recorded refusal:", args.topic)
        return 0
    if args.cmd == "pin":
        ops.pin_connector(store, args.connector, args.version_hash)
        print("pinned")
        return 0
    if args.cmd == "audit":
        if args.action == "verify":
            ok, n, bad = store.verify_audit()
            print(f"audit log {'intact' if ok else 'TAMPERED at seq ' + str(bad)} ({n} records)")
            return 0 if ok else 1
        _print(store.tail(args.n))
        return 0
    if args.cmd == "export":
        print("exported to", ops.export(store, args.path))
        return 0
    if args.cmd == "rules":
        print(render(args.platform, guard.policy))
        return 0
    if args.cmd == "serve":
        from .http_server import serve
        serve(args.host, args.port, guard)
        return 0
    if args.cmd == "mcp":
        from .mcp import serve_stdio
        serve_stdio(guard)
        return 0
    if args.cmd == "proxy":
        from .mcp import run_proxy
        cmd = args.downstream[1:] if args.downstream[:1] == ["--"] else args.downstream
        if not cmd:
            ap.error("give the downstream MCP server command after --")
        run_proxy(cmd, guard, load_mapping(args.map), args.agent)
        return 0
    if args.cmd == "hook":
        from .hooks import claude_pretooluse
        return claude_pretooluse(guard=guard, mapping=load_mapping(args.map))
    return 1


if __name__ == "__main__":
    sys.exit(main())
