**Top 10: https://kenhuangus.github.io/owasp-top-10-for-personal-ai-agents/**

**Crosswalk: [Agentic Skills Top 10 and MCP Top 10](docs/crosswalk.md)**

# paa10-guard

A reference mitigation for the [OWASP Top 10 for Personal AI Agents (PAA10)](https://github.com/kenhuangus/owasp-top-10-for-personal-ai-agents). It is a small, dependency-free policy guard that checks each action a personal agent proposes, outside the model, and answers **allow**, **require_approval**, or **deny**. It ships as a Python package, a CLI, an MCP server, a gating MCP proxy, a Claude plugin (skill, hook, MCP), and rule packs for Meta Muse, Grok Bot, OpenAI Dots and Anthropic Claude Duet.

> Status: v0.1 reference implementation for the PAA10 draft. Use it to learn from, test against, and adapt. It is not a certified product, and it does not replace a platform's own safeguards.

## Why "outside the model"

Every PAA10 entry asks providers to enforce limits at the permission or execution boundary, because a prompt like "confirm before acting" can be lost (the OpenClaw inbox case) or overridden by injected text (the Comet one-time-code case). The guard keeps mandates, approvals, payees, consents and the stop switch in an owner-controlled store that the agent cannot write to, and checks the action itself rather than what the model says about it.

## What it checks

| Entry | Main controls |
|---|---|
| PAA01 Mandate drift | Mandates bound to purpose, action classes, resources, expiry and delegation depth; children never wider than parents; withdrawal cascades |
| PAA02 Account takeover | Blocks one-time codes, reset links, keys and passwords in outbound content; hands recovery and 2FA changes to the owner; blocks credential-store exfiltration; connector pinning |
| PAA03 Context exposure | Work/private/family context crossing, sensitive categories and inferences, public sharing |
| PAA04 Memory corruption | Provenance on every memory; untrusted facts and instructions quarantined; unconfirmed memory cannot drive actions |
| PAA05 Scams | Lookalike and unverified merchants, changed payee details, new payees, phishing login pages, downloads a page demands |
| PAA06 Spending | Approvals bound to the exact terms and single-use; per-action, daily and monthly caps; duplicate-charge and model-budget limits; irreversible actions |
| PAA07 Representation | Draft vs send, audience expansion, contact-list blasts, per-recipient rate limits, commitments and public posts in the owner's name |
| PAA08 Household and bystanders | Consent recorded from the data subject, not the operator; no recording of non-users |
| PAA09 Choice manipulation | Undisclosed sponsorship, ranking against the owner's criteria, urgency and guilt language, respected refusals |
| PAA10 Control | Owner kill switch for all agents, one agent, or its children, which cancels outstanding approvals; loop breaker; hash-chained audit log; export |

[docs/mapping.md](docs/mapping.md) maps every provider requirement in the Top 10 to a guard rule and a test.

## Crosswalk to the Agentic Skills Top 10 and MCP Top 10

Personal agents are assembled from skills and MCP servers, so the guard is also mapped to the [OWASP Agentic Skills Top 10](https://owasp.github.io/www-project-agentic-skills-top-10/) and the [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10). [docs/crosswalk.md](docs/crosswalk.md) lists, for each AST and MCP item, the PAA entries it leads to, the guard rules that address it, and whether coverage is enforced or partial.

| | Enforced | Partial |
|---|---|---|
| Agentic Skills Top 10 | AST03, AST05, AST07, AST09 | AST01, AST02, AST04, AST06, AST08, AST10 |
| MCP Top 10 | MCP01, MCP02, MCP07, MCP08 | MCP03, MCP04, MCP05, MCP06, MCP09, MCP10 |

The guard does not judge whether a skill or server is trustworthy; it limits what any of them can make the agent do to its owner. Pair it with skill and server vetting, sandboxing, and routing every server through the proxy.

## Quick start

```bash
pip install git+https://github.com/kenhuangus/paa10-guard
paa-guard init                                  # writes ~/.paa-guard/policy.json for you to edit
python examples/run_examples.py                 # one scenario per entry (from a checkout)

echo '{"class":"purchase","payment":{"merchant_domain":"walmart-deals.shop","amount":79,"currency":"USD"}}' | paa-guard check
# exit code: 0 allow, 3 require_approval, 2 deny
```

You can also run it without installing: `python bin/paa-guard.py ...` from a checkout. It needs Python 3.9 or later and no other packages.

## Owner commands

```bash
paa-guard mandate add groceries --purpose "weekly groceries" --classes read,purchase --expires 2026-12-01T00:00:00Z
paa-guard pending                       # what the agent is waiting on
paa-guard approve apr_1a2b3c            # approve one exact action (any change in terms voids it)
paa-guard stop --reason "something is off"   # every later check denies; outstanding approvals are cancelled
paa-guard resume
paa-guard payee add "Acme Plumbing" --account acct-111 --verified-via "called the number on my last invoice"
paa-guard consent add partner --category location --evidence "partner turned on sharing"
paa-guard memory list | paa-guard memory confirm KEY | paa-guard memory delete KEY
paa-guard audit verify && paa-guard export my-agent-records.json
```

Approving, resuming, mandates, payees, consents and memory confirmation exist only on the CLI and on the owner HTTP endpoints, never on the agent's tools.

## Ways to plug it in

| Integration | Command or file | Enforcement |
|---|---|---|
| **Gating MCP proxy** in front of any stdio tool server | `paa-guard proxy [--map tool-map.json] -- <server command>` | Enforced: blocked calls are never forwarded |
| **Hook** (Claude Code, Agent SDK, any host that runs a pre-action command) | `hooks/hooks.json`, or `paa-guard hook claude-code`, or `paa-guard check` exit codes | Enforced on every tool call |
| **Hosted guard** for cloud agents (MCP over HTTP plus REST) | `paa-guard serve` with separate agent and owner tokens behind HTTPS | Enforced for services that call it |
| **Agent-facing MCP tools** | `paa-guard mcp` (`paa_guard_check`, `paa_guard_remember`, `paa_guard_record_refusal`, `paa_guard_status`, `paa_guard_stop_self`) | Advisory unless paired with the proxy |
| **Skill** | `skills/paa10-guard/SKILL.md` | Advisory |
| **Rule packs** | `paa-guard rules --platform dots/grok/muse/claude` | Enforced by the platform where it supports rules (Dots Custom Rules) |

## Platform guides

- [Meta Muse](platforms/meta-muse/README.md): hosted guard as a connector, proxy in front of risky connectors, skill text.
- [Grok Bot](platforms/grok-bot/README.md): skill, routine approval boundaries, guard connector where MCP is available.
- [OpenAI Dots](platforms/openai-dots/README.md): Custom Rules pack, narrow app permissions, guard as a ChatGPT app.
- [Anthropic Claude Duet and Claude Code](platforms/anthropic-duet/README.md): install as a plugin (`/plugin marketplace add kenhuangus/paa10-guard`), remote connector for Duet.

Each guide separates what the guard enforces from what is guidance to the agent. The platform descriptions are taken from vendor pages and reviews cited in each guide. Extension points differ by account and change over time, so check what your account offers.

## Tool mapping

The proxy and hook map tool calls to PAA actions. Unknown tools are classified from their names (`send_email` becomes `send`, `checkout` becomes `purchase`), and a tool with an unrecognized name is treated as `modify`, never as `read`. For accurate checks, give the proxy a map like [examples/tool-map.example.json](examples/tool-map.example.json) that says which argument holds the recipients, amount or merchant.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite has 55 tests: one or more scenarios per entry (most taken from the documented cases in the Top 10), integration tests for the CLI, the MCP server, the proxy, the hook adapter, and HTTP token separation, and checks that the crosswalk is complete and cites only real rules. CI runs it on Linux, Windows and macOS.

## Limits

See [docs/mapping.md](docs/mapping.md#limits-of-a-reference-implementation). In short: the guard enforces only where actions pass through it, its detectors are deliberately simple, and it trusts the fields an adapter supplies.

## License

Apache License 2.0.
