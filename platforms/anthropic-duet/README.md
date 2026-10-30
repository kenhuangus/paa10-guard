# Anthropic Claude Duet (and other Claude surfaces)

## What Duet offers

Claude Duet (research preview, October 2026) carries over the memory, skills and connectors on your Claude account, uses connectors and plugins from the Claude Marketplace, and asks for approval on sensitive steps such as payments. A hands-on review reports that Duet could not use local skills, so the reviewer packaged them as plugins. Anthropic's plugin format bundles skills, MCP servers and hooks. No source documents hooks running inside Duet itself. Sources: [TechCrunch](https://techcrunch.com/2026/10/22/claude-duet-app-is-anthropics-bet-on-agents/), [Lenny's Newsletter review](https://www.lennysnewsletter.com/p/claude-duet-is-beautiful-i-still), [Claude Code plugins reference](https://code.claude.com/docs/en/plugins-reference).

## Setup

This repository is a Claude plugin and plugin marketplace:

- `skills/paa10-guard/SKILL.md`: the rules and the check-before-acting habit.
- `.mcp.json`: the guard's MCP tools (a local stdio server).
- `hooks/hooks.json`: a `PreToolUse` hook that checks every tool call. It is used where hooks run, such as Claude Code and the Agent SDK.

1. **Claude Code or the Agent SDK (full enforcement).**

   ```
   /plugin marketplace add kenhuangus/paa10-guard
   /plugin install paa10-guard@paa10-guard
   ```

   Every tool call then passes through the guard: deny blocks it, and require_approval opens Claude's own confirmation prompt, so your answer there is the approval. The hook needs `python3` on your PATH. On Windows, make sure `python3` resolves (or edit the command to `python`).

2. **Duet.** Install the same plugin from the Claude Marketplace or your organization's plugin catalog once it is listed, so Duet gets the skill. Duet runs in the cloud and cannot start a local stdio server, so add the guard as a remote connector: run `paa-guard serve` behind HTTPS (see the [Meta Muse guide](../meta-muse/README.md#setup)) and add `https://YOUR-HOST/mcp` as a custom connector with the agent token.

3. **Approve and stop.** Use `paa-guard pending`, `paa-guard approve <id>` and `paa-guard stop`, or the owner HTTP endpoints. Duet's own payment approvals still apply on top.

## What is enforced and what is advisory

| Surface | Enforcement |
|---|---|
| Claude Code and Agent SDK, via the plugin hook | Enforced on every tool call. |
| Connectors behind `paa-guard proxy` | Enforced. |
| Duet built-in actions | The skill asks Duet to check first (advisory); Duet's own approvals and classifier still apply. |
