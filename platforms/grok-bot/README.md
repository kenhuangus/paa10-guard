# Grok Bot (xAI)

## What Grok Bot offers

According to xAI's documentation, a **skill** is a reusable set of instructions that you save by asking the Bot. Skills form a private library and are switched on per Bot under **Connect apps > Private skills**. **Routines** run on a schedule or on events, including webhooks: a `POST` with `Authorization: Bearer <key>`, where a `200` means the run started. The docs leave approvals to the skill or routine instructions; there is no separate platform-level approval setting. Source: [Skills and routines](https://docs.x.ai/grok-bot/skills-routines-and-automations).

Third-party guides say Grok Bot can use MCP servers and plugins. xAI's skills page does not document this, so treat it as unverified for your account.

## Setup

1. **Install the skill.** Run `paa-guard rules --platform grok > grok-skill.md` (or use [`rules.md`](rules.md)). Tell your Bot: *"Save this as a skill named PAA10 guard and follow it in every routine"*, and paste the text. Then turn the skill on for each Bot under Connect apps > Private skills.

2. **Add the guard connector (if your account supports MCP or custom apps).** Run `paa-guard serve` as described in the [Meta Muse guide](../meta-muse/README.md#setup) and connect `https://YOUR-HOST/mcp` with the agent token. If MCP is not available, keep the skill and route sensitive actions (email, payments) through services you control that call `POST /v1/check` first.

3. **Write approval boundaries into every routine.** xAI recommends confirming each routine's approval boundary. Use the guard's: *"Before sending, buying, paying, deleting or posting, check with the PAA10 guard and stop for my approval if it says so."*

4. **Stopping.** Pause the routine in Grok Bot (**Pause**, or **Active** off on the phone). Also run `paa-guard stop`, so any guard-gated action is refused even if a run is already in progress.

## What is enforced and what is advisory

| Path | Enforcement |
|---|---|
| Actions on services that call the guard or sit behind `paa-guard proxy` | Enforced. |
| The Bot's own built-in tools | Advisory: the skill asks the Bot to check first. Grok Bot exposes no documented pre-action hook. |
| Routine rate limits | xAI caps routines at 300 runs per hour in total and 200 per routine. The guard's loop breaker adds a per-action limit. |
