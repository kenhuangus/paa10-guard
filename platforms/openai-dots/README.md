# OpenAI Dots

## What Dots offers

OpenAI's launch post describes three controls: the apps a Dot may use, managed through ChatGPT app controls; built-in and **Custom Rules** for when the Dot acts on its own or asks; and **action review** that checks actions against your instructions, rules and safety requirements. Some sensitive steps, such as changing a password, always stay with you. Third-party guides add that Custom Rules can allow, require approval for, or block an action. OpenAI has not published a public Dots API. Sources: [Introducing dots](https://openai.com/index/introducing-dots/), [Dots privacy, security, and safety FAQs](https://help.openai.com/en/articles/20001529-dots-privacy-security-and-safety-faqs).

## Setup

1. **Paste the rule pack.** Run `paa-guard rules --platform dots`, or open [`custom-rules.md`](custom-rules.md). Add each line to the Dot's Custom Rules: **Block** lines as block rules, **Require approval** lines as approval rules. This is the fastest win and needs no server.

2. **Narrow app permissions.** Give each Dot only the apps its job needs. This is PAA01 (mandate) and PAA03 (context) in Dots' own terms. Use separate Dots for work and personal tasks.

3. **Optional: add the guard as an app.** ChatGPT apps are built on MCP. If your workspace lets you connect a custom app, run `paa-guard serve` (see the [Meta Muse guide](../meta-muse/README.md#setup)) and connect `https://YOUR-HOST/mcp` with the agent token. The Dot can then call `paa_guard_check`, record refusals, and stop itself. Put `paa-guard proxy` in front of any custom app that can send or pay, so a blocked call is refused before it reaches the service.

4. **Use Activity View with the audit log.** Dots shows what the agent did. `paa-guard audit tail` shows what the guard allowed or blocked, in a hash-chained log you can verify with `paa-guard audit verify`.

## What is enforced and what is advisory

| Path | Enforcement |
|---|---|
| Custom Rules | Enforced by OpenAI's action review, as OpenAI describes it. |
| Custom apps behind `paa-guard proxy` | Enforced by the guard. |
| Built-in Dot actions not routed through the guard | Covered by OpenAI's own controls only. |
