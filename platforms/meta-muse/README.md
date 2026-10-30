# Meta Muse

## What Muse offers

Muse reaches outside services through **connectors**. Meta's Muse Connector Platform accepts either a hosted MCP endpoint or a raw API with an OpenAPI spec, authenticated with API keys or OAuth with PKCE, and reviews submissions before listing them. Meta's built-in connectors come with written instructions (skills). Reports differ on whether individual users can add their own MCP URL as a custom connector, so check what your account shows. Sources: [Stacktree's account of the connector form](https://stacktr.ee/blog/muse-connector-platform), [AI Agents Library](https://www.aiagentslibrary.com/blog/meta-muse-mcp/).

Muse has no documented pre-action hook that third parties can attach to, so the guard is enforced only for actions that pass through it.

## Setup

1. **Run the guard as a hosted connector.** Run it on any host Muse can reach over HTTPS: a small VM, a container, or a tunnel to a home machine.

   ```bash
   pip install git+https://github.com/kenhuangus/paa10-guard
   export PAA_GUARD_AGENT_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
   export PAA_GUARD_OWNER_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
   paa-guard init
   paa-guard serve --host 127.0.0.1 --port 8787   # put HTTPS in front (Caddy, nginx, or a tunnel)
   ```

   Give Muse the MCP endpoint `https://YOUR-HOST/mcp` with the **agent** token as its API key. Keep the **owner** token for yourself; Muse never gets it.

2. **Route risky tools through the gate.** For the strongest setup, put `paa-guard proxy` in front of the MCP servers that send, pay, or delete, and register the proxied endpoint as the connector instead of the raw service. A blocked call then never reaches the service, whatever the model decides.

3. **Add the instructions.** Paste [`rules.md`](rules.md) as the connector's skill text, or as standing instructions in Muse. It tells Muse to call `paa_guard_check` first and how to handle each decision.

4. **Approve from your phone or laptop.** Run `paa-guard pending` and `paa-guard approve <id>`, or `POST /v1/approve` with the owner token.

## What is enforced and what is advisory

| Path | Enforcement |
|---|---|
| Tools reached through `paa-guard proxy` | Enforced: a blocked call is never forwarded. |
| Muse calling `paa_guard_check` before its own built-in actions | Advisory: depends on Muse following the skill. Muse's own action review still applies. |
| Stop | `paa_guard_stop_self` or `POST /v1/stop` makes every later guard check deny. Also use Muse's own stop control, because the guard cannot halt actions that do not pass through it. |
