"""HTTP surface (stdlib only) for hosted agents: Meta Muse custom connectors, ChatGPT apps used by Dots,
Claude connectors used by Duet, or any webhook-capable agent.

  POST /mcp            MCP JSON-RPC (agent token)          -> guard tools for the agent
  POST /v1/check       {"action": {...}} (agent token)     -> decision
  POST /v1/stop        {"agent": "...", "reason": "..."}   -> agent or owner token; anyone allowed can stop
  GET  /v1/status      owner token
  POST /v1/approve     {"id": "...", "approve": true} owner token
  POST /v1/resume      {"agent": "..."} owner token

Two different bearer tokens: PAA_GUARD_AGENT_TOKEN for the agent, PAA_GUARD_OWNER_TOKEN for the owner.
The agent token can never approve or resume. Run behind HTTPS (a reverse proxy or tunnel) when exposed.
"""
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import Guard
from .mcp import handle


def make_handler(guard, agent_token, owner_token):
    class H(BaseHTTPRequestHandler):
        server_version = "paa10-guard"

        def log_message(self, fmt, *args):  # keep request logs off stdout
            pass

        def _role(self):
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            if owner_token and tok and hmac.compare_digest(tok, owner_token):
                return "owner"
            if agent_token and tok and hmac.compare_digest(tok, agent_token):
                return "agent"
            return None

        def _send(self, code, obj):
            body = json.dumps(obj).encode("utf8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 1_000_000:
                raise ValueError("request too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            role = self._role()
            if self.path == "/healthz":
                return self._send(200, {"ok": True})
            if self.path == "/v1/status":
                if role != "owner":
                    return self._send(403, {"error": "owner token required"})
                return self._send(200, guard.status())
            self._send(404, {"error": "not found"})

        def do_POST(self):
            role = self._role()
            if role is None:
                return self._send(401, {"error": "missing or invalid bearer token"})
            try:
                body = self._body()
            except Exception as e:
                return self._send(400, {"error": str(e)})
            try:
                if self.path == "/mcp":
                    msgs = body if isinstance(body, list) else [body]
                    out = [r for r in (handle(guard, m) for m in msgs) if r is not None]
                    if not out:
                        self.send_response(202)
                        self.end_headers()
                        return
                    return self._send(200, out if isinstance(body, list) else out[0])
                if self.path == "/v1/check":
                    return self._send(200, guard.check(body.get("action") or {}))
                if self.path == "/v1/stop":
                    return self._send(200, guard.stop(agent=body.get("agent"), reason=body.get("reason", "")))
                if role != "owner":
                    return self._send(403, {"error": "owner token required"})
                if self.path == "/v1/approve":
                    return self._send(200, guard.approve(body["id"], bool(body.get("approve", True)), body.get("note", "")))
                if self.path == "/v1/resume":
                    guard.resume(body.get("agent"))
                    return self._send(200, {"resumed": body.get("agent") or "all"})
            except (KeyError, ValueError) as e:
                return self._send(400, {"error": str(e)})
            self._send(404, {"error": "not found"})

    return H


def serve(host="127.0.0.1", port=8787, guard=None):
    agent_token = os.environ.get("PAA_GUARD_AGENT_TOKEN", "")
    owner_token = os.environ.get("PAA_GUARD_OWNER_TOKEN", "")
    if not agent_token or not owner_token:
        raise SystemExit("Set PAA_GUARD_AGENT_TOKEN and PAA_GUARD_OWNER_TOKEN (two different random values).")
    if agent_token == owner_token:
        raise SystemExit("The agent token and the owner token must differ.")
    httpd = ThreadingHTTPServer((host, port), make_handler(guard or Guard(), agent_token, owner_token))
    print(f"paa10-guard listening on http://{host}:{port}  (MCP at /mcp)", flush=True)
    httpd.serve_forever()
