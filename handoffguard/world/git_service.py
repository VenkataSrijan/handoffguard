"""A tiny local git-hosting API that really enforces token auth and scopes.

Runs on 127.0.0.1 in a background thread. Deploy and backup scripts call it
over HTTP from separate processes, so a 403 in the demo is produced by real
request handling, not by a flag.

Endpoints
  POST /repos/<owner>/<repo>/fetch   needs scope repo:read
  POST /repos/<owner>/<repo>/tags    needs scope contents:write
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NEEDS = {"fetch": "repo:read", "tags": "contents:write"}

_ACTIVE: dict = {"world": None}
_SERVER: dict = {"url": None, "server": None}
_LOCK = threading.Lock()


def set_active_world(world) -> None:
    _ACTIVE["world"] = world


def get_active_world():
    return _ACTIVE["world"]


class _Handler(BaseHTTPRequestHandler):
    server_version = "MockGit/1.0"

    def do_POST(self):  # noqa: N802 (http.server naming)
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        parts = self.path.strip("/").split("/")
        if len(parts) != 4 or parts[0] != "repos" or parts[3] not in NEEDS:
            return self._send(404, "remote: Repository not found.")
        world = _ACTIVE["world"]
        if world is None:
            return self._send(503, "remote: service unavailable (no world loaded)")
        auth = self.headers.get("Authorization", "")
        value = auth[7:].strip() if auth.startswith("Bearer ") else ""
        step = self.headers.get("X-Step", parts[3])
        client = self.headers.get("User-Agent", "unknown")
        code, msg = world.authorize(value, NEEDS[parts[3]], step, f"{parts[1]}/{parts[2]}", client)
        return self._send(code, msg)

    def _send(self, code: int, message: str):
        body = json.dumps({"message": message}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the console quiet
        return


def ensure_service() -> str:
    """Start the service once per process and return its base URL."""
    with _LOCK:
        if _SERVER["url"]:
            return _SERVER["url"]
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, name="mock-git", daemon=True)
        thread.start()
        _SERVER["server"] = server
        _SERVER["url"] = f"http://127.0.0.1:{server.server_address[1]}"
        return _SERVER["url"]
