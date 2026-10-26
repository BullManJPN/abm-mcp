"""テスト用の Apple 模擬サーバー。

トークンエンドポイントでは本物と同様に client assertion（ES256）の署名・クレームを検証する。
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import jwt

AUDIENCE = "https://account.apple.com/auth/oauth2/v2/token"
CLIENT_ID = "BUSINESSAPI.test-client"
KEY_ID = "test-key-id"


class FakeApple:
    def __init__(self, public_key_pem: bytes):
        self.public_key = public_key_pem
        self.reset()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # 静かにする
                pass

            def _send(self, status, body=None):
                raw = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def do_GET(self):
                outer.handle(self, "GET")

            def do_POST(self):
                outer.handle(self, "POST")

            def do_PATCH(self):
                outer.handle(self, "PATCH")

            def do_DELETE(self):
                outer.handle(self, "DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def reset(self):
        self.token_requests = []   # (style, has_kid)
        self.issued = []
        self.valid = set()
        self.api_log = []          # (method, path, body)
        self.reject_kid = False
        self.accept_style = "both"  # query / body / both
        self.fail_next = {}         # (method) -> [status,...]
        self.devices = [f"SERIAL{i:03d}" for i in range(7)]

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    # ------------------------------------------------------------------
    def handle(self, h, method):
        parsed = urlparse(h.path)
        raw = h._body()
        if parsed.path == "/auth/oauth2/token":
            return self.handle_token(h, parsed, raw)

        auth = h.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.valid:
            return h._send(401, {"errors": [{"status": "401", "code": "NOT_AUTHORIZED", "title": "Unauthorized"}]})

        body = json.loads(raw) if raw else None
        self.api_log.append((method, parsed.path, body))

        queue = self.fail_next.get(method)
        if queue:
            return h._send(queue.pop(0), {"errors": [{"status": "503", "code": "UNAVAILABLE", "title": "busy"}]})

        q = parse_qs(parsed.query)
        p = parsed.path

        if method == "GET" and p == "/v1/orgDevices":
            limit = int(q.get("limit", ["100"])[0])
            start = int(q["cursor"][0][1:]) if "cursor" in q else 0
            chunk = self.devices[start:start + limit]
            nxt = start + limit
            out = {"data": [{"type": "orgDevices", "id": d} for d in chunk],
                   "links": {"self": self.base + p}, "meta": {"paging": {"limit": limit}}}
            if nxt < len(self.devices):
                out["meta"]["paging"]["nextCursor"] = f"c{nxt}"
                out["links"]["next"] = f"https://evil.example/v1/orgDevices?cursor=c{nxt}"
            return h._send(200, out)
        if method == "GET" and p.startswith("/v1/orgDevices/"):
            tail = p[len("/v1/orgDevices/"):]
            if tail.endswith("/assignedServer"):
                return h._send(404, {"errors": [{"status": "404", "code": "NOT_FOUND", "title": "none"}]})
            if tail in self.devices:
                return h._send(200, {"data": {"type": "orgDevices", "id": tail}})
            return h._send(404, {"errors": [{"status": "404", "code": "NOT_FOUND", "title": "Not found",
                                             "detail": f"device {tail}"}]})
        if method == "GET" and p == "/v1/mdmServers":
            return h._send(200, {"data": [{"type": "mdmServers", "id": "SRV1"}]})
        if method == "POST" and p == "/v1/orgDeviceActivities":
            return h._send(201, {"data": {"type": "orgDeviceActivities", "id": "act-1",
                                          "attributes": {"status": "IN_PROGRESS"}}})
        if p.startswith("/v1/blueprints") and method in ("POST", "DELETE") and "/relationships/" in p:
            return h._send(204)
        if method == "POST" and p == "/v1/blueprints":
            return h._send(201, {"data": {"type": "blueprints", "id": "bp-1"}})
        if method == "DELETE" and p.startswith("/v1/blueprints/"):
            return h._send(204)
        return h._send(404, {"errors": [{"status": "404", "code": "NOT_FOUND", "title": "unknown path " + p}]})

    def handle_token(self, h, parsed, raw):
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        b = {k: v[0] for k, v in parse_qs(raw.decode()).items()} if raw else {}
        style = "query" if q.get("client_assertion") else "body"
        params = q or b
        if self.accept_style != "both" and style != self.accept_style:
            return h._send(400, {"error": "invalid_request"})
        try:
            header = jwt.get_unverified_header(params["client_assertion"])
            has_kid = "kid" in header
            self.token_requests.append((style, has_kid))
            if has_kid and self.reject_kid:
                return h._send(401, {"error": "invalid_client"})
            claims = jwt.decode(params["client_assertion"], self.public_key, algorithms=["ES256"], audience=AUDIENCE)
            assert header["alg"] == "ES256"
            assert claims["sub"] == CLIENT_ID and claims["iss"] == CLIENT_ID
            assert claims["exp"] > claims["iat"] and claims["jti"]
            assert params["grant_type"] == "client_credentials"
            assert params["client_id"] == CLIENT_ID
            assert params["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            assert params["scope"] == "business.api"
        except Exception as exc:  # noqa: BLE001
            return h._send(401, {"error": "invalid_client", "detail": str(exc)[:80]})
        token = f"tok-{len(self.issued) + 1}"
        self.issued.append(token)
        self.valid.add(token)
        return h._send(200, {"access_token": token, "token_type": "Bearer", "expires_in": 3600,
                             "scope": "business.api"})
