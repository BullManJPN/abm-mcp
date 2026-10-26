"""OAuth 2 (client credentials + JWT client assertion) のトークン管理。

Apple のドキュメントに沿って ES256 で署名した client assertion を作り、
アクセストークン（有効 1 時間）を取得・キャッシュする。
標準出力は MCP のプロトコルに使われるため、ログは必ず標準エラーに出す。
"""
from __future__ import annotations

import stat
import sys
import threading
import time
import uuid

import jwt
import requests

from .config import Config


class ABMAuthError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def log(msg: str) -> None:
    print(f"[abm-mcp] {msg}", file=sys.stderr, flush=True)


class TokenProvider:
    ASSERTION_TTL = 3600  # 毎回作り直すので短くてよい（上限は発行から 180 日未満）
    REFRESH_MARGIN = 60

    def __init__(self, cfg: Config, session: requests.Session | None = None):
        self._cfg = cfg
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires_at = 0.0
        self._variant: tuple[bool, str] | None = None  # うまくいった組み合わせを記憶
        self._key: bytes | None = None

    # ---- client assertion ----
    def _load_key(self) -> bytes:
        if self._key is None:
            path = self._cfg.private_key_path
            if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                log(f"警告: 秘密鍵 {path} の権限が緩すぎます。chmod 600 を推奨します。")
            self._key = path.read_bytes()
        return self._key

    def build_assertion(self, include_kid: bool | None = None) -> str:
        include_kid = self._cfg.include_kid if include_kid is None else include_kid
        now = int(time.time())
        payload = {
            "iss": self._cfg.client_id,
            "sub": self._cfg.client_id,
            "aud": self._cfg.audience,
            "iat": now,
            "exp": now + self.ASSERTION_TTL,
            "jti": str(uuid.uuid4()),
        }
        headers = {"kid": self._cfg.key_id} if include_kid else {}
        return jwt.encode(payload, self._load_key(), algorithm="ES256", headers=headers)

    # ---- token ----
    def _variants(self) -> list[tuple[bool, str]]:
        first = (self._cfg.include_kid, self._cfg.token_params_in)
        everything = [(k, s) for k in (True, False) for s in ("query", "body")]
        return [first] + [v for v in everything if v != first]

    def _request_token(self, variant: tuple[bool, str]) -> dict:
        include_kid, style = variant
        params = {
            "grant_type": "client_credentials",
            "client_id": self._cfg.client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.build_assertion(include_kid),
            "scope": self._cfg.scope,
        }
        try:
            if style == "query":
                resp = self._session.post(
                    self._cfg.token_url,
                    params=params,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=self._cfg.timeout,
                )
            else:
                resp = self._session.post(
                    self._cfg.token_url, data=params, timeout=self._cfg.timeout
                )
        except requests.RequestException as exc:
            raise ABMAuthError(f"トークンエンドポイントに接続できません: {exc.__class__.__name__}") from exc

        if resp.status_code != 200:
            raise ABMAuthError(
                f"トークン取得に失敗しました (HTTP {resp.status_code}): {resp.text[:300]}",
                status=resp.status_code,
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise ABMAuthError("トークン応答が JSON ではありません") from exc
        if not data.get("access_token"):
            raise ABMAuthError("トークン応答に access_token がありません")
        return data

    def get_token(self, force: bool = False) -> str:
        with self._lock:
            if not force and self._token and time.time() < self._expires_at - self.REFRESH_MARGIN:
                return self._token

            candidates = [self._variant] if self._variant else self._variants()
            last: ABMAuthError | None = None
            for variant in candidates:
                try:
                    data = self._request_token(variant)
                except ABMAuthError as exc:
                    last = exc
                    # 初回の方式探索中だけ、400/401 なら別の組み合わせを試す
                    if self._variant is None and exc.status in (400, 401):
                        continue
                    raise
                self._token = data["access_token"]
                self._expires_at = time.time() + float(data.get("expires_in", 3600))
                if self._variant is None and variant != candidates[0]:
                    log(f"トークン取得方式を切り替えました: kid={variant[0]}, params={variant[1]}")
                self._variant = variant
                return self._token
            assert last is not None
            raise last

    def invalidate(self) -> None:
        with self._lock:
            self._token = None
            self._expires_at = 0.0

    @property
    def expires_in(self) -> int:
        return max(0, int(self._expires_at - time.time()))
