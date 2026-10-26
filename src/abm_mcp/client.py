"""Apple Business API の HTTP クライアント。

- アクセストークンは設定した API ホスト以外には絶対に送らない
- 401 はトークンを取り直して 1 回だけ再試行
- 429 は全メソッドで、5xx は GET のみ再試行（POST の二重実行を避ける）
- 一覧はカーソル方式のページングで取得
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import requests

from .auth import TokenProvider
from .config import Config


class ABMError(Exception):
    def __init__(self, status: int, message: str, errors: list[dict] | None = None):
        super().__init__(message)
        self.status = status
        self.errors = errors or []

    def __str__(self) -> str:
        return f"HTTP {self.status}: {self.args[0]}"


def _error_message(resp: requests.Response) -> tuple[str, list[dict]]:
    try:
        body = resp.json()
    except ValueError:
        return (resp.text[:300] or resp.reason or "エラー"), []
    errors = body.get("errors") if isinstance(body, dict) else None
    if errors and isinstance(errors, list):
        parts = []
        for err in errors[:3]:
            if isinstance(err, dict):
                bits = [str(err.get(k)) for k in ("code", "title", "detail") if err.get(k)]
                parts.append(" / ".join(bits) or str(err))
        return "; ".join(parts) or resp.reason or "エラー", errors
    return (str(body)[:300]), []


class ABMClient:
    PAGE_MAX = 100

    def __init__(
        self,
        cfg: Config,
        tokens: TokenProvider | None = None,
        session: requests.Session | None = None,
    ):
        self.cfg = cfg
        self.session = session or requests.Session()
        self.tokens = tokens or TokenProvider(cfg, self.session)
        self._base = urlparse(cfg.api_base)

    # ---- URL 検証 ----
    def _url(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            if (parsed.scheme, parsed.netloc) != (self._base.scheme, self._base.netloc):
                raise ABMError(0, "設定された API ホスト以外には送信しません")
            return target
        if not target.startswith("/v1/") or "?" in target or "#" in target:
            raise ABMError(0, f"パスは /v1/ で始め、クエリは params で渡してください: {target!r}")
        if ".." in target.split("/"):
            raise ABMError(0, "パスに .. は使えません")
        return self.cfg.api_base + target

    def _backoff(self, resp: requests.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), 60.0)
            except ValueError:
                pass
        return min(self.cfg.backoff_base * (2 ** attempt), 30.0)

    # ---- 基本リクエスト ----
    def request(
        self,
        method: str,
        target: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
    ) -> Any:
        method = method.upper()
        url = self._url(target)
        refreshed = False
        attempt = 0
        while True:
            token = self.tokens.get_token()
            try:
                resp = self.session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    timeout=self.cfg.timeout,
                )
            except requests.RequestException as exc:
                raise ABMError(0, f"API に接続できません: {exc.__class__.__name__}") from exc

            if resp.status_code == 401 and not refreshed:
                self.tokens.invalidate()
                refreshed = True
                continue

            retriable = resp.status_code == 429 or (
                method == "GET" and resp.status_code in (500, 502, 503, 504)
            )
            if retriable and attempt < self.cfg.max_retries:
                time.sleep(self._backoff(resp, attempt))
                attempt += 1
                continue

            return self._handle(resp)

    @staticmethod
    def _handle(resp: requests.Response) -> Any:
        if resp.status_code >= 400:
            message, errors = _error_message(resp)
            raise ABMError(resp.status_code, message, errors)
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise ABMError(resp.status_code, "応答が JSON ではありません") from exc

    # ---- ページング ----
    @staticmethod
    def _next_cursor(body: dict) -> str | None:
        cursor = ((body.get("meta") or {}).get("paging") or {}).get("nextCursor")
        if cursor:
            return cursor
        nxt = (body.get("links") or {}).get("next")
        if nxt:
            from urllib.parse import parse_qs

            values = parse_qs(urlparse(nxt).query).get("cursor")
            if values:
                return values[0]
        return None

    def list_resources(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        max_items: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """max_items 件以上になるまでページを辿る。取りこぼしを避けるため切り詰めはしない。"""
        base = dict(params or {})
        items: list[Any] = []
        next_cursor = cursor
        first = True
        while first or (next_cursor and len(items) < max_items):
            q = dict(base)
            q["limit"] = max(1, min(self.PAGE_MAX, max_items - len(items)))
            if next_cursor:
                q["cursor"] = next_cursor
            body = self.request("GET", path, params=q) or {}
            items.extend(body.get("data") or [])
            next_cursor = self._next_cursor(body)
            first = False
        return {"count": len(items), "items": items, "next_cursor": next_cursor}
