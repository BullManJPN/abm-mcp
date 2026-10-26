"""変更系操作の安全装置。

- ABM_ENABLE_WRITE / ABM_ENABLE_DESTRUCTIVE のフラグで操作の階層を制御
- 変更は「プレビュー → 確認トークン付きで再実行」の 2 段階
  （トークンは引数の内容に紐づく・1 回限り・有効期限あり）
- すべての操作を JSON Lines の監査ログに記録（トークンや本文は記録しない）
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from .config import Config


class GateError(Exception):
    """安全装置により操作が拒否された。"""


def _shorten(obj: Any, limit: int = 400) -> Any:
    """プレビュー表示用に長い文字列を切り詰める。"""
    if isinstance(obj, str):
        return obj if len(obj) <= limit else obj[:limit] + f"...(+{len(obj) - limit}文字)"
    if isinstance(obj, list):
        return [_shorten(x, limit) for x in obj]
    if isinstance(obj, dict):
        return {k: _shorten(v, limit) for k, v in obj.items()}
    return obj


class Gate:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._pending: dict[str, tuple[str, float]] = {}

    # ---- フラグ ----
    def require(self, destructive: bool) -> None:
        if not self.cfg.enable_write:
            raise GateError("変更系の操作は無効です。環境変数 ABM_ENABLE_WRITE=1 を設定して再起動してください。")
        if destructive and not self.cfg.enable_destructive:
            raise GateError(
                "破壊的な操作は無効です。環境変数 ABM_ENABLE_DESTRUCTIVE=1 を設定して再起動してください。"
            )

    # ---- 確認トークン ----
    @staticmethod
    def _digest(action: str, payload: Any) -> str:
        raw = json.dumps({"a": action, "p": payload}, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _issue(self, digest: str) -> str:
        token = secrets.token_urlsafe(12)
        with self._lock:
            now = time.time()
            self._pending = {t: v for t, v in self._pending.items() if v[1] > now}
            self._pending[token] = (digest, now + self.cfg.confirm_ttl)
        return token

    def _consume(self, digest: str, token: str) -> bool:
        with self._lock:
            entry = self._pending.pop(token, None)
        return bool(entry and entry[0] == digest and entry[1] > time.time())

    # ---- 監査ログ ----
    def audit(self, event: dict[str, Any]) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(), **event}
        path = self.cfg.audit_log
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    # ---- 実行 ----
    def run_write(
        self,
        *,
        action: str,
        payload: Any,
        summary: str,
        confirm_token: str | None,
        destructive: bool,
        execute: Callable[[], Any],
    ) -> dict[str, Any]:
        self.require(destructive)
        digest = self._digest(action, payload)
        tier = "destructive" if destructive else "write"

        if not confirm_token:
            token = self._issue(digest)
            self.audit({"event": "preview", "tier": tier, "action": action,
                        "digest": digest[:16], "summary": summary})
            return {
                "status": "preview",
                "action": action,
                "tier": tier,
                "summary": summary,
                "will_send": _shorten(payload),
                "confirm_token": token,
                "expires_in_seconds": self.cfg.confirm_ttl,
                "next_step": (
                    "内容をユーザーに見せて承認を得てください。承認されたら、同じ引数に "
                    "confirm_token を付けて再実行します。引数を変えるとトークンは無効になります。"
                ),
            }

        if not self._consume(digest, confirm_token):
            raise GateError(
                "確認トークンが無効です（期限切れ・使用済み・引数の変更のいずれか）。"
                "confirm_token を付けずに呼び直して、新しいプレビューを取得してください。"
            )

        self.audit({"event": "execute", "tier": tier, "action": action,
                    "digest": digest[:16], "summary": summary})
        try:
            result = execute()
        except Exception as exc:  # noqa: BLE001 - 失敗も記録してから再送出
            self.audit({"event": "failed", "action": action, "digest": digest[:16],
                        "error": str(exc)[:300]})
            raise
        self.audit({"event": "done", "action": action, "digest": digest[:16]})
        return {"status": "executed", "action": action, "tier": tier,
                "summary": summary, "result": result}
