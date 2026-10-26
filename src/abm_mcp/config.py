"""環境変数からの設定読み込み。

秘密鍵そのものは環境変数に入れず、ファイルパスだけを渡す。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    """設定が足りない・不正なときのエラー。"""


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} は整数で指定してください: {raw!r}") from exc


@dataclass(frozen=True)
class Config:
    client_id: str
    key_id: str
    private_key_path: Path
    # --- 接続先（Apple 公式ドキュメントの値が既定） ---
    scope: str = "business.api"
    api_base: str = "https://api-business.apple.com"
    token_url: str = "https://account.apple.com/auth/oauth2/token"
    audience: str = "https://account.apple.com/auth/oauth2/v2/token"
    # JWT ヘッダーに kid を入れるか、トークン要求パラメータをどこに載せるか。
    # 公式サンプルと実運用で差があり得るため、失敗時は自動で他の組み合わせを試す。
    include_kid: bool = True
    token_params_in: str = "query"  # "query" or "body"
    # --- 安全装置 ---
    enable_write: bool = False
    enable_destructive: bool = False
    max_devices_per_op: int = 25
    confirm_ttl: int = 600
    # --- ファイル ---
    home_dir: Path = Path.home() / ".abm-mcp"
    audit_log: Path = Path.home() / ".abm-mcp" / "audit.jsonl"
    files_dir: Path = Path.home() / ".abm-mcp" / "files"
    # --- 通信 ---
    timeout: float = 30.0
    max_retries: int = 3
    backoff_base: float = 1.0

    @classmethod
    def from_env(cls) -> "Config":
        required = ("ABM_CLIENT_ID", "ABM_KEY_ID", "ABM_PRIVATE_KEY_PATH")
        missing = [n for n in required if not os.environ.get(n, "").strip()]
        if missing:
            raise ConfigError(
                "必須の環境変数が未設定です: " + ", ".join(missing)
                + "（Apple Business の「設定 > API」で確認できる値を指定してください）"
            )

        key_path = Path(os.environ["ABM_PRIVATE_KEY_PATH"]).expanduser()
        if not key_path.is_file():
            raise ConfigError(f"秘密鍵ファイルが見つかりません: {key_path}")

        style = os.environ.get("ABM_TOKEN_PARAMS_IN", "query").strip().lower()
        if style not in {"query", "body"}:
            raise ConfigError("ABM_TOKEN_PARAMS_IN は query か body を指定してください")

        api_base = os.environ.get("ABM_API_BASE", cls.api_base).rstrip("/")
        token_url = os.environ.get("ABM_TOKEN_URL", cls.token_url)
        if not _flag("ABM_ALLOW_INSECURE"):
            for label, url in (("ABM_API_BASE", api_base), ("ABM_TOKEN_URL", token_url)):
                if not url.startswith("https://"):
                    raise ConfigError(f"{label} は https:// で始めてください: {url}")

        home = Path(os.environ.get("ABM_HOME", "~/.abm-mcp")).expanduser()
        return cls(
            client_id=os.environ["ABM_CLIENT_ID"].strip(),
            key_id=os.environ["ABM_KEY_ID"].strip(),
            private_key_path=key_path,
            scope=os.environ.get("ABM_SCOPE", cls.scope),
            api_base=api_base,
            token_url=token_url,
            audience=os.environ.get("ABM_AUDIENCE", cls.audience),
            include_kid=_flag("ABM_INCLUDE_KID", True),
            token_params_in=style,
            enable_write=_flag("ABM_ENABLE_WRITE"),
            enable_destructive=_flag("ABM_ENABLE_DESTRUCTIVE"),
            max_devices_per_op=max(1, _int("ABM_MAX_DEVICES_PER_OP", 25)),
            confirm_ttl=max(30, _int("ABM_CONFIRM_TTL", 600)),
            home_dir=home,
            audit_log=Path(os.environ.get("ABM_AUDIT_LOG", str(home / "audit.jsonl"))).expanduser(),
            files_dir=Path(os.environ.get("ABM_FILES_DIR", str(home / "files"))).expanduser(),
            timeout=float(_int("ABM_TIMEOUT", 30)),
        )
