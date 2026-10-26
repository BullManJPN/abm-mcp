"""MCP サーバーのエントリーポイント（stdio）。

標準出力は MCP のプロトコルが使うため、ログは標準エラーにだけ出す。
"""
import sys

from .auth import log
from .config import Config, ConfigError
from .tools import build_server


def main() -> None:
    try:
        cfg = Config.from_env()
    except ConfigError as exc:
        print(f"[abm-mcp] 設定エラー: {exc}", file=sys.stderr)
        sys.exit(2)

    tiers = ["参照"]
    if cfg.enable_write:
        tiers.append("変更")
    if cfg.enable_destructive and cfg.enable_write:
        tiers.append("破壊的")
    log(f"起動します（有効な操作: {' / '.join(tiers)}、API: {cfg.api_base}）")
    build_server(cfg).run("stdio")


if __name__ == "__main__":
    main()
