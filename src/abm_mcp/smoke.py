"""接続確認用スクリプト: python -m abm_mcp.smoke

MCP サーバーを動かす前に、鍵・ID・権限が正しいかを段階ごとに確認する。
トークンや秘密鍵の内容は表示しない。
"""
import sys

from .auth import ABMAuthError, TokenProvider
from .client import ABMClient, ABMError
from .config import Config, ConfigError


def _hint_for_auth(exc: ABMAuthError) -> str:
    text = str(exc).lower()
    if "invalid_client" in text:
        return ("invalid_client: クライアント ID・キー ID・秘密鍵の組み合わせを確認してください。"
                "鍵を再生成した場合は新しい鍵ファイルを指定してください。")
    if exc.status == 400:
        return "400: パラメータの形式を確認してください（ABM_SCOPE、ABM_AUDIENCE など）。"
    return "ネットワークや時刻のずれ（Mac の自動時刻設定）も確認してください。"


def main() -> int:
    print("== Apple Business API 接続確認 ==")
    try:
        cfg = Config.from_env()
    except ConfigError as exc:
        print(f"[NG] 設定: {exc}")
        return 2
    print(f"[OK] 設定を読み込みました（API: {cfg.api_base}）")

    tokens = TokenProvider(cfg)
    try:
        assertion = tokens.build_assertion()
    except Exception as exc:  # noqa: BLE001
        print(f"[NG] client assertion の作成に失敗: {exc.__class__.__name__}: {exc}")
        print("     秘密鍵が ES256（P-256）の PEM か確認してください。")
        return 2
    print(f"[OK] client assertion を作成しました（{len(assertion)} 文字）")

    try:
        tokens.get_token()
    except ABMAuthError as exc:
        print(f"[NG] トークン取得: {exc}")
        print(f"     ヒント: {_hint_for_auth(exc)}")
        return 1
    print(f"[OK] アクセストークンを取得しました（有効期間 約 {tokens.expires_in // 60} 分）")

    client = ABMClient(cfg, tokens)
    checks = [
        ("デバイス管理サービス", "/v1/mdmServers"),
        ("デバイス", "/v1/orgDevices"),
    ]
    failed = False
    for label, path in checks:
        try:
            body = client.request("GET", path, params={"limit": 1}) or {}
            print(f"[OK] {label} ({path}): 取得できました（1 ページ目 {len(body.get('data') or [])} 件）")
        except ABMError as exc:
            failed = True
            print(f"[NG] {label} ({path}): {exc}")
            if exc.status == 403:
                print("     ヒント: API アカウントの役割に該当する権限があるか確認してください。")

    print()
    print(f"変更系: {'有効' if cfg.enable_write else '無効'} / 破壊的: "
          f"{'有効' if cfg.enable_write and cfg.enable_destructive else '無効'} / "
          f"1 回あたりの最大デバイス数: {cfg.max_devices_per_op}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
