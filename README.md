# abm-mcp — Operate Apple Business from Claude through a gated MCP server

> **English summary** (Japanese documentation follows below)

A Python [MCP](https://modelcontextprotocol.io) server that lets Claude work with the Apple Business API
(OAuth 2 with an ES256 client assertion): devices, device management services, users, groups, apps,
blueprints, configurations and audit events.

**Design goals: safe by default, auditable, honest about what is verified.**

- **Read-only by default.** Write tools are registered only with `ABM_ENABLE_WRITE=1`; destructive tools
  (release devices, delete blueprint/configuration/MDM server) additionally need `ABM_ENABLE_DESTRUCTIVE=1`.
  Tools that are disabled are not registered at all, so Claude cannot see them.
- **Two-step execution for every change.** The first call returns a preview and sends nothing. The change runs
  only with a one-time, expiring confirmation token bound to the exact arguments, and the client's own
  approval dialog still applies.
- **Guardrails:** per-operation device cap, ID format checks, requests limited to the API host and `/v1/` paths,
  file reads (certificates, profiles) limited to one directory.
- **Local audit log** (JSON Lines, mode 600) of every preview, execution, success and failure. Tokens and request
  bodies are not logged.
- **Secrets stay out of the code:** the private key is passed by file path only.
- **Verification status is documented:** endpoints are marked as verified against Apple's documentation,
  inferred from third-party clients, or unverified. 29 automated tests run against a mock Apple server.

**Status and limits.** Built and verified against a live Apple Business organization (my own, personally
contracted) — the real API, not only mocks. Live-verified so far: 8 read tools (device management services,
devices, blueprints, user groups, organizational units, packages, Activation Lock status, MDM-enrolled devices)
and one write tool (`create_blueprint`, through the preview/confirm flow); see the endpoint-confidence section (エンドポイントの確度) below.
Not tested at scale: rate limits and batch-size limits are unverified, destructive tools have not been run
live, and it has not been used by multiple administrators. Human approval cannot be distinguished from a click
on the client's approval dialog. For production
use I would add least-privilege API roles, centralized and searchable audit logs with approver identity, and
enterprise secret management.

**Disclosure.** This project was designed by me (requirements and safety model) and built with Claude Code. It is
an independent personal project and is not affiliated with, endorsed by, or supported by Apple Inc. or Anthropic.
"Apple" and "Apple Business" are trademarks of Apple Inc.

**License:** MIT (see `LICENSE`). Provided as is, without warranty. This tool can change and delete data in an
Apple Business organization when its write and destructive modes are enabled; use it on a dedicated test
organization first.

---

# 日本語ドキュメント

> 実際の Apple Business（個人契約）に対して構築・動作検証した個人プロジェクトです。大規模運用（レート制限、1 回の操作の上限台数、複数管理者での利用）は未検証です。Apple Inc. とは無関係です。Claude Code を使って開発しました。

Apple Business の API（OAuth 2 + ES256 の client assertion）を MCP ツールとして公開します。
デバイス・デバイス管理サービス・ユーザー・グループ・アプリ・ブループリント・構成・監査イベントの参照と、
割り当て変更・ブループリント/構成の作成更新・削除などの変更ができます。

> **重要**: 変更系・破壊的な操作は、必ず「プレビュー → 承認 → 実行」の 2 段階で動きます。
> 個人の検証用組織で、できること／できないことを試す用途を想定しています。

## 1. セットアップ（Mac）

**Python 3.10 以上が必要です。** macOS 標準の `python3`（3.9）では動きません。
`brew install python` か [uv](https://docs.astral.sh/uv/) で用意してください。

```bash
cd abm-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Apple Business 側の準備

1. 組織管理者でサインイン →「設定」＞「API」＞「APIアカウントを追加する」
2. 名前と**役割**を選びます。使いたい機能に対応する権限を持つ役割にしてください
   （デバイス、デバイス管理サービス、ユーザー、ユーザーグループ、組織のユニット、ブループリント、構成、パッケージ、アプリ、監査イベント）。
3. 「生成してダウンロード」で秘密鍵（.pem）を保存します。**鍵は一度しか生成されません。**
4. アカウントの「編集」画面で **クライアントID**（`BUSINESSAPI.…`）と **キーID** を控えます。

秘密鍵は専用の場所に置き、権限を絞ります（チャットや Git には絶対に載せないでください）。

```bash
mkdir -p ~/.abm-mcp/files && chmod 700 ~/.abm-mcp
mv ~/Downloads/<ダウンロードした鍵>.pem ~/.abm-mcp/abm-key.pem
chmod 600 ~/.abm-mcp/abm-key.pem
```

### 接続確認（Claude に繋ぐ前に）

```bash
export ABM_CLIENT_ID="BUSINESSAPI.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export ABM_KEY_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export ABM_PRIVATE_KEY_PATH="$HOME/.abm-mcp/abm-key.pem"
python -m abm_mcp.smoke
```

鍵の読み込み → トークン取得 → API 呼び出しを段階ごとに `[OK]/[NG]` で表示します（トークンは表示しません）。

## 2. Claude に登録する

### Claude デスクトップアプリ
`~/Library/Application Support/Claude/claude_desktop_config.json` に追加して、アプリを再起動します。

```json
{
  "mcpServers": {
    "apple-business": {
      "command": "/Users/<あなた>/abm-mcp/.venv/bin/python",
      "args": ["-m", "abm_mcp"],
      "env": {
        "ABM_CLIENT_ID": "BUSINESSAPI.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "ABM_KEY_ID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "ABM_PRIVATE_KEY_PATH": "/Users/<あなた>/.abm-mcp/abm-key.pem"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add apple-business \
  -e ABM_CLIENT_ID=BUSINESSAPI.xxxx -e ABM_KEY_ID=xxxx \
  -e ABM_PRIVATE_KEY_PATH=$HOME/.abm-mcp/abm-key.pem \
  -- /Users/<あなた>/abm-mcp/.venv/bin/python -m abm_mcp
```

上の設定例は**読み取り専用**です（既定）。変更系ツールは `ABM_ENABLE_WRITE=1`、破壊的ツールはさらに `ABM_ENABLE_DESTRUCTIVE=1` を追加したときだけ登録されます。影響を理解し、専用の検証用組織で試してから有効にしてください。

## 3. 環境変数

| 変数 | 既定 | 説明 |
|---|---|---|
| `ABM_CLIENT_ID` / `ABM_KEY_ID` / `ABM_PRIVATE_KEY_PATH` | （必須） | 認証情報。鍵は**パスだけ**渡す |
| `ABM_ENABLE_WRITE` | 無効 | 変更系ツールを登録する |
| `ABM_ENABLE_DESTRUCTIVE` | 無効 | 破壊的ツールを登録する（`ABM_ENABLE_WRITE` も必要） |
| `ABM_MAX_DEVICES_PER_OP` | 25 | 1 回の操作で扱えるデバイス数の上限 |
| `ABM_CONFIRM_TTL` | 600 | 確認トークンの有効秒数 |
| `ABM_HOME` | `~/.abm-mcp` | 監査ログ・ファイル置き場の親 |
| `ABM_AUDIT_LOG` | `$ABM_HOME/audit.jsonl` | 監査ログ（JSON Lines、権限 600） |
| `ABM_FILES_DIR` | `$ABM_HOME/files` | 証明書・構成プロファイルの読み込み元（**この中だけ**読める） |
| `ABM_SCOPE` | `business.api` | OAuth のスコープ |
| `ABM_INCLUDE_KID` / `ABM_TOKEN_PARAMS_IN` | `1` / `query` | トークン取得方式（失敗時は他の組み合わせを自動で試し、成功した方式を記憶） |
| `ABM_API_BASE` / `ABM_TOKEN_URL` / `ABM_AUDIENCE` | Apple 公式の値 | 通常は変更不要 |

## 4. ツール

**参照（常に有効）** — `check_connection`, `list_devices`, `get_device`, `get_device_applecare`,
`get_device_activation_lock`, `get_device_assigned_server(_id)`, `list_mdm_enrolled_devices`,
`get_mdm_enrolled_device_details`, `list_mdm_servers`, `get_mdm_server`, `list_mdm_server_devices`,
`get_activity`, `list_users`, `get_user`, `list_user_groups`, `get_user_group`, `list_user_group_members`,
`list_organizational_units`, `get_organizational_unit`, `list_organizational_unit_members`,
`list_apps`, `get_app`, `list_packages`, `get_package`, `list_blueprints`, `get_blueprint`,
`get_blueprint_members`, `list_configurations`, `get_configuration`, `list_audit_events`, `api_get`（任意の GET）

**変更（`ABM_ENABLE_WRITE=1`）** — `assign_devices_to_mdm`, `unassign_devices_from_mdm`,
`schedule_mdm_migration`, `update_mdm_migration_deadline`, `cancel_mdm_migration`,
`create_blueprint`, `update_blueprint`, `add_to_blueprint`, `remove_from_blueprint`,
`create_custom_configuration`, `update_custom_configuration`, `create_mdm_server`, `update_mdm_server`

**破壊的（`ABM_ENABLE_DESTRUCTIVE=1` も必要）** — `release_devices`, `delete_blueprint`,
`delete_configuration`, `delete_mdm_server`

### エンドポイントの確度
- **実環境で動作確認済み（個人契約の Apple Business）**
  - 参照: `list_mdm_servers`、`list_devices`、`list_blueprints`、`list_user_groups`、`list_organizational_units`、`list_packages`、`get_device_activation_lock`、`list_mdm_enrolled_devices`
  - 変更: `create_blueprint`（プレビュー → 確認トークン → 実行の流れで確認）
  - これに伴い、以前は「第三者クライアントの記載から推定」としていた `activationLockStatus`、`mdmDevices`、`organizationalUnits`、`userGroups`、`packages` は、実環境で確認できました。
- **Apple 公式ドキュメントで確認済み（実環境では未実行）**: orgDeviceActivities（割り当て・解除・移行・解放）、apps、users、auditEvents、configurations、blueprints の relationships（追加）、OAuth 全般
- **推定**: ブループリント関係の **DELETE**（本文は追加と同形式と仮定）。404/400 が出たら `api_get` で実際の応答を確認し、`src/abm_mcp/tools.py` のパスを直してください。
- **未確認**: レート制限、1 回の割り当て操作の上限台数、`update_blueprint` に `members` を渡した時の挙動（追加か置換か）、監査イベントのフィルターのうち `startTimestamp` / `endTimestamp` 以外。破壊的ツールは実環境で実行していません。

「できること／できないこと」を調べる目的なので、これらの結果は Apple の仕様確認として役に立ちます。

## 5. 安全設計

- **2 段階実行**: 変更系は `confirm_token` なしで呼ぶとプレビューだけ返し、何も送信しません。
  トークンは「その引数の内容」に紐づき、1 回限り・期限付きです。引数を変えると無効になります。
- **フラグで階層化**: フラグが無効なツールは**そもそも登録されません**（Claude から見えません）。
- **デバイス数の上限**、ID の形式チェック（パス注入対策）、`/v1/` 配下以外・API ホスト以外には送信しません。
- **ファイル読み込みの制限**: 証明書・構成プロファイルは `ABM_FILES_DIR` の中だけ。
  悪意あるプロンプトで任意のファイルを Apple に送らせることはできません。
- **監査ログ**: preview / execute / done / failed を記録（トークン・本文は記録しない）。
- **再試行**: 401 はトークン再取得、429 は全メソッド、5xx は GET のみ（POST の二重実行を避ける）。
- MCP のツール注釈（読み取り専用／破壊的）が付くので、Claude 側の承認ダイアログも併用されます。

> 承認は**あなたが内容を確認して**与えてください。`release_devices` は組織への登録と自動登録の割り当てが外れ、
> ブループリントからも除外されます。元に戻すには再登録が必要です。

## 6. トラブルシューティング

| 症状 | 対処 |
|---|---|
| `invalid_client` | クライアント ID・キー ID・鍵の組み合わせを確認。鍵を再生成したなら新しい鍵を指定。サーバーは kid あり/なし、パラメータ位置の違いを自動で試します |
| `403` | API アカウントの役割にその機能の権限がない。役割を編集 |
| アプリ・パッケージ系が失敗 | 組み込みデバイス管理が有効な組織のみ対応 |
| 起動しない（`設定エラー`） | 必須の環境変数、鍵ファイルのパスを確認 |
| 鍵の権限の警告 | `chmod 600` |

## 7. 開発・テスト

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Apple を模したサーバー（ES256 署名とクレームを実際に検証）に対して、認証・再試行・ページング・安全装置・
stdio での MCP 通信まで 29 件を確認します。**実際の Apple Business 組織に対する動作確認は、
`python -m abm_mcp.smoke` で行ってください。**
