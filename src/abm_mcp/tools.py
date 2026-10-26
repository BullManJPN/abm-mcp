"""MCP ツール定義。

Toolbox の各メソッドが 1 つのツールに対応する。
  参照系       : 常に有効
  変更系       : ABM_ENABLE_WRITE=1 のときだけ登録
  破壊的な操作 : ABM_ENABLE_WRITE=1 かつ ABM_ENABLE_DESTRUCTIVE=1 のときだけ登録

変更系は confirm_token なしで呼ぶとプレビューだけ返し、何も送信しない。

エンドポイントの確度:
  Apple 公式ドキュメントで確認済み … orgDevices, mdmServers, orgDeviceActivities, apps, users,
      auditEvents, blueprints(+relationships), configurations
  第三者クライアントの記載から推定 … activationLockStatus, mdmDevices, organizationalUnits,
      userGroups, packages, ブループリント関係の DELETE（本文は POST と同形式と仮定）
  推定のものは 404/400 になる可能性があります。その場合は api_get で実際の応答を確認してください。
"""
import base64
import functools
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .auth import ABMAuthError
from .client import ABMClient, ABMError
from .config import Config
from .safety import Gate, GateError

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

# ブループリントの関係名（URL のパスと JSON:API の type を兼ねる）
BLUEPRINT_RELATIONSHIPS = ("apps", "configurations", "packages", "orgDevices", "users", "userGroups")

MAX_PROFILE_BYTES = 1_000_000


def _id(value: str, label: str = "id") -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise ValueError(f"{label} の形式が不正です（英数字と . _ : - のみ、128 文字以内）: {value!r}")
    return value


def _parse_deadline(value: str, *, enforce_max_90_days: bool) -> str:
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"期限は ISO 8601 形式で指定してください（例: 2026-12-01T09:00:00Z）: {value!r}") from exc
    if dt.tzinfo is None:
        raise ValueError("期限にはタイムゾーンが必要です（例: 末尾に Z または +09:00）")
    dt = dt.astimezone(timezone.utc)
    if enforce_max_90_days and dt > datetime.now(timezone.utc) + timedelta(days=90):
        raise ValueError("移行期限は 90 日より先には設定できません")
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Toolbox:
    def __init__(self, cfg: Config, client: ABMClient, gate: Gate):
        self.cfg = cfg
        self.client = client
        self.gate = gate

    # ------------------------------------------------------------------ 補助
    def _device_ids(self, device_ids: list[str]) -> list[str]:
        if not device_ids:
            raise ValueError("device_ids が空です")
        unique = list(dict.fromkeys(_id(d, "device_id") for d in device_ids))
        if len(unique) > self.cfg.max_devices_per_op:
            raise ValueError(
                f"1 回の操作で扱えるデバイスは {self.cfg.max_devices_per_op} 台までです"
                f"（{len(unique)} 台指定）。ABM_MAX_DEVICES_PER_OP で変更できます。"
            )
        return unique

    def _read_allowed_file(self, path: str) -> bytes:
        """プロンプトインジェクション対策として、読めるのは files_dir 配下のファイルだけ。"""
        root = self.cfg.files_dir.expanduser().resolve()
        target = (root / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
        if root != target and root not in target.parents:
            raise ValueError(f"読み込めるのは {root} 配下のファイルだけです")
        if not target.is_file():
            raise ValueError(f"ファイルが見つかりません: {target}")
        if target.stat().st_size > MAX_PROFILE_BYTES:
            raise ValueError("ファイルが大きすぎます（1MB まで）")
        return target.read_bytes()

    @staticmethod
    def _cert_to_base64(raw: bytes) -> str:
        text = raw.strip()
        if text.startswith(b"-----BEGIN"):
            lines = [ln for ln in text.decode("ascii", "ignore").splitlines() if not ln.startswith("-----")]
            return "".join(lines).strip()
        return base64.b64encode(raw).decode("ascii")

    def _activity_payload(
        self,
        activity_type: str,
        device_ids: list[str],
        server_id: str | None = None,
        deadline: str | None = None,
    ) -> dict[str, Any]:
        attrs: dict[str, Any] = {"activityType": activity_type}
        if deadline:
            attrs["activityTypeMetadata"] = {"mdmMigrationDeadlineDateTime": deadline}
        rels: dict[str, Any] = {
            "devices": {"data": [{"type": "orgDevices", "id": d} for d in device_ids]}
        }
        if server_id:
            rels["mdmServer"] = {"data": {"type": "mdmServers", "id": server_id}}
        return {"data": {"type": "orgDeviceActivities", "attributes": attrs, "relationships": rels}}

    def _submit_activity(
        self, action: str, summary: str, payload: dict, confirm_token: str | None, destructive: bool = False
    ) -> dict[str, Any]:
        return self.gate.run_write(
            action=action,
            payload=payload,
            summary=summary,
            confirm_token=confirm_token,
            destructive=destructive,
            execute=lambda: self.client.request("POST", "/v1/orgDeviceActivities", json_body=payload),
        )

    def _relationship_payload(self, relationship: str, ids: list[str]) -> list[dict[str, str]]:
        if relationship not in BLUEPRINT_RELATIONSHIPS:
            raise ValueError(f"relationship は {', '.join(BLUEPRINT_RELATIONSHIPS)} のいずれかです")
        if not ids:
            raise ValueError("ids が空です")
        unique = list(dict.fromkeys(_id(i) for i in ids))
        cap = self.cfg.max_devices_per_op if relationship == "orgDevices" else 200
        if len(unique) > cap:
            raise ValueError(f"1 回で扱える {relationship} は {cap} 件までです（{len(unique)} 件指定）")
        return [{"type": relationship, "id": i} for i in unique]

    def _relationships_block(self, rels: dict[str, list[str]] | None) -> dict[str, Any]:
        block: dict[str, Any] = {}
        for name, ids in (rels or {}).items():
            block[name] = {"data": self._relationship_payload(name, ids)}
        return block

    # ================================================================ 参照系
    def check_connection(self) -> dict[str, Any]:
        """接続確認。認証 → API 呼び出しの順に試し、どこで失敗したかと現在の安全設定を返す。"""
        status: dict[str, Any] = {
            "api_base": self.cfg.api_base,
            "write_enabled": self.cfg.enable_write,
            "destructive_enabled": self.cfg.enable_destructive,
            "max_devices_per_operation": self.cfg.max_devices_per_op,
        }
        try:
            self.client.tokens.get_token()
        except ABMAuthError as exc:
            return {**status, "ok": False, "stage": "auth", "error": str(exc)}
        try:
            body = self.client.request("GET", "/v1/mdmServers", params={"limit": 1}) or {}
        except ABMError as exc:
            return {**status, "ok": False, "stage": "api", "error": str(exc)}
        return {**status, "ok": True, "token_expires_in_seconds": self.client.tokens.expires_in,
                "mdm_servers_in_first_page": len(body.get("data") or [])}

    def api_get(self, path: str, query: dict[str, str] | None = None) -> Any:
        """任意の GET を送る（/v1/ 配下のみ・1 ページ分）。専用ツールがない参照系や、推定パスの確認用。"""
        return self.client.request("GET", path, params=query)

    # ---- デバイス ----
    def list_devices(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """組織のデバイス一覧（自動デバイス登録で追加されたもの）。続きは next_cursor を cursor に渡す。"""
        return self.client.list_resources("/v1/orgDevices", max_items=max_items, cursor=cursor)

    def get_device(self, device_id: str) -> Any:
        """デバイス 1 台の詳細。device_id はシリアル番号。"""
        return self.client.request("GET", f"/v1/orgDevices/{_id(device_id, 'device_id')}")

    def get_device_applecare(self, device_id: str) -> Any:
        """デバイスの AppleCare 保証情報。"""
        return self.client.request("GET", f"/v1/orgDevices/{_id(device_id, 'device_id')}/appleCareCoverage")

    def get_device_activation_lock(self, device_id: str) -> Any:
        """デバイスのアクティベーションロック状態（パスは推定）。"""
        return self.client.request("GET", f"/v1/orgDevices/{_id(device_id, 'device_id')}/activationLockStatus")

    def get_device_assigned_server(self, device_id: str) -> dict[str, Any]:
        """デバイスの割り当て先デバイス管理サービス。未割り当てなら assigned=false。"""
        try:
            body = self.client.request("GET", f"/v1/orgDevices/{_id(device_id, 'device_id')}/assignedServer")
        except ABMError as exc:
            if exc.status == 404:
                return {"assigned": False}
            raise
        return {"assigned": True, "server": body}

    def get_device_assigned_server_id(self, device_id: str) -> dict[str, Any]:
        """デバイスの割り当て先サービス ID のみ（軽量版）。未割り当てなら assigned=false。"""
        try:
            body = self.client.request(
                "GET", f"/v1/orgDevices/{_id(device_id, 'device_id')}/relationships/assignedServer"
            )
        except ABMError as exc:
            if exc.status == 404:
                return {"assigned": False}
            raise
        return {"assigned": True, "linkage": body}

    def list_mdm_enrolled_devices(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """組み込みデバイス管理（Apple Device Management）に登録済みのデバイス一覧（パスは推定）。"""
        return self.client.list_resources("/v1/mdmDevices", max_items=max_items, cursor=cursor)

    def get_mdm_enrolled_device_details(self, device_id: str) -> Any:
        """組み込みデバイス管理に登録済みのデバイスの詳細（パスは推定）。"""
        return self.client.request("GET", f"/v1/mdmDevices/{_id(device_id, 'device_id')}/details")

    # ---- デバイス管理サービス ----
    def list_mdm_servers(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """デバイス管理サービス（MDM）の一覧。"""
        return self.client.list_resources("/v1/mdmServers", max_items=max_items, cursor=cursor)

    def get_mdm_server(self, server_id: str) -> Any:
        """デバイス管理サービス 1 件の情報。"""
        return self.client.request("GET", f"/v1/mdmServers/{_id(server_id, 'server_id')}")

    def list_mdm_server_devices(
        self, server_id: str, max_items: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        """デバイス管理サービスに割り当て済みのデバイス（シリアル番号）一覧。"""
        return self.client.list_resources(
            f"/v1/mdmServers/{_id(server_id, 'server_id')}/relationships/devices",
            max_items=max_items,
            cursor=cursor,
        )

    def get_activity(self, activity_id: str) -> Any:
        """割り当て変更などのアクティビティの進行状況・結果（直近 30 日分）。変更系の実行後にこれで結果を確認する。"""
        return self.client.request("GET", f"/v1/orgDeviceActivities/{_id(activity_id, 'activity_id')}")

    # ---- ユーザー・グループ・組織のユニット ----
    def list_users(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """組織のユーザー一覧。"""
        return self.client.list_resources("/v1/users", max_items=max_items, cursor=cursor)

    def get_user(self, user_id: str) -> Any:
        """ユーザー 1 人の情報。"""
        return self.client.request("GET", f"/v1/users/{_id(user_id, 'user_id')}")

    def list_user_groups(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """ユーザーグループの一覧（パスは推定）。"""
        return self.client.list_resources("/v1/userGroups", max_items=max_items, cursor=cursor)

    def get_user_group(self, group_id: str) -> Any:
        """ユーザーグループ 1 件の情報（パスは推定）。"""
        return self.client.request("GET", f"/v1/userGroups/{_id(group_id, 'group_id')}")

    def list_user_group_members(
        self, group_id: str, max_items: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        """ユーザーグループに所属するユーザー ID の一覧（パスは推定）。"""
        return self.client.list_resources(
            f"/v1/userGroups/{_id(group_id, 'group_id')}/relationships/users",
            max_items=max_items, cursor=cursor,
        )

    def list_organizational_units(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """組織のユニットの一覧（パスは推定）。"""
        return self.client.list_resources("/v1/organizationalUnits", max_items=max_items, cursor=cursor)

    def get_organizational_unit(self, unit_id: str) -> Any:
        """組織のユニット 1 件の情報（パスは推定）。"""
        return self.client.request("GET", f"/v1/organizationalUnits/{_id(unit_id, 'unit_id')}")

    def list_organizational_unit_members(
        self, unit_id: str, max_items: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        """組織のユニットに属するユーザー ID の一覧（パスは推定）。"""
        return self.client.list_resources(
            f"/v1/organizationalUnits/{_id(unit_id, 'unit_id')}/relationships/users",
            max_items=max_items, cursor=cursor,
        )

    # ---- アプリ・パッケージ ----
    def list_apps(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """ライセンス済みアプリの一覧（組み込みデバイス管理が有効な組織のみ）。"""
        return self.client.list_resources("/v1/apps", max_items=max_items, cursor=cursor)

    def get_app(self, app_id: str) -> Any:
        """アプリ 1 件の情報。"""
        return self.client.request("GET", f"/v1/apps/{_id(app_id, 'app_id')}")

    def list_packages(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """パッケージの一覧（パスは推定）。"""
        return self.client.list_resources("/v1/packages", max_items=max_items, cursor=cursor)

    def get_package(self, package_id: str) -> Any:
        """パッケージ 1 件の情報（パスは推定）。"""
        return self.client.request("GET", f"/v1/packages/{_id(package_id, 'package_id')}")

    # ---- ブループリント・構成 ----
    def list_blueprints(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """ブループリントの一覧。"""
        return self.client.list_resources("/v1/blueprints", max_items=max_items, cursor=cursor)

    def get_blueprint(self, blueprint_id: str) -> Any:
        """ブループリント 1 件の情報。"""
        return self.client.request("GET", f"/v1/blueprints/{_id(blueprint_id, 'blueprint_id')}")

    def get_blueprint_members(
        self, blueprint_id: str, relationship: str, max_items: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        """ブループリントに含まれる要素の ID 一覧。relationship は apps / configurations / packages / orgDevices / users / userGroups。"""
        if relationship not in BLUEPRINT_RELATIONSHIPS:
            raise ValueError(f"relationship は {', '.join(BLUEPRINT_RELATIONSHIPS)} のいずれかです")
        return self.client.list_resources(
            f"/v1/blueprints/{_id(blueprint_id, 'blueprint_id')}/relationships/{relationship}",
            max_items=max_items, cursor=cursor,
        )

    def list_configurations(self, max_items: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """構成の一覧。一覧では customSettingsValues は null になるため、中身は get_configuration で取得する。"""
        return self.client.list_resources("/v1/configurations", max_items=max_items, cursor=cursor)

    def get_configuration(self, configuration_id: str) -> Any:
        """構成 1 件の詳細（カスタム構成なら構成プロファイルの中身を含む）。"""
        return self.client.request("GET", f"/v1/configurations/{_id(configuration_id, 'configuration_id')}")

    # ---- 監査イベント ----
    def list_audit_events(
        self,
        start: str,
        end: str | None = None,
        extra_filters: dict[str, str] | None = None,
        max_items: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """監査イベント。start/end は ISO 8601（例: 2026-10-01T00:00:00Z）。
        extra_filters は filter[キー] として追加される（利用可能なキーは Apple の仕様に従う）。"""
        params: dict[str, Any] = {"filter[startTimestamp]": start}
        if end:
            params["filter[endTimestamp]"] = end
        for key, value in (extra_filters or {}).items():
            if not re.match(r"^[A-Za-z][A-Za-z0-9]{0,63}$", key):
                raise ValueError(f"extra_filters のキーが不正です: {key!r}")
            params[f"filter[{key}]"] = value
        return self.client.list_resources("/v1/auditEvents", params, max_items=max_items, cursor=cursor)

    # ================================================================ 変更系
    # ---- デバイスの割り当て ----
    def assign_devices_to_mdm(
        self, server_id: str, device_ids: list[str], confirm_token: str | None = None
    ) -> dict[str, Any]:
        """デバイスをデバイス管理サービスに割り当てる（ASSIGN_DEVICES）。
        confirm_token なしで呼ぶとプレビューのみ。実行後は get_activity で結果を確認する。"""
        sid, ids = _id(server_id, "server_id"), self._device_ids(device_ids)
        payload = self._activity_payload("ASSIGN_DEVICES", ids, server_id=sid)
        return self._submit_activity("assign_devices", f"{len(ids)} 台をサービス {sid} に割り当て", payload, confirm_token)

    def unassign_devices_from_mdm(
        self, server_id: str, device_ids: list[str], confirm_token: str | None = None
    ) -> dict[str, Any]:
        """デバイスをデバイス管理サービスから割り当て解除する（UNASSIGN_DEVICES）。
        confirm_token なしで呼ぶとプレビューのみ。"""
        sid, ids = _id(server_id, "server_id"), self._device_ids(device_ids)
        payload = self._activity_payload("UNASSIGN_DEVICES", ids, server_id=sid)
        return self._submit_activity("unassign_devices", f"{len(ids)} 台をサービス {sid} から割り当て解除", payload, confirm_token)

    def schedule_mdm_migration(
        self, server_id: str, device_ids: list[str], deadline: str, confirm_token: str | None = None
    ) -> dict[str, Any]:
        """割り当て先を変更し、デバイス管理サービスの移行を期限付きで予約する。
        deadline は ISO 8601（タイムゾーン付き・90 日以内）。confirm_token なしならプレビューのみ。"""
        sid, ids = _id(server_id, "server_id"), self._device_ids(device_ids)
        dl = _parse_deadline(deadline, enforce_max_90_days=True)
        payload = self._activity_payload("ASSIGN_DEVICES_WITH_MDM_MIGRATION_DEADLINE", ids, server_id=sid, deadline=dl)
        return self._submit_activity("schedule_mdm_migration", f"{len(ids)} 台を {sid} へ移行（期限 {dl}）", payload, confirm_token)

    def update_mdm_migration_deadline(
        self, device_ids: list[str], deadline: str, confirm_token: str | None = None
    ) -> dict[str, Any]:
        """進行中の移行の期限を更新する。新しい期限が現在より前だと、ユーザーに延期の選択肢なく即時適用される。"""
        ids = self._device_ids(device_ids)
        dl = _parse_deadline(deadline, enforce_max_90_days=False)
        payload = self._activity_payload("UPDATE_MDM_MIGRATION_DEADLINE", ids, deadline=dl)
        return self._submit_activity("update_mdm_migration_deadline", f"{len(ids)} 台の移行期限を {dl} に更新", payload, confirm_token)

    def cancel_mdm_migration(self, device_ids: list[str], confirm_token: str | None = None) -> dict[str, Any]:
        """進行中のデバイス管理サービス移行をキャンセルする。"""
        ids = self._device_ids(device_ids)
        payload = self._activity_payload("CANCEL_MDM_MIGRATION", ids)
        return self._submit_activity("cancel_mdm_migration", f"{len(ids)} 台の移行をキャンセル", payload, confirm_token)

    # ---- ブループリント ----
    def create_blueprint(
        self,
        name: str,
        description: str | None = None,
        members: dict[str, list[str]] | None = None,
        confirm_token: str | None = None,
    ) -> dict[str, Any]:
        """ブループリントを作成する。members は {"apps": [...], "configurations": [...], "users": [...], ...}。
        存在しない ID は Apple 側で無視される。メンバーなしの作成は拒否される場合がある。"""
        if not name.strip():
            raise ValueError("name が空です")
        attrs: dict[str, Any] = {"name": name}
        if description is not None:
            attrs["description"] = description
        data: dict[str, Any] = {"type": "blueprints", "attributes": attrs}
        rels = self._relationships_block(members)
        if rels:
            data["relationships"] = rels
        payload = {"data": data}
        return self.gate.run_write(
            action="create_blueprint", payload=payload, summary=f"ブループリント「{name}」を作成",
            confirm_token=confirm_token, destructive=False,
            execute=lambda: self.client.request("POST", "/v1/blueprints", json_body=payload),
        )

    def update_blueprint(
        self,
        blueprint_id: str,
        name: str | None = None,
        description: str | None = None,
        members: dict[str, list[str]] | None = None,
        confirm_token: str | None = None,
    ) -> dict[str, Any]:
        """ブループリントの名前・説明・メンバーを更新する（指定した項目のみ）。
        members を渡したときに「追加」になるか「置換」になるかは未確認なので、
        メンバーの増減には add_to_blueprint / remove_from_blueprint を使うのが確実。"""
        bid = _id(blueprint_id, "blueprint_id")
        attrs: dict[str, Any] = {}
        if name is not None:
            attrs["name"] = name
        if description is not None:
            attrs["description"] = description
        rels = self._relationships_block(members)
        if not attrs and not rels:
            raise ValueError("更新する項目がありません")
        data: dict[str, Any] = {"type": "blueprints", "id": bid}
        if attrs:
            data["attributes"] = attrs
        if rels:
            data["relationships"] = rels
        payload = {"data": data}
        return self.gate.run_write(
            action="update_blueprint", payload={"id": bid, **payload}, summary=f"ブループリント {bid} を更新",
            confirm_token=confirm_token, destructive=False,
            execute=lambda: self.client.request("PATCH", f"/v1/blueprints/{bid}", json_body=payload),
        )

    def add_to_blueprint(
        self, blueprint_id: str, relationship: str, ids: list[str], confirm_token: str | None = None
    ) -> dict[str, Any]:
        """ブループリントに要素を追加する。relationship は apps / configurations / packages / orgDevices / users / userGroups。"""
        bid = _id(blueprint_id, "blueprint_id")
        data = self._relationship_payload(relationship, ids)
        payload = {"data": data}
        return self.gate.run_write(
            action="add_to_blueprint", payload={"id": bid, "rel": relationship, **payload},
            summary=f"ブループリント {bid} に {relationship} を {len(data)} 件追加",
            confirm_token=confirm_token, destructive=False,
            execute=lambda: self.client.request(
                "POST", f"/v1/blueprints/{bid}/relationships/{relationship}", json_body=payload
            ),
        )

    def remove_from_blueprint(
        self, blueprint_id: str, relationship: str, ids: list[str], confirm_token: str | None = None
    ) -> dict[str, Any]:
        """ブループリントから要素を外す（DELETE。本文の形式は追加と同じと仮定）。"""
        bid = _id(blueprint_id, "blueprint_id")
        data = self._relationship_payload(relationship, ids)
        payload = {"data": data}
        return self.gate.run_write(
            action="remove_from_blueprint", payload={"id": bid, "rel": relationship, **payload},
            summary=f"ブループリント {bid} から {relationship} を {len(data)} 件外す",
            confirm_token=confirm_token, destructive=False,
            execute=lambda: self.client.request(
                "DELETE", f"/v1/blueprints/{bid}/relationships/{relationship}", json_body=payload
            ),
        )

    # ---- 構成（カスタム構成のみ API で作成・更新できる） ----
    def _profile_text(self, configuration_profile: str | None, profile_path: str | None) -> str | None:
        if configuration_profile and profile_path:
            raise ValueError("configuration_profile と profile_path はどちらか一方だけ指定してください")
        text = configuration_profile
        if profile_path:
            text = self._read_allowed_file(profile_path).decode("utf-8")
        if text is None:
            return None
        if "<plist" not in text:
            raise ValueError("構成プロファイル（.mobileconfig の XML plist）の形式ではありません")
        if len(text.encode("utf-8")) > MAX_PROFILE_BYTES:
            raise ValueError("構成プロファイルが大きすぎます（1MB まで）")
        return text

    @staticmethod
    def _check_filename(filename: str | None) -> None:
        if filename is not None and not filename.endswith(".mobileconfig"):
            raise ValueError("filename は .mobileconfig で終わる必要があります")

    def create_custom_configuration(
        self,
        name: str,
        configuration_profile: str | None = None,
        profile_path: str | None = None,
        filename: str | None = None,
        platforms: list[str] | None = None,
        confirm_token: str | None = None,
    ) -> dict[str, Any]:
        """カスタム構成（CUSTOM_SETTING）を作成する。プロファイルは XML 文字列、または files ディレクトリ内の
        ファイル（profile_path）で渡す。platforms 例: ["PLATFORM_MACOS", "PLATFORM_IOS"]（省略時は自動判定）。"""
        text = self._profile_text(configuration_profile, profile_path)
        if text is None:
            raise ValueError("configuration_profile または profile_path が必要です")
        self._check_filename(filename)
        values: dict[str, Any] = {"configurationProfile": text}
        if filename:
            values["filename"] = filename
        attrs: dict[str, Any] = {"type": "CUSTOM_SETTING", "name": name, "customSettingsValues": values}
        if platforms:
            attrs["configuredForPlatforms"] = platforms
        payload = {"data": {"type": "configurations", "attributes": attrs}}
        return self.gate.run_write(
            action="create_configuration", payload=payload, summary=f"カスタム構成「{name}」を作成",
            confirm_token=confirm_token, destructive=False,
            execute=lambda: self.client.request("POST", "/v1/configurations", json_body=payload),
        )

    def update_custom_configuration(
        self,
        configuration_id: str,
        name: str | None = None,
        configuration_profile: str | None = None,
        profile_path: str | None = None,
        filename: str | None = None,
        platforms: list[str] | None = None,
        confirm_token: str | None = None,
    ) -> dict[str, Any]:
        """カスタム構成を更新する（指定した項目のみ。CUSTOM_SETTING 以外は更新できない）。"""
        cid = _id(configuration_id, "configuration_id")
        text = self._profile_text(configuration_profile, profile_path)
        self._check_filename(filename)
        attrs: dict[str, Any] = {}
        if name is not None:
            attrs["name"] = name
        if platforms:
            attrs["configuredForPlatforms"] = platforms
        values: dict[str, Any] = {}
        if text is not None:
            values["configurationProfile"] = text
        if filename:
            values["filename"] = filename
        if values:
            attrs["customSettingsValues"] = values
        if not attrs:
            raise ValueError("更新する項目がありません")
        payload = {"data": {"type": "configurations", "id": cid, "attributes": attrs}}
        return self.gate.run_write(
            action="update_configuration", payload=payload, summary=f"構成 {cid} を更新",
            confirm_token=confirm_token, destructive=False,
            execute=lambda: self.client.request("PATCH", f"/v1/configurations/{cid}", json_body=payload),
        )

    # ---- デバイス管理サービス ----
    def _certificate(self, name: str | None, base64_data: str | None, path: str | None) -> dict[str, str] | None:
        if base64_data and path:
            raise ValueError("certificate_base64 と certificate_path はどちらか一方だけ指定してください")
        if path:
            data = self._cert_to_base64(self._read_allowed_file(path))
            name = name or Path(path).name
        elif base64_data:
            data = re.sub(r"\s+", "", base64_data)
        else:
            return None
        if not name:
            raise ValueError("certificate_name が必要です")
        return {"name": name, "data": data}

    def create_mdm_server(
        self,
        server_name: str,
        certificate_path: str | None = None,
        certificate_base64: str | None = None,
        certificate_name: str | None = None,
        enable_mdm_disown_flag: bool | None = None,
        confirm_token: str | None = None,
    ) -> dict[str, Any]:
        """デバイス管理サービスを作成する。サーバー証明書（.cer/.pem）は files ディレクトリ内のファイル
        （certificate_path）か Base64 文字列で渡す。"""
        cert = self._certificate(certificate_name, certificate_base64, certificate_path)
        if cert is None:
            raise ValueError("certificate_path または certificate_base64 が必要です")
        attrs: dict[str, Any] = {"serverName": server_name, "serverCertificate": cert}
        if enable_mdm_disown_flag is not None:
            attrs["enableMdmDisownFlag"] = enable_mdm_disown_flag
        payload = {"data": {"type": "mdmServers", "attributes": attrs}}
        return self.gate.run_write(
            action="create_mdm_server", payload=payload, summary=f"デバイス管理サービス「{server_name}」を作成",
            confirm_token=confirm_token, destructive=False,
            execute=lambda: self.client.request("POST", "/v1/mdmServers", json_body=payload),
        )

    def update_mdm_server(
        self,
        server_id: str,
        server_name: str | None = None,
        certificate_path: str | None = None,
        certificate_base64: str | None = None,
        certificate_name: str | None = None,
        enable_mdm_disown_flag: bool | None = None,
        confirm_token: str | None = None,
    ) -> dict[str, Any]:
        """デバイス管理サービスを更新する（指定した項目のみ）。"""
        sid = _id(server_id, "server_id")
        attrs: dict[str, Any] = {}
        if server_name is not None:
            attrs["serverName"] = server_name
        cert = self._certificate(certificate_name, certificate_base64, certificate_path)
        if cert:
            attrs["serverCertificate"] = cert
        if enable_mdm_disown_flag is not None:
            attrs["enableMdmDisownFlag"] = enable_mdm_disown_flag
        if not attrs:
            raise ValueError("更新する項目がありません")
        payload = {"data": {"type": "mdmServers", "id": sid, "attributes": attrs}}
        return self.gate.run_write(
            action="update_mdm_server", payload=payload, summary=f"デバイス管理サービス {sid} を更新",
            confirm_token=confirm_token, destructive=False,
            execute=lambda: self.client.request("PATCH", f"/v1/mdmServers/{sid}", json_body=payload),
        )

    # ============================================================ 破壊的な操作
    def release_devices(self, device_ids: list[str], confirm_token: str | None = None) -> dict[str, Any]:
        """【破壊的】デバイスを組織から解放する（RELEASE_DEVICES）。組織への登録と自動登録の割り当てが外れ、
        組み込みデバイス管理から登録解除され、ブループリントからも外れる。元に戻すには再登録が必要。"""
        ids = self._device_ids(device_ids)
        payload = self._activity_payload("RELEASE_DEVICES", ids)
        return self._submit_activity(
            "release_devices",
            f"【破壊的】{len(ids)} 台を組織から解放（登録解除・ブループリントから除外）",
            payload, confirm_token, destructive=True,
        )

    def _delete(self, action: str, collection: str, item_id: str, label: str, confirm_token: str | None) -> dict[str, Any]:
        iid = _id(item_id, "id")
        return self.gate.run_write(
            action=action, payload={"id": iid}, summary=f"【破壊的】{label} {iid} を削除",
            confirm_token=confirm_token, destructive=True,
            execute=lambda: self.client.request("DELETE", f"/v1/{collection}/{iid}"),
        )

    def delete_blueprint(self, blueprint_id: str, confirm_token: str | None = None) -> dict[str, Any]:
        """【破壊的】ブループリントを削除する。"""
        return self._delete("delete_blueprint", "blueprints", blueprint_id, "ブループリント", confirm_token)

    def delete_configuration(self, configuration_id: str, confirm_token: str | None = None) -> dict[str, Any]:
        """【破壊的】構成を削除する。"""
        return self._delete("delete_configuration", "configurations", configuration_id, "構成", confirm_token)

    def delete_mdm_server(self, server_id: str, confirm_token: str | None = None) -> dict[str, Any]:
        """【破壊的】デバイス管理サービスを削除する。デバイスが割り当てられている間は Apple 側で拒否される場合がある。"""
        return self._delete("delete_mdm_server", "mdmServers", server_id, "デバイス管理サービス", confirm_token)


READ_TOOLS = (
    "check_connection", "api_get",
    "list_devices", "get_device", "get_device_applecare", "get_device_activation_lock",
    "get_device_assigned_server", "get_device_assigned_server_id",
    "list_mdm_enrolled_devices", "get_mdm_enrolled_device_details",
    "list_mdm_servers", "get_mdm_server", "list_mdm_server_devices", "get_activity",
    "list_users", "get_user", "list_user_groups", "get_user_group", "list_user_group_members",
    "list_organizational_units", "get_organizational_unit", "list_organizational_unit_members",
    "list_apps", "get_app", "list_packages", "get_package",
    "list_blueprints", "get_blueprint", "get_blueprint_members",
    "list_configurations", "get_configuration", "list_audit_events",
)
WRITE_TOOLS = (
    "assign_devices_to_mdm", "unassign_devices_from_mdm", "schedule_mdm_migration",
    "update_mdm_migration_deadline", "cancel_mdm_migration",
    "create_blueprint", "update_blueprint", "add_to_blueprint", "remove_from_blueprint",
    "create_custom_configuration", "update_custom_configuration",
    "create_mdm_server", "update_mdm_server",
)
DESTRUCTIVE_TOOLS = ("release_devices", "delete_blueprint", "delete_configuration", "delete_mdm_server")

INSTRUCTIONS = """\
Apple Business（組織のデバイス・ユーザー・ブループリント等）を操作するサーバーです。
- device_id はデバイスのシリアル番号です。
- 一覧は next_cursor が返ったら cursor に渡して続きを取得できます。
- 変更系・破壊的ツールは、confirm_token なしで呼ぶとプレビューだけ返し何も送信しません。
  必ずプレビュー内容をユーザーに見せて承認を得てから、同じ引数に confirm_token を付けて再実行してください。
- 割り当て変更などは非同期です。実行後は get_activity で結果を確認してください。
- 一部のパスは推定です。404 や 400 が出たら api_get で実際の応答を確認してください。
"""


def surface_errors(fn: Callable[..., Any]) -> Callable[..., Any]:
    """想定内の失敗を ToolError にして、理由が Claude に届くようにする。

    MCP SDK は ToolError 以外の例外を「クラッシュ」とみなし、Claude には
    "Error executing tool ..." としか返さない。API のエラー内容・安全装置の拒否理由・
    入力不正の説明が見えないと、Claude が次の行動を判断できない。
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except (ABMError, ABMAuthError, GateError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    return wrapper


def build_server(cfg: Config, client: ABMClient | None = None, gate: Gate | None = None) -> MCPServer:
    client = client or ABMClient(cfg)
    gate = gate or Gate(cfg)
    box = Toolbox(cfg, client, gate)
    server = MCPServer("apple-business", instructions=INSTRUCTIONS)

    read_ann = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)
    write_ann = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)
    danger_ann = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True)

    def register(name: str, annotations: ToolAnnotations) -> None:
        server.tool(name=name, annotations=annotations)(surface_errors(getattr(box, name)))

    for name in READ_TOOLS:
        register(name, read_ann)
    if cfg.enable_write:
        for name in WRITE_TOOLS:
            register(name, write_ann)
        if cfg.enable_destructive:
            for name in DESTRUCTIVE_TOOLS:
                register(name, danger_ann)
    return server
