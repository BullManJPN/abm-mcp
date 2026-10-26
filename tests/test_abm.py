import asyncio
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from abm_mcp.auth import ABMAuthError, TokenProvider  # noqa: E402
from abm_mcp.client import ABMClient, ABMError  # noqa: E402
from abm_mcp.config import Config  # noqa: E402
from abm_mcp.safety import Gate, GateError  # noqa: E402
from abm_mcp.tools import (DESTRUCTIVE_TOOLS, READ_TOOLS, WRITE_TOOLS, Toolbox,  # noqa: E402
                           build_server)
from fake_apple import AUDIENCE, CLIENT_ID, KEY_ID, FakeApple  # noqa: E402


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        key = ec.generate_private_key(ec.SECP256R1())
        cls.key_path = Path(cls.tmp.name) / "key.pem"
        cls.key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(cls.key_path, 0o600)
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.server = FakeApple(pub)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def setUp(self):
        self.server.reset()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def cfg(self, **kw):
        base = dict(
            client_id=CLIENT_ID, key_id=KEY_ID, private_key_path=self.key_path,
            api_base=self.server.base, token_url=self.server.base + "/auth/oauth2/token",
            audience=AUDIENCE, audit_log=Path(self.dir.name) / "audit.jsonl",
            files_dir=Path(self.dir.name) / "files", home_dir=Path(self.dir.name),
            backoff_base=0.01, max_retries=2,
        )
        base.update(kw)
        return Config(**base)

    def box(self, **kw):
        cfg = self.cfg(**kw)
        return Toolbox(cfg, ABMClient(cfg), Gate(cfg))

    def posts(self, path_prefix):
        return [e for e in self.server.api_log if e[0] == "POST" and e[1].startswith(path_prefix)]


class AuthTests(Base):
    def test_assertion_claims_and_header(self):
        tp = TokenProvider(self.cfg())
        token = tp.build_assertion()
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "ES256")
        self.assertEqual(header["kid"], KEY_ID)
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(claims["sub"], CLIENT_ID)
        self.assertEqual(claims["aud"], AUDIENCE)
        self.assertLess(claims["exp"] - claims["iat"], 180 * 86400)
        self.assertNotIn("kid", jwt.get_unverified_header(tp.build_assertion(include_kid=False)))

    def test_token_is_cached(self):
        c = ABMClient(self.cfg())
        c.request("GET", "/v1/mdmServers")
        c.request("GET", "/v1/mdmServers")
        self.assertEqual(len(self.server.issued), 1)

    def test_401_refreshes_token_once(self):
        c = ABMClient(self.cfg())
        c.request("GET", "/v1/mdmServers")
        self.server.valid.clear()  # 期限切れを再現
        c.request("GET", "/v1/mdmServers")
        self.assertEqual(len(self.server.issued), 2)

    def test_kid_rejection_falls_back_and_is_remembered(self):
        self.server.reject_kid = True
        tp = TokenProvider(self.cfg())
        tp.get_token()
        self.assertTrue(tp._variant is not None and tp._variant[0] is False)
        n = len(self.server.token_requests)
        tp.get_token(force=True)
        self.assertEqual(len(self.server.token_requests), n + 1)  # 記憶した方式で 1 回だけ

    def test_body_style_fallback(self):
        self.server.accept_style = "body"
        tp = TokenProvider(self.cfg(token_params_in="query"))
        tp.get_token()
        self.assertEqual(tp._variant[1], "body")

    def test_bad_key_gives_auth_error(self):
        other = Path(self.dir.name) / "other.pem"
        other.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(other, 0o600)
        with self.assertRaises(ABMAuthError):
            TokenProvider(self.cfg(private_key_path=other)).get_token()


class ClientTests(Base):
    def test_error_mapping(self):
        with self.assertRaises(ABMError) as cm:
            ABMClient(self.cfg()).request("GET", "/v1/orgDevices/NOPE")
        self.assertEqual(cm.exception.status, 404)
        self.assertIn("NOT_FOUND", str(cm.exception))

    def test_pagination_full_and_partial(self):
        c = ABMClient(self.cfg())
        full = c.list_resources("/v1/orgDevices", max_items=50)
        self.assertEqual(full["count"], 7)
        self.assertIsNone(full["next_cursor"])
        part = c.list_resources("/v1/orgDevices", max_items=3)
        self.assertEqual(part["count"], 3)
        self.assertEqual(part["next_cursor"], "c3")
        rest = c.list_resources("/v1/orgDevices", max_items=50, cursor=part["next_cursor"])
        ids = [i["id"] for i in part["items"] + rest["items"]]
        self.assertEqual(ids, self.server.devices)  # 取りこぼし・重複なし

    def test_never_follows_foreign_link_and_never_sends_token_there(self):
        # モックの links.next は evil.example を指すが、カーソルだけ使うので接続しない
        c = ABMClient(self.cfg())
        self.assertEqual(c.list_resources("/v1/orgDevices", max_items=7)["count"], 7)

    def test_foreign_host_and_bad_paths_rejected(self):
        c = ABMClient(self.cfg())
        for target in ("https://evil.example/v1/x", "/v2/x", "/v1/../etc", "/v1/x?y=1", "v1/x"):
            with self.assertRaises(ABMError, msg=target):
                c.request("GET", target)

    def test_post_is_not_retried_on_5xx_but_get_is(self):
        c = ABMClient(self.cfg())
        self.server.fail_next["POST"] = [503, 503]
        with self.assertRaises(ABMError):
            c.request("POST", "/v1/orgDeviceActivities", json_body={})
        self.assertEqual(len(self.posts("/v1/orgDeviceActivities")), 1)
        self.server.fail_next["GET"] = [503]
        self.assertIsNotNone(c.request("GET", "/v1/mdmServers"))


class GateAndToolTests(Base):
    def test_write_disabled_by_default(self):
        with self.assertRaises(GateError):
            self.box().assign_devices_to_mdm("SRV1", ["SERIAL000"])
        self.assertEqual(self.posts("/v1/orgDeviceActivities"), [])

    def test_preview_then_execute_flow(self):
        box = self.box(enable_write=True)
        pre = box.assign_devices_to_mdm("SRV1", ["SERIAL000", "SERIAL001"])
        self.assertEqual(pre["status"], "preview")
        self.assertEqual(self.posts("/v1/orgDeviceActivities"), [])  # プレビューでは送信しない
        done = box.assign_devices_to_mdm("SRV1", ["SERIAL000", "SERIAL001"], confirm_token=pre["confirm_token"])
        self.assertEqual(done["status"], "executed")
        body = self.posts("/v1/orgDeviceActivities")[0][2]
        attrs = body["data"]["attributes"]
        rels = body["data"]["relationships"]
        self.assertEqual(attrs["activityType"], "ASSIGN_DEVICES")
        self.assertEqual(rels["mdmServer"]["data"], {"type": "mdmServers", "id": "SRV1"})
        self.assertEqual([d["id"] for d in rels["devices"]["data"]], ["SERIAL000", "SERIAL001"])
        # トークンは使い回せない
        with self.assertRaises(GateError):
            box.assign_devices_to_mdm("SRV1", ["SERIAL000", "SERIAL001"], confirm_token=pre["confirm_token"])

    def test_token_bound_to_arguments(self):
        box = self.box(enable_write=True)
        pre = box.assign_devices_to_mdm("SRV1", ["SERIAL000"])
        with self.assertRaises(GateError):
            box.assign_devices_to_mdm("SRV1", ["SERIAL001"], confirm_token=pre["confirm_token"])
        self.assertEqual(self.posts("/v1/orgDeviceActivities"), [])

    def test_token_expires(self):
        box = self.box(enable_write=True)
        pre = box.cancel_mdm_migration(["SERIAL000"])
        for k in list(box.gate._pending):
            digest, _ = box.gate._pending[k]
            box.gate._pending[k] = (digest, 0)
        with self.assertRaises(GateError):
            box.cancel_mdm_migration(["SERIAL000"], confirm_token=pre["confirm_token"])

    def test_destructive_needs_both_flags(self):
        for kw in ({}, {"enable_write": True}):
            with self.assertRaises(GateError):
                self.box(**kw).release_devices(["SERIAL000"])
        box = self.box(enable_write=True, enable_destructive=True)
        pre = box.release_devices(["SERIAL000"])
        self.assertEqual(pre["tier"], "destructive")
        box.release_devices(["SERIAL000"], confirm_token=pre["confirm_token"])
        body = self.posts("/v1/orgDeviceActivities")[0][2]
        self.assertEqual(body["data"]["attributes"]["activityType"], "RELEASE_DEVICES")
        self.assertNotIn("mdmServer", body["data"]["relationships"])

    def test_delete_blueprint_is_gated_and_sends_delete(self):
        box = self.box(enable_write=True, enable_destructive=True)
        pre = box.delete_blueprint("bp-1")
        self.assertFalse([e for e in self.server.api_log if e[0] == "DELETE"])
        box.delete_blueprint("bp-1", confirm_token=pre["confirm_token"])
        self.assertTrue([e for e in self.server.api_log if e[0] == "DELETE" and e[1] == "/v1/blueprints/bp-1"])

    def test_device_cap_dedupe_and_id_validation(self):
        box = self.box(enable_write=True, max_devices_per_op=2)
        with self.assertRaises(ValueError):
            box.assign_devices_to_mdm("SRV1", ["A1", "B2", "C3"])
        pre = box.assign_devices_to_mdm("SRV1", ["A1", "A1", "B2"])  # 重複は除去され 2 台
        self.assertEqual(len(pre["will_send"]["data"]["relationships"]["devices"]["data"]), 2)
        for bad in ("../x", "a b", "", "x/y"):
            with self.assertRaises(ValueError, msg=bad):
                box.get_device(bad)

    def test_migration_deadline_validation(self):
        box = self.box(enable_write=True)
        with self.assertRaises(ValueError):
            box.schedule_mdm_migration("SRV1", ["A1"], "2999-01-01T00:00:00Z")  # 90 日超
        with self.assertRaises(ValueError):
            box.schedule_mdm_migration("SRV1", ["A1"], "tomorrow")
        with self.assertRaises(ValueError):
            box.schedule_mdm_migration("SRV1", ["A1"], "2030-01-01T00:00:00")  # TZ なし

    def test_blueprint_member_payloads(self):
        box = self.box(enable_write=True)
        pre = box.add_to_blueprint("bp-1", "orgDevices", ["SERIAL000"])
        box.add_to_blueprint("bp-1", "orgDevices", ["SERIAL000"], confirm_token=pre["confirm_token"])
        e = [x for x in self.server.api_log if x[1] == "/v1/blueprints/bp-1/relationships/orgDevices"][0]
        self.assertEqual(e[2], {"data": [{"type": "orgDevices", "id": "SERIAL000"}]})
        with self.assertRaises(ValueError):
            box.add_to_blueprint("bp-1", "bogus", ["x1"])

    def test_assigned_server_404_means_unassigned(self):
        self.assertEqual(self.box().get_device_assigned_server("SERIAL000"), {"assigned": False})

    def test_file_reads_are_confined(self):
        box = self.box(enable_write=True)
        files = Path(self.dir.name) / "files"
        files.mkdir()
        (files / "ok.mobileconfig").write_text("<plist></plist>")
        outside = Path(self.dir.name) / "secret.txt"
        outside.write_text("secret")
        pre = box.create_custom_configuration("n", profile_path="ok.mobileconfig", filename="ok.mobileconfig")
        self.assertEqual(pre["status"], "preview")
        for bad in (str(outside), "../secret.txt"):
            with self.assertRaises(ValueError, msg=bad):
                box.create_custom_configuration("n", profile_path=bad)
        with self.assertRaises(ValueError):
            box.create_custom_configuration("n", configuration_profile="<plist/>", filename="x.txt")

    def test_check_connection_reports_stage(self):
        ok = self.box().check_connection()
        self.assertTrue(ok["ok"])
        bad_cfg = self.cfg(token_url=self.server.base + "/nope")
        bad = Toolbox(bad_cfg, ABMClient(bad_cfg), Gate(bad_cfg)).check_connection()
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["stage"], "auth")

    def test_audit_log_has_no_secrets_and_is_private(self):
        box = self.box(enable_write=True)
        pre = box.cancel_mdm_migration(["SERIAL000"])
        box.cancel_mdm_migration(["SERIAL000"], confirm_token=pre["confirm_token"])
        path = box.cfg.audit_log
        text = path.read_text()
        events = [json.loads(line)["event"] for line in text.splitlines()]
        self.assertEqual(events, ["preview", "execute", "done"])
        self.assertNotIn(pre["confirm_token"], text)
        for t in self.server.issued:
            self.assertNotIn(t, text)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


class RegistrationTests(Base):
    def names(self, **kw):
        server = build_server(self.cfg(**kw))
        tools = asyncio.run(server.list_tools())
        tools = getattr(tools, "tools", tools)
        return {t.name: t for t in tools}

    def test_tier_registration(self):
        read_only = self.names()
        self.assertEqual(set(read_only), set(READ_TOOLS))
        write = self.names(enable_write=True)
        self.assertEqual(set(write), set(READ_TOOLS) | set(WRITE_TOOLS))
        full = self.names(enable_write=True, enable_destructive=True)
        self.assertEqual(set(full), set(READ_TOOLS) | set(WRITE_TOOLS) | set(DESTRUCTIVE_TOOLS))
        # destructive フラグだけでは何も増えない
        self.assertEqual(set(self.names(enable_destructive=True)), set(READ_TOOLS))

    def test_annotations(self):
        full = self.names(enable_write=True, enable_destructive=True)
        self.assertTrue(full["list_devices"].annotations.read_only_hint)
        self.assertFalse(full["assign_devices_to_mdm"].annotations.read_only_hint)
        self.assertTrue(full["release_devices"].annotations.destructive_hint)
        self.assertIn("device_ids", json.dumps(full["assign_devices_to_mdm"].input_schema
                                                if hasattr(full["assign_devices_to_mdm"], "input_schema")
                                                else full["assign_devices_to_mdm"].inputSchema))


if __name__ == "__main__":
    unittest.main()
