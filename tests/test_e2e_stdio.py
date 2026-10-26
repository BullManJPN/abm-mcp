"""実際に stdio で MCP サーバーを起動し、MCP クライアントとして通しで確認する。"""
import asyncio
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from fake_apple import CLIENT_ID, KEY_ID  # noqa: E402
from test_abm import Base  # noqa: E402

SRC = str(Path(__file__).resolve().parents[1] / "src")


def text(result) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


class StdioEndToEnd(Base):
    def env(self, **extra):
        env = dict(
            os.environ, PYTHONPATH=SRC, ABM_CLIENT_ID=CLIENT_ID, ABM_KEY_ID=KEY_ID,
            ABM_PRIVATE_KEY_PATH=str(self.key_path), ABM_API_BASE=self.server.base,
            ABM_TOKEN_URL=self.server.base + "/auth/oauth2/token", ABM_ALLOW_INSECURE="1",
            ABM_HOME=self.dir.name,
        )
        env.update(extra)
        return env

    async def _session(self, env, scenario):
        params = StdioServerParameters(command=sys.executable, args=["-m", "abm_mcp"], env=env)
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                return await scenario(s)

    def run_scenario(self, scenario, **extra):
        return asyncio.run(self._session(self.env(**extra), scenario))

    def test_full_flow_and_error_messages_reach_the_model(self):
        async def scenario(s):
            out = {}
            out["tools"] = {t.name for t in (await s.list_tools()).tools}
            out["conn"] = json.loads(text(await s.call_tool("check_connection", {})))
            out["devices"] = json.loads(text(await s.call_tool("list_devices", {"max_items": 3})))
            pre = json.loads(text(await s.call_tool(
                "assign_devices_to_mdm", {"server_id": "SRV1", "device_ids": ["SERIAL000"]})))
            out["pre"] = pre
            out["posts_after_preview"] = len(self.posts("/v1/orgDeviceActivities"))
            out["done"] = json.loads(text(await s.call_tool(
                "assign_devices_to_mdm",
                {"server_id": "SRV1", "device_ids": ["SERIAL000"], "confirm_token": pre["confirm_token"]})))
            out["bad_id"] = await s.call_tool("get_device", {"device_id": "../etc/passwd"})
            out["not_found"] = await s.call_tool("get_device", {"device_id": "NOPE"})
            out["bad_token"] = await s.call_tool(
                "assign_devices_to_mdm",
                {"server_id": "SRV1", "device_ids": ["SERIAL001"], "confirm_token": "wrong"})
            return out

        out = self.run_scenario(scenario, ABM_ENABLE_WRITE="1")
        self.assertTrue(out["conn"]["ok"])
        self.assertEqual(out["devices"]["count"], 3)
        self.assertEqual(out["pre"]["status"], "preview")
        self.assertEqual(out["posts_after_preview"], 0)
        self.assertEqual(out["done"]["result"]["data"]["id"], "act-1")
        # 失敗の理由が Claude に見える（"Error executing tool ..." だけにならない）
        self.assertTrue(out["bad_id"].is_error)
        self.assertIn("device_id", text(out["bad_id"]))
        self.assertTrue(out["not_found"].is_error)
        self.assertIn("404", text(out["not_found"]))
        self.assertIn("NOT_FOUND", text(out["not_found"]))
        self.assertTrue(out["bad_token"].is_error)
        self.assertIn("確認トークン", text(out["bad_token"]))
        self.assertNotIn("release_devices", out["tools"])

    def test_write_tools_absent_when_disabled(self):
        async def scenario(s):
            return {t.name for t in (await s.list_tools()).tools}

        names = self.run_scenario(scenario)
        self.assertIn("list_devices", names)
        self.assertNotIn("assign_devices_to_mdm", names)

    def test_missing_config_exits_with_message(self):
        import subprocess

        env = {k: v for k, v in os.environ.items() if not k.startswith("ABM_")}
        env["PYTHONPATH"] = SRC
        proc = subprocess.run([sys.executable, "-m", "abm_mcp"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("ABM_CLIENT_ID", proc.stderr)
        self.assertEqual(proc.stdout, "")  # 標準出力は MCP 専用


if __name__ == "__main__":
    unittest.main()
