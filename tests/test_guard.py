import json
import os
import time
import unittest
from types import SimpleNamespace

from llm_egress_audit import addon as addon_mod
from llm_egress_audit.guard import Guard
from llm_egress_audit.recorder import Event
from llm_egress_audit.verify import verify_file

from test_core import SECRET, Base, claude_style


class FakeReq:
    def __init__(self, body, host="api.anthropic.com", path="/v1/messages"):
        self.pretty_host = host
        self.method = "POST"
        self.path = path
        self.headers = {"user-agent": "claude-cli/2.1", "content-type": "application/json"}
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def get_content(self, strict=True):
        return self._body


class FakeMsg:
    def __init__(self, content):
        self.from_client = True
        self.is_text = True
        self.content = content
        self.dropped = False

    def drop(self):
        self.dropped = True


class GuardBase(Base):
    def setUp(self):
        super().setUp()
        self.store.protect(str(self.file.resolve()))
        self.guard = Guard(self.store)
        self.guard.scan()
        self.addon = addon_mod.EgressAudit()
        self.addon.recorder = self.rec
        self.addon.guard = self.guard
        self.addon.make_response = lambda status, body, headers: SimpleNamespace(
            status_code=status, content=body)

    def http(self, body, **kw):
        flow = SimpleNamespace(request=FakeReq(body, **kw), response=None)
        self.addon.request(flow)
        return flow


class TestGuard(GuardBase):
    def test_protected_content_is_blocked_and_never_recorded(self):
        flow = self.http({"messages": [{"content": [
            {"type": "tool_result", "content": claude_style(SECRET)}]}]})
        self.assertEqual(flow.response.status_code, 403)
        self.assertIn(b"egress_blocked", flow.response.content)
        self.assertNotIn(b"forecast notes", flow.response.content)   # no file name to the agent
        r = verify_file(self.store, self.file)
        self.assertEqual(r.grade, 1)
        self.assertIn("/v1/messages", r.blocked[0]["detail"])
        self.assertEqual(self.store.window()[2], 0)                   # nothing went out

    def test_unrelated_request_passes(self):
        flow = self.http({"messages": [{"content": "what is the capital of France, briefly please"}]})
        self.assertIsNone(flow.response)
        self.assertEqual(self.store.window()[2], 1)

    def test_one_shared_phrase_does_not_block(self):
        words = SECRET.split("\n")[0].split()[:9]         # exactly two 8-word windows
        flow = self.http({"messages": [{"content": "x " + " ".join(words) + " y"}]})
        self.assertIsNone(flow.response)

    def test_three_lines_are_enough_to_block(self):
        part = "\n".join(SECRET.split("\n")[5:8])
        self.assertEqual(self.http({"m": part}).response.status_code, 403)

    def test_double_encoded_codex_output_is_blocked(self):
        inner = json.dumps({"output": SECRET.replace("\n", "\r\n")})
        flow = self.http({"input": [{"type": "function_call_output", "output": inner}]},
                         host="chatgpt.com", path="/backend-api/codex/responses")
        self.assertEqual(flow.response.status_code, 403)

    def test_websocket_message_is_dropped_and_socket_closed(self):
        msg = FakeMsg(json.dumps({"input": SECRET}).encode())
        closed = []
        self.addon.close_websocket = closed.append
        flow = SimpleNamespace(request=FakeReq(b"", host="chatgpt.com"),
                               websocket=SimpleNamespace(messages=[msg]))
        self.addon.websocket_message(flow)
        self.assertTrue(msg.dropped)
        self.assertEqual(closed, [flow])

    def test_websocket_still_dropped_if_close_fails(self):
        msg = FakeMsg(json.dumps({"input": SECRET}).encode())
        self.addon.close_websocket = lambda flow: 1 / 0
        flow = SimpleNamespace(request=FakeReq(b"", host="chatgpt.com"),
                               websocket=SimpleNamespace(messages=[msg]))
        self.addon.websocket_message(flow)
        self.assertTrue(msg.dropped)

    def test_folder_protection_and_rescan_sees_edits(self):
        folder = self.dir / "vault"
        folder.mkdir()
        f = folder / "new.txt"
        f.write_bytes(b"old content that nobody cares about at all really " * 3)
        self.store.protect(str(folder.resolve()))
        self.guard.scan()
        secret2 = "the launch code for the orbital platform is hidden under the blue stone " * 2
        f.write_bytes(secret2.encode())
        os.utime(f, (time.time() + 5, time.time() + 5))
        self.assertIsNone(self.http({"m": secret2}).response)      # not yet rescanned
        self.guard.scan()
        self.assertEqual(self.http({"m": secret2}).response.status_code, 403)

    def test_unprotect(self):
        self.store.unprotect(str(self.file.resolve()))
        self.guard.scan()
        self.assertIsNone(self.http({"m": SECRET}).response)

    def test_fails_closed(self):
        self.guard.hasher.text_hashes = lambda text: (_ for _ in ()).throw(RuntimeError("x"))
        self.guard._cache.clear()
        flow = self.http({"m": "anything at all, even harmless text"})
        self.assertEqual(flow.response.status_code, 403)
        self.assertIn("guard error", self.store.db.execute("SELECT detail FROM blocked").fetchone()[0])

    def test_binary_protected_file(self):
        import base64
        import secrets
        blob = secrets.token_bytes(10000)
        b = self.dir / "scan.pdf"
        b.write_bytes(blob)
        self.store.protect(str(b.resolve()))
        self.guard.scan()
        flow = self.http({"document": {"data": base64.b64encode(blob).decode()}})
        self.assertEqual(flow.response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
