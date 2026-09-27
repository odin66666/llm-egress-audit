import base64
import gzip
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from llm_egress_audit.recorder import Event, Recorder
from llm_egress_audit.store import KeyMismatch, Store
from llm_egress_audit.verify import verify_file

SECRET = "\n".join(
    f"Line {i}: the quarterly forecast for project nightingale assumes {i * 37} units "
    f"shipped through the northern warehouse before the audit window closes"
    for i in range(1, 41)
)


def claude_style(text: str) -> str:
    """How Claude Code's Read tool returns a file: cat -n with tab separators."""
    return "\n".join(f"{n:>6}\t{line}" for n, line in enumerate(text.split("\n"), start=1))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.store = Store(self.dir / "db.sqlite3", secrets.token_bytes(32))
        self.rec = Recorder(self.store, threaded=False)
        self.file = self.dir / "forecast notes.txt"
        self.file.write_bytes(SECRET.encode("utf-8"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def send(self, body, host="api.anthropic.com", ct="application/json", path="/v1/messages",
             client="claude-cli/2.1"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.rec.submit(Event(1_800_000_000.0, host, client, "POST", path, ct, body))

    def grade(self, path=None):
        return verify_file(self.store, path or self.file)


class TestGrades(Base):
    def test_nothing_sent_is_grade_0(self):
        self.send({"messages": [{"role": "user", "content": "hello there, how are you today"}]})
        self.assertEqual(self.grade().grade, 0)

    def test_full_file_through_claude_read_tool_is_grade_4(self):
        self.send({"messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "x", "content": claude_style(SECRET)}]}]})
        r = self.grade()
        self.assertEqual(r.grade, 4)
        self.assertEqual(r.coverage, 1.0)
        self.assertEqual(r.content_sent_to[0].host, "api.anthropic.com")
        self.assertTrue(r.content_sent_to[0].is_llm)

    def test_partial_reports_lines(self):
        part = "\n".join(SECRET.split("\n")[10:20])
        self.send({"input": [{"role": "user", "content": part}]}, host="api.openai.com")
        r = self.grade()
        self.assertEqual(r.grade, 3)
        self.assertEqual(r.confidence, "strong")
        self.assertEqual(r.exposed_lines, [(11, 20)])
        self.assertLess(r.coverage, 0.9)

    def test_name_only_is_grade_2(self):
        self.send({"contents": [{"parts": [{"text": "list: C:\\Users\\me\\docs\\forecast notes.txt"}]}]},
                  host="generativelanguage.googleapis.com")
        self.assertEqual(self.grade().grade, 2)

    def test_blocked_is_grade_1(self):
        self.store.log_block("claude-code", str(self.file.resolve()), "PreToolUse deny")
        r = self.grade()
        self.assertEqual(r.grade, 1)
        self.assertEqual(r.blocked[0]["tool"], "claude-code")

    def test_alphanumeric_text_is_not_mistaken_for_base64(self):
        # Regression, found with a real agent session: once whitespace was stripped
        # this read like base64 and the text was never fingerprinted.
        words = [f"umber{i}" for i in range(40)]
        text = "canary aa0b1eef\n" + "\n".join(" ".join(words[i:i + 10]) for i in range(0, 40, 10))
        for pad in range(4):
            f = self.dir / f"c{pad}.txt"
            body = text + " x" * pad
            f.write_bytes(body.encode())
            numbered = "".join(f"{n}\t{l}\n" for n, l in enumerate(body.split("\n"), start=1))
            self.send({"messages": [{"content": [{"type": "tool_result", "content": numbered}]}]},
                      client=f"c{pad}")
            self.assertEqual(self.grade(f).grade, 4, f"pad={pad}")

    def test_double_encoded_tool_output(self):
        # Codex sends shell output as a JSON document inside a JSON string, with CRLF.
        inner = json.dumps({"output": SECRET.replace("\n", "\r\n"), "metadata": {"exit_code": 0}})
        self.send({"type": "response.create", "input": [
            {"type": "function_call_output", "call_id": "c1", "output": inner}]},
            host="chatgpt.com", path="/backend-api/codex/responses")
        r = self.grade()
        self.assertEqual(r.grade, 4)
        self.assertEqual(r.coverage, 1.0)

    def test_leftover_literal_escapes(self):
        # Escaped text that is not valid JSON on its own (a log line, a truncated payload).
        escaped = "log: " + json.dumps(SECRET)[1:-1] + " [truncated"
        self.send({"events": [{"message": escaped}]}, host="example.org")
        self.assertEqual(self.grade().coverage, 1.0)

    def test_whitespace_and_case_changes_still_match(self):
        mangled = SECRET.upper().replace("\n", "  \r\n   ").replace(" ", "   ")
        self.send({"prompt": mangled}, host="openrouter.ai")
        self.assertEqual(self.grade().grade, 4)


class TestEncodings(Base):
    def test_base64_attachment(self):
        b64 = base64.b64encode(SECRET.encode()).decode()
        self.send({"messages": [{"content": [{"type": "document", "source": {
            "type": "base64", "media_type": "text/plain", "data": b64}}]}]})
        r = self.grade()
        self.assertEqual(r.grade, 4)
        self.assertTrue(r.whole_file_seen)

    def test_binary_data_url(self):
        png = self.dir / "photo.png"
        blob = b"\x89PNG\r\n\x1a\n" + secrets.token_bytes(20000)
        png.write_bytes(blob)
        url = "data:image/png;base64," + base64.b64encode(blob).decode()
        self.send({"messages": [{"content": [{"type": "image_url", "image_url": {"url": url}}]}]})
        r = self.grade(png)
        self.assertEqual(r.grade, 4)
        self.assertEqual(r.kind, "binary")

    def test_truncated_binary_is_partial(self):
        blob = secrets.token_bytes(40960)
        f = self.dir / "dump.bin"
        f.write_bytes(blob)
        self.send({"data": base64.b64encode(blob[:16384]).decode()})
        r = self.grade(f)
        self.assertEqual(r.grade, 3)
        self.assertEqual(r.matched, 4)

    def test_multipart_upload(self):
        boundary = "XyZ123"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nassistants\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\n"
                f"Content-Type: text/plain\r\n\r\n{SECRET}\r\n--{boundary}--\r\n").encode()
        self.send(body, host="api.openai.com", ct=f"multipart/form-data; boundary={boundary}",
                  path="/v1/files")
        self.assertEqual(self.grade().grade, 4)

    def test_ndjson_and_query_string(self):
        lines = "\n".join(json.dumps({"t": l}) for l in SECRET.split("\n")[:5])
        self.send(lines.encode(), ct="application/x-ndjson")
        self.assertEqual(self.grade().grade, 3)

    def test_query_string_values_are_checked_and_not_stored(self):
        q = "?q=" + "+".join(SECRET.split("\n")[0].split()) + "&key=SECRETKEY"
        self.send(b"", path="/search" + q, host="example.org")
        self.assertEqual(self.grade().grade, 3)
        paths = [r[0] for r in self.store.db.execute("SELECT path FROM requests")]
        self.assertEqual(paths, ["/search"])


class TestStore(Base):
    def test_no_plaintext_in_database(self):
        self.send({"messages": [{"content": SECRET}]})
        self.store.db.commit()
        raw = (self.dir / "db.sqlite3").read_bytes()
        for wal in self.dir.glob("db.sqlite3-*"):
            raw += wal.read_bytes()
        for word in ("nightingale", "warehouse", "forecast"):
            self.assertNotIn(word.encode(), raw.lower())

    def test_repeated_context_keeps_first_exposure(self):
        body = {"messages": [{"content": SECRET}]}
        self.rec.submit(Event(100.0, "api.anthropic.com", "c", "POST", "/v1/messages", "application/json",
                              json.dumps(body).encode()))
        self.rec.submit(Event(200.0, "api.anthropic.com", "c", "POST", "/v1/messages", "application/json",
                              json.dumps(body).encode()))
        r = self.grade()
        self.assertEqual(r.content_sent_to[0].first_ts, 100.0)
        n = self.store.db.execute("SELECT new_hashes FROM requests ORDER BY id").fetchall()
        self.assertGreater(n[0][0], 0)
        self.assertEqual(n[1][0], 0)

    def test_two_destinations_are_both_reported(self):
        self.send({"m": SECRET}, host="api.anthropic.com")
        self.send({"m": SECRET}, host="api.deepseek.com")
        hosts = {e.host for e in self.grade().content_sent_to}
        self.assertEqual(hosts, {"api.anthropic.com", "api.deepseek.com"})

    def test_wrong_key_is_refused(self):
        self.store.close()
        with self.assertRaises(KeyMismatch):
            Store(self.dir / "db.sqlite3", secrets.token_bytes(32))
        self.store = Store.__new__(Store)
        self.store.close = lambda: None

    def test_unanalysable_body_is_counted(self):
        self.rec.fingerprints = lambda e: (_ for _ in ()).throw(ValueError("boom"))
        os.environ["LLM_EGRESS_AUDIT_HOME"] = str(self.dir)
        try:
            self.send({"m": "x"})
        finally:
            del os.environ["LLM_EGRESS_AUDIT_HOME"]
        self.assertEqual(self.store.window()[3], 1)


class TestAddon(Base):
    def test_gzip_request_through_addon(self):
        from llm_egress_audit import addon as addon_mod

        a = addon_mod.EgressAudit()
        a.recorder = self.rec
        raw = gzip.compress(json.dumps({"messages": [{"content": SECRET}]}).encode())

        class Req:
            pretty_host = "api.anthropic.com"
            method = "POST"
            path = "/v1/messages?beta=true"
            headers = {"user-agent": "claude-cli/2.1", "content-type": "application/json"}

            def get_content(self, strict=True):
                return gzip.decompress(raw)     # mitmproxy decodes Content-Encoding

        a.request(SimpleNamespace(request=Req()))
        self.assertEqual(self.grade().grade, 4)


if __name__ == "__main__":
    unittest.main()


class TestCategories(Base):
    def test_categorize(self):
        from llm_egress_audit.categories import categorize
        cases = {
            ("api.anthropic.com", "/v1/messages?beta=true"): "llm",
            ("api.anthropic.com", "/api/event_logging/v2/batch"): "telemetry",
            ("api.anthropic.com", "/api/oauth/account/settings"): "auth",
            ("api.anthropic.com", "/v1/mcp_servers"): "tools/mcp",
            ("chatgpt.com", "/backend-api/codex/responses"): "llm",
            ("api.openai.com", "/v1/files"): "llm",
            ("cloudcode-pa.googleapis.com", "/v1internal:streamGenerateContent"): "llm",
            ("http-intake.logs.us5.datadoghq.com", "/api/v2/logs"): "telemetry",
            ("o123.ingest.sentry.io", "/api/1/envelope/"): "error-reporting",
            ("pastebin.com", "/api/api_post.php"): "cloud-storage",
            ("api.github.com", "/repos/x/y"): "dev-services",
            ("example.org", "/"): "other",
        }
        for (host, path), expected in cases.items():
            self.assertEqual(categorize(host, path), expected, f"{host}{path}")

    def test_same_client_prompt_then_telemetry_both_reported(self):
        self.send({"messages": [{"content": SECRET}]}, path="/v1/messages")
        self.send({"events": [{"payload": SECRET}]}, path="/api/event_logging/v2/batch")
        r = self.grade()
        self.assertEqual(r.categories, ["llm", "telemetry"])
        self.assertEqual({e.category for e in r.content_sent_to}, {"llm", "telemetry"})
