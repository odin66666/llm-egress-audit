"""mitmproxy addon. Loaded with: mitmdump -s <this file>

Records every client->server HTTP body and WebSocket message that crosses the
proxy. Response bodies are ignored: they come from the provider, not from you.

With protected paths configured (and LLM_EGRESS_AUDIT_GUARD not set to 0), each
request is checked *before* it is forwarded, and requests carrying protected
content are answered locally with 403 instead of being sent.
"""
from __future__ import annotations

import json
import os
import sys
import time

try:
    from llm_egress_audit.recorder import Event, Recorder
except ImportError:  # executed as a bare script by mitmdump from a source checkout
    import pathlib

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from llm_egress_audit.recorder import Event, Recorder

from llm_egress_audit.guard import Guard, Verdict
from llm_egress_audit.store import Store

# Kept generic on purpose: an agent may paste this error into its next prompt, and
# the name of a protected file is itself information.
BLOCK_MESSAGE = (
    "Blocked by llm-egress-audit: this request contains content from a protected file and "
    "was not sent. The content is now in this conversation's context, so every further "
    "request from this session will be blocked too: start a new session."
)


def _block_body() -> bytes:
    return json.dumps({
        "type": "error",
        "error": {"type": "permission_error", "code": "egress_blocked", "message": BLOCK_MESSAGE},
    }).encode()


def _make_response(status: int, body: bytes, headers: dict):
    from mitmproxy import http
    return http.Response.make(status, body, headers)


def _close_websocket(flow) -> None:
    """Close a live WebSocket on both sides.

    flow.kill() does not do it: mitmproxy cannot kill a WebSocket in transit
    (mitmproxy issue #4711), so the socket stays open and the agent waits forever.
    Feeding the connection handler a "client closed" event makes mitmproxy's own
    WebSocket layer send close frames both ways and drop both connections.
    """
    from mitmproxy import ctx
    from mitmproxy.proxy import events
    from mitmproxy.utils import asyncio_utils

    proxyserver = ctx.master.addons.get("proxyserver")
    handler = proxyserver.connections.get(flow.client_conn.id)
    if handler is None:
        return
    asyncio_utils.create_task(
        handler.server_event(events.ConnectionClosed(handler.client)),
        name="llm-egress-audit close websocket",
        keep_ref=True,
        client=flow.client_conn.peername,
    )


class EgressAudit:
    def __init__(self) -> None:
        self.recorder = None
        self.guard = None
        self.make_response = _make_response
        self.close_websocket = _close_websocket

    def _rec(self):
        if self.recorder is None:
            self.recorder = Recorder.open_default()
        return self.recorder

    def _start_guard(self) -> None:
        if os.environ.get("LLM_EGRESS_AUDIT_GUARD", "1") == "0":
            return
        # Always on, even with nothing protected yet: paths added with `protect` while the
        # proxy runs are picked up by the periodic rescan.
        guard = Guard(Store.open_default())
        guard.scan()           # synchronous: no request may pass before the index exists
        self.guard = guard
        sys.stderr.write(f"[llm-egress-audit] guard ON: {len(guard.files)} protected file(s)\n")
        for w in guard.warnings:
            sys.stderr.write(f"[llm-egress-audit] {w}\n")

    def running(self) -> None:
        self._rec()
        self._start_guard()

    def _event(self, flow, body: bytes, method: str, content_type: str) -> Event:
        req = flow.request
        return Event(
            ts=time.time(),
            host=req.pretty_host,
            client=req.headers.get("user-agent", ""),
            method=method,
            path=req.path,
            content_type=content_type,
            body=body,
        )

    def _verdict(self, event: Event) -> Verdict:
        if self.guard is None:
            return Verdict(False)
        self.guard.maybe_rescan()
        verdict = self.guard.check(event)
        if verdict.blocked:
            self.guard.log(verdict, event)
            what = verdict.error or ", ".join(f"{p} ({n}/{t})" for p, n, t in verdict.files)
            sys.stderr.write(f"[llm-egress-audit] BLOCKED {event.method} {event.host}"
                             f"{event.path.split('?', 1)[0]}: {what}\n")
        return verdict

    def request(self, flow) -> None:
        req = flow.request
        event = self._event(flow, req.get_content(strict=False) or b"", req.method,
                            req.headers.get("content-type", ""))
        if self._verdict(event).blocked:
            flow.response = self.make_response(403, _block_body(), {"content-type": "application/json"})
            return
        self._rec().submit(event)

    def websocket_message(self, flow) -> None:
        msg = flow.websocket.messages[-1]
        if not msg.from_client:
            return
        ct = "application/json" if msg.is_text else "application/octet-stream"
        event = self._event(flow, msg.content, "WS", ct)
        if self._verdict(event).blocked:
            msg.drop()         # this alone already keeps the content from leaving
            try:
                self.close_websocket(flow)   # so the agent sees an error instead of hanging
            except Exception as exc:
                sys.stderr.write(f"[llm-egress-audit] could not close the WebSocket "
                                 f"(message was dropped anyway): {exc}\n")
            return
        self._rec().submit(event)

    def done(self) -> None:
        if self.recorder is not None:
            self.recorder.close()
            self.recorder = None
        if self.guard is not None:
            self.guard.store.close()
            self.guard = None


addons = [EgressAudit()]
