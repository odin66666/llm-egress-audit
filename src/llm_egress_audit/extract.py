"""Turn a raw request body into the pieces of content it carries.

Yields ("text", str) and ("blob", bytes). JSON is parsed so escaping disappears,
base64 and data: URLs are decoded, multipart uploads are split into files.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from email.parser import BytesParser
from email.policy import default as default_policy
from typing import Iterator, Optional, Tuple
from urllib.parse import parse_qsl

Part = Tuple[str, object]

_B64 = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_DATA_URL = re.compile(r"data:[^;,]{0,100};base64,", re.I)
MIN_B64 = 128


def _b64(s: str, minimum: int = MIN_B64) -> Optional[bytes]:
    # Only line breaks are tolerated (MIME wraps at 76 columns). Dropping spaces too would
    # turn ordinary text such as "1\tfoo bar" into a decodable alphanumeric run.
    s = s.strip().replace("\r", "").replace("\n", "")
    if len(s) < minimum or not _B64.fullmatch(s):
        return None
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def as_text(raw: bytes) -> Optional[str]:
    if b"\x00" in raw[:8192]:
        return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _from_blob(raw: bytes) -> Iterator[Part]:
    yield ("blob", raw)
    text = as_text(raw)
    if text is not None:
        yield ("text", text)


_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\", "/": "/"}
_ESCAPE = re.compile(r'\\(["\\/nrt])')
MAX_DEPTH = 4


def _unescape(s: str) -> str:
    return _ESCAPE.sub(lambda m: _ESCAPES[m.group(1)], s)


def _from_string(s: str, depth: int = 0) -> Iterator[Part]:
    # Some agents encode tool output twice (Codex: a JSON document inside a JSON string).
    # Without this, a literal backslash-n stays in the text and glues itself to the next word.
    if depth < MAX_DEPTH:
        docs = _json_documents(s)
        if docs is not None:
            for doc in docs:
                yield from _walk(doc, depth + 1)
            return
        if s.count("\\n") >= 2 or s.count('\\"') >= 2:
            yield ("text", _unescape(s))
    m = _DATA_URL.match(s)
    if m:
        raw = _b64(s[m.end():], minimum=4)
        if raw is not None:
            yield from _from_blob(raw)
            return
    raw = _b64(s)
    if raw is not None:
        yield from _from_blob(raw)
    # Always keep the string as text as well: a false base64 positive must never
    # hide real content.
    yield ("text", s)


def _walk(obj, depth: int = 0) -> Iterator[Part]:
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, str):
            yield from _from_string(o, depth)
        elif isinstance(o, dict):
            stack.extend(o.values())
        elif isinstance(o, list):
            stack.extend(o)


def _json_documents(text: str):
    """One JSON document, or NDJSON; None if the text is neither."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return [json.loads(stripped)]
    except ValueError:
        pass
    docs = []
    for line in stripped.splitlines():
        if line.strip():
            try:
                docs.append(json.loads(line))
            except ValueError:
                return None
    return docs


def _multipart(body: bytes, content_type: str) -> Iterator[Part]:
    header = b"Content-Type: " + content_type.encode("latin-1", "replace") + b"\r\n\r\n"
    msg = BytesParser(policy=default_policy).parsebytes(header + body)
    if not msg.is_multipart():
        yield from _from_blob(body)
        return
    for part in msg.iter_parts():
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename:
            yield ("text", filename)
            yield from _from_blob(payload)
        else:
            yield from iter_parts(payload, part.get_content_type())


def iter_parts(body: bytes, content_type: str = "") -> Iterator[Part]:
    if not body:
        return
    ct = (content_type or "").lower()
    if ct.startswith("multipart/"):
        yield from _multipart(body, content_type)
        return
    if "x-www-form-urlencoded" in ct:
        for _, value in parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True):
            yield from _from_string(value)
        return
    text = as_text(body)
    if text is None:
        yield ("blob", body)
        return
    docs = _json_documents(text)
    if docs is None:
        yield from _from_string(text)
        return
    for doc in docs:
        yield from _walk(doc)


def query_values(path_with_query: str) -> Iterator[str]:
    if "?" not in path_with_query:
        return
    for _, value in parse_qsl(path_with_query.split("?", 1)[1], keep_blank_values=False):
        yield value
