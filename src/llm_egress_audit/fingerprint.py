"""Keyed fingerprints of text, file names and binary blobs.

Nothing here is reversible: every fingerprint is a truncated HMAC-SHA256 under a
local secret key. The same normalisation runs on outgoing traffic and on the
files being verified, so the two sides meet only if the content really left.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
from typing import Iterable, List, Set, Tuple

SHINGLE = 8          # words per text window
SHORT_MIN = 3        # a whole string of 3..7 words still gets one fingerprint
CHUNK = 4096         # bytes per binary chunk

# Agents often prefix file lines with numbers ("   12\t...", "12→...", "12|...").
# Stripping them on both sides keeps numbered and raw copies comparable.
_LINE_PREFIX = re.compile(r"^[ \t]{0,8}\d{1,7}(?:\t|→|\|)", re.M)
_TOKEN = re.compile(r"\w+", re.UNICODE)
_NAME = re.compile(r"[^\s\"'<>|*?`()\[\]{},;]*\.[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*(?![A-Za-z0-9])")
_SEP = re.compile(r"[\\/]")

_D_TEXT, _D_NAME, _D_BLOB, _D_CHUNK, _D_PATH = b"t", b"n", b"b", b"c", b"p"


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return _LINE_PREFIX.sub("", text).casefold()


def tokens(text: str) -> List[str]:
    return _TOKEN.findall(normalize(text))


def tokens_with_lines(text: str) -> Tuple[List[str], List[int]]:
    """Tokens plus the 1-based source line of each one (same stream as tokens())."""
    toks: List[str] = []
    lines: List[int] = []
    for lineno, line in enumerate(normalize(text).split("\n"), start=1):
        for tok in _TOKEN.findall(line):
            toks.append(tok)
            lines.append(lineno)
    return toks, lines


def normalize_name(name: str) -> str:
    return unicodedata.normalize("NFKC", name).strip().casefold()


def normalize_path(path: str) -> str:
    return normalize_name(path.replace("\\", "/")).rstrip("/")


def name_candidates(text: str, max_words: int = 4, limit: int = 2000) -> Set[str]:
    """Everything in `text` that could be a file name, including names with spaces."""
    out: Set[str] = set()
    for m in _NAME.finditer(text):
        if len(out) >= limit:
            break
        token = m.group(0)
        base = _SEP.split(token)[-1]
        if base and base != ".":
            out.add(base)
        if _SEP.search(token):
            continue
        prefix = text[max(0, m.start() - 200):m.start()]
        if not prefix.endswith(" "):
            continue
        acc = token
        for word in reversed(prefix[:-1].split(" ")[-max_words:]):
            if not word:
                break
            acc = word + " " + acc
            out.add(_SEP.split(acc)[-1])
            if _SEP.search(word):
                break
    return out


class Hasher:
    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("key must be at least 32 bytes")
        self._key = key

    def _h(self, domain: bytes, data: bytes) -> int:
        digest = hmac.new(self._key, domain + b"\x00" + data, hashlib.sha256).digest()
        return int.from_bytes(digest[:8], "big", signed=True)

    # -- text -------------------------------------------------------------
    def shingle(self, words: Iterable[str]) -> int:
        return self._h(_D_TEXT, " ".join(words).encode("utf-8"))

    def text_hashes(self, text: str) -> Set[int]:
        toks = tokens(text)
        if len(toks) < SHINGLE:
            return {self.shingle(toks)} if len(toks) >= SHORT_MIN else set()
        return {self.shingle(toks[i:i + SHINGLE]) for i in range(len(toks) - SHINGLE + 1)}

    # -- names and paths --------------------------------------------------
    def name(self, name: str) -> int:
        return self._h(_D_NAME, normalize_name(name).encode("utf-8"))

    def name_hashes(self, text: str) -> Set[int]:
        return {self.name(c) for c in name_candidates(text)}

    def path(self, path: str) -> int:
        return self._h(_D_PATH, normalize_path(path).encode("utf-8"))

    # -- binary -----------------------------------------------------------
    def blob(self, data: bytes) -> int:
        return self._h(_D_BLOB, hashlib.sha256(data).digest())

    def chunk_hashes(self, data: bytes) -> List[int]:
        return [self._h(_D_CHUNK, data[i:i + CHUNK])
                for i in range(0, len(data) - CHUNK + 1, CHUNK)]

    def blob_hashes(self, data: bytes) -> Set[int]:
        return {self.blob(data), *self.chunk_hashes(data)}

    # -- self check -------------------------------------------------------
    def key_check(self) -> str:
        return hmac.new(self._key, b"llm-egress-audit key check", hashlib.sha256).hexdigest()[:16]
