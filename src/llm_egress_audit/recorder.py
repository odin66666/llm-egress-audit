"""Fingerprint outgoing requests off the proxy's event loop.

Agents resend the whole conversation on every turn, so the same strings cross the
wire hundreds of times. Strings already recorded for a destination are skipped by
digest; only their first exposure matters and that one is already stored.
"""
from __future__ import annotations

import hashlib
import queue
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple

from . import config
from .categories import categorize
from .extract import iter_parts, query_values
from .store import Store

SEEN_CAP = 1_000_000


@dataclass
class Event:
    ts: float
    host: str
    client: str
    method: str
    path: str          # may include the query string; it is stripped before storage
    content_type: str
    body: bytes


class Recorder:
    def __init__(self, store: Store, threaded: bool = True):
        self.store = store
        self.hasher = store.hasher
        self._seen: Dict[Tuple[str, str, str], Set[bytes]] = {}
        self._queue: "queue.Queue[Optional[Event]]" = queue.Queue(maxsize=2000)
        self._thread: Optional[threading.Thread] = None
        self.errors = 0
        if threaded:
            self._thread = threading.Thread(target=self._run, name="egress-recorder", daemon=True)
            self._thread.start()

    @classmethod
    def open_default(cls) -> "Recorder":
        return cls(Store.open_default())

    def submit(self, event: Event) -> None:
        if self._thread is None:
            self.process(event)
        else:
            # Blocking on purpose: slowing traffic down is better than losing evidence.
            self._queue.put(event)

    def close(self) -> None:
        if self._thread is not None:
            self._queue.put(None)
            self._thread.join()
            self._thread = None
        self.store.close()

    def _run(self) -> None:
        while True:
            event = self._queue.get()
            if event is None:
                return
            self.process(event)

    def _new(self, dest: Tuple[str, str, str], kind: bytes, data: bytes) -> bool:
        seen = self._seen.setdefault(dest, set())
        digest = hashlib.blake2b(kind + data, digest_size=16).digest()
        if digest in seen:
            return False
        if len(seen) >= SEEN_CAP:
            seen.clear()
        seen.add(digest)
        return True

    @staticmethod
    def dest_key(event: Event) -> Tuple[str, str, str]:
        return (event.host, event.client[:200], categorize(event.host, event.path))

    def fingerprints(self, event: Event) -> Set[int]:
        dest = self.dest_key(event)
        hashes: Set[int] = set()
        texts = list(query_values(event.path))
        for kind, value in iter_parts(event.body, event.content_type):
            if kind == "text":
                texts.append(value)
            elif self._new(dest, b"b", value):
                hashes |= self.hasher.blob_hashes(value)
        for text in texts:
            if self._new(dest, b"t", text.encode("utf-8", "surrogatepass")):
                hashes |= self.hasher.text_hashes(text)
                hashes |= self.hasher.name_hashes(text)
        return hashes

    def process(self, event: Event) -> None:
        path = event.path.split("?", 1)[0]
        try:
            hashes = self.fingerprints(event)
        except Exception:
            self.errors += 1
            self._log_error(event)
            hashes = None
        try:
            self.store.record(event.ts, event.host, event.client[:200], event.method,
                              path[:500], len(event.body), hashes, self.dest_key(event)[2])
        except Exception:
            # The strings were marked as seen but never stored: forget them so the next
            # request carrying them records the exposure.
            self._seen.pop(self.dest_key(event), None)
            self.errors += 1
            self._log_error(event)

    def _log_error(self, event: Event) -> None:
        line = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} {event.method} {event.host}"
                f"{event.path.split('?', 1)[0]}\n{traceback.format_exc()}\n")
        sys.stderr.write("[llm-egress-audit] " + line)
        try:
            with open(config.home() / "errors.log", "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass
