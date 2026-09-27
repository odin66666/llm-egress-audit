"""Guard mode: stop requests that carry content from protected files.

The check runs *before* a request is forwarded, on the proxy's own thread, so a
blocked request never leaves the machine. It fails closed: if the check itself
breaks, the request is blocked, because a guard that lets traffic through on error
protects nothing.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .categories import categorize
from .extract import as_text, iter_parts, query_values
from .fingerprint import Hasher
from .recorder import Event
from .store import Store

MIN_MATCHES = 3                 # distinct 8-word windows needed to block (fewer for tiny files)
MAX_FILE_BYTES = 100 * 1024 * 1024
RESCAN_SECONDS = 15.0
CACHE_CAP = 200_000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


@dataclass
class ProtectedFile:
    path: str
    total: int                  # fingerprints of this file
    mtime: float
    size: int
    hashes: FrozenSet[int] = field(default=frozenset(), repr=False)


@dataclass
class Verdict:
    blocked: bool
    files: List[Tuple[str, int, int]] = field(default_factory=list)   # (path, matched, total)
    error: Optional[str] = None


def expand(paths: List[str]) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                out.extend(Path(root) / f for f in files)
        elif path.is_file():
            out.append(path)
    return out


def file_fingerprints(hasher: Hasher, data: bytes) -> Set[int]:
    hashes = hasher.blob_hashes(data)
    text = as_text(data)
    if text is not None:
        hashes |= hasher.text_hashes(text)
    return hashes


class Guard:
    def __init__(self, store: Store, min_matches: int = MIN_MATCHES):
        self.store = store
        self.hasher = store.hasher
        self.min_matches = min_matches
        self._lock = threading.Lock()
        self._db_lock = threading.Lock()      # the proxy thread and the rescan thread share a connection
        self._index: Dict[int, FrozenSet[int]] = {}      # fingerprint -> file ids
        self._files: List[ProtectedFile] = []
        self._cache: Dict[bytes, FrozenSet[int]] = {}    # content digest -> protected fingerprints in it
        self._last_scan = 0.0
        self._scanning = False
        self.warnings: List[str] = []

    # -- index --------------------------------------------------------------
    def roots(self) -> List[str]:
        with self._db_lock:
            return self.store.protected()

    def scan(self) -> None:
        """Rebuild the index from disk. Unchanged files are reused, not re-read."""
        previous = {f.path: f for f in self._files}
        files: List[ProtectedFile] = []
        index: Dict[int, Set[int]] = {}
        warnings: List[str] = []
        for path in expand(self.roots()):
            try:
                st = path.stat()
            except OSError:
                continue
            key = str(path.resolve())
            if st.st_size > MAX_FILE_BYTES:
                warnings.append(f"not protected (over {MAX_FILE_BYTES // 2**20} MiB): {key}")
                continue
            fid = len(files)
            prev = previous.get(key)
            if prev and prev.mtime == st.st_mtime and prev.size == st.st_size:
                hashes = prev.hashes
            else:
                try:
                    hashes = frozenset(file_fingerprints(self.hasher, path.read_bytes()))
                except OSError as exc:
                    warnings.append(f"not protected (unreadable: {exc}): {key}")
                    continue
            files.append(ProtectedFile(key, len(hashes), st.st_mtime, st.st_size, hashes))
            for h in hashes:
                index.setdefault(h, set()).add(fid)
        frozen = {h: frozenset(ids) for h, ids in index.items()}
        with self._lock:
            changed = frozen != self._index
            self._index, self._files, self.warnings = frozen, files, warnings
            if changed:
                self._cache.clear()
            self._last_scan = time.time()

    def maybe_rescan(self) -> None:
        """Pick up edited and newly added files without blocking traffic."""
        if self._scanning or time.time() - self._last_scan < RESCAN_SECONDS:
            return
        self._scanning = True

        def run():
            try:
                self.scan()
            finally:
                self._scanning = False

        threading.Thread(target=run, name="guard-rescan", daemon=True).start()

    @property
    def files(self) -> List[ProtectedFile]:
        return list(self._files)

    # -- check --------------------------------------------------------------
    def _protected_in(self, kind: bytes, value) -> FrozenSet[int]:
        data = value.encode("utf-8", "surrogatepass") if isinstance(value, str) else value
        digest = hashlib.blake2b(kind + data, digest_size=16).digest()
        cached = self._cache.get(digest)
        if cached is not None:
            return cached
        index = self._index
        hashes = self.hasher.text_hashes(value) if kind == b"t" else self.hasher.blob_hashes(value)
        found = frozenset(h for h in hashes if h in index)
        if len(self._cache) >= CACHE_CAP:
            self._cache.clear()
        self._cache[digest] = found
        return found

    def check(self, event: Event) -> Verdict:
        try:
            with self._lock:
                index, files = self._index, self._files
                if not index:
                    return Verdict(False)
                seen: Set[int] = set()
                for value in query_values(event.path):
                    seen |= self._protected_in(b"t", value)
                for kind, value in iter_parts(event.body, event.content_type):
                    seen |= self._protected_in(b"t" if kind == "text" else b"b", value)
            per_file: Dict[int, int] = {}
            for h in seen:
                for fid in index.get(h, ()):
                    per_file[fid] = per_file.get(fid, 0) + 1
            hit = []
            for fid, n in per_file.items():
                f = files[fid]
                if n >= min(self.min_matches, max(f.total, 1)):
                    hit.append((f.path, n, f.total))
            return Verdict(bool(hit), sorted(hit))
        except Exception as exc:          # fail closed
            return Verdict(True, error=f"{type(exc).__name__}: {exc}")

    def log(self, verdict: Verdict, event: Event) -> None:
        with self._db_lock:
            self._log(verdict, event)

    def _log(self, verdict: Verdict, event: Event) -> None:
        where = f"{event.method} {event.host}{event.path.split('?', 1)[0]} [{categorize(event.host, event.path)}]"
        if verdict.error:
            self.store.log_block(event.client[:200] or "unknown", "<guard error>",
                                 f"{where} guard error, blocked: {verdict.error}")
        for path, n, total in verdict.files:
            self.store.log_block(event.client[:200] or "unknown", path,
                                 f"{where} {n}/{total} fingerprints")
