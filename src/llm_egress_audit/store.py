"""SQLite store: destinations, requests and first exposure of every fingerprint.

No traffic content is ever written: only metadata (hosts, clients, times, URL paths)
and the paths you chose to protect. Fingerprints let someone confirm a guess only if
they also hold the key; without it they are random 64-bit integers.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from . import config
from .categories import categorize
from .fingerprint import Hasher

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS destinations(
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL,
    client TEXT NOT NULL,
    category TEXT NOT NULL,
    is_llm INTEGER NOT NULL,
    first_ts REAL NOT NULL,
    last_ts REAL NOT NULL,
    n_requests INTEGER NOT NULL DEFAULT 0,
    UNIQUE(host, client, category)
);
CREATE TABLE IF NOT EXISTS requests(
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    dest_id INTEGER NOT NULL REFERENCES destinations(id),
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    new_hashes INTEGER NOT NULL      -- -1 = body could not be analysed
);
CREATE TABLE IF NOT EXISTS exposure(
    h INTEGER NOT NULL,
    dest_id INTEGER NOT NULL,
    request_id INTEGER NOT NULL,
    PRIMARY KEY(h, dest_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS blocked(
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    tool TEXT NOT NULL,
    path_h INTEGER NOT NULL,
    name_h INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS protected(
    path TEXT PRIMARY KEY,           -- a file or folder you chose to protect (its content is never stored)
    added_ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS blocked_path ON blocked(path_h);
CREATE INDEX IF NOT EXISTS blocked_name ON blocked(name_h);
"""


class KeyMismatch(RuntimeError):
    pass


def load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = path.read_bytes()
        if len(key) != 32:
            raise KeyMismatch(f"{path} is not a valid key (expected 32 bytes, got {len(key)})")
        return key
    key = secrets.token_bytes(32)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


class Store:
    def __init__(self, db_file: Path, key: bytes):
        db_file.parent.mkdir(parents=True, exist_ok=True)
        self.hasher = Hasher(key)
        self.db = sqlite3.connect(str(db_file), timeout=30, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        try:
            self._check_key()
        except KeyMismatch:
            self.db.close()
            raise

    @classmethod
    def open_default(cls) -> "Store":
        return cls(config.db_path(), load_or_create_key(config.key_path()))

    def _check_key(self) -> None:
        check = self.hasher.key_check()
        row = self.db.execute("SELECT v FROM meta WHERE k='key_check'").fetchone()
        if row is None:
            self.db.execute("INSERT INTO meta(k, v) VALUES('key_check', ?)", (check,))
            self.db.execute("INSERT OR IGNORE INTO meta(k, v) VALUES('created', ?)", (str(time.time()),))
            self.db.commit()
        elif row[0] != check:
            raise KeyMismatch(
                "the key file does not match this database: every fingerprint in it would "
                "be unreadable. Restore the original key or point LLM_EGRESS_AUDIT_HOME elsewhere."
            )

    def close(self) -> None:
        self.db.close()

    # -- writing ------------------------------------------------------------
    def destination(self, host: str, client: str, category: str, ts: float) -> int:
        """One row per (host, client, category): the same client can send the same text as a
        prompt and later inside telemetry, and both first exposures must survive."""
        self.db.execute(
            "INSERT INTO destinations(host, client, category, is_llm, first_ts, last_ts) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(host, client, category) DO NOTHING",
            (host, client, category, int(config.is_llm_host(host)), ts, ts),
        )
        return self.db.execute(
            "SELECT id FROM destinations WHERE host=? AND client=? AND category=?",
            (host, client, category),
        ).fetchone()[0]

    def record(self, ts: float, host: str, client: str, method: str, path: str,
               size: int, hashes: Optional[Iterable[int]], category: Optional[str] = None) -> int:
        """Store one request. hashes=None marks a body that could not be analysed."""
        category = category or categorize(host, path)
        with self.db:
            dest = self.destination(host, client, category, ts)
            hashes = None if hashes is None else list(hashes)
            cur = self.db.execute(
                "INSERT INTO requests(ts, dest_id, method, path, bytes, new_hashes) VALUES(?,?,?,?,?,?)",
                (ts, dest, method, path, size, -1 if hashes is None else len(hashes)),
            )
            rid = cur.lastrowid
            if hashes:
                self.db.executemany(
                    "INSERT OR IGNORE INTO exposure(h, dest_id, request_id) VALUES(?,?,?)",
                    ((h, dest, rid) for h in hashes),
                )
            self.db.execute(
                "UPDATE destinations SET last_ts=MAX(last_ts, ?), n_requests=n_requests+1 WHERE id=?",
                (ts, dest),
            )
        return rid

    def log_block(self, tool: str, path: str, detail: str = "", ts: Optional[float] = None) -> None:
        name = os.path.basename(path.replace("\\", "/").rstrip("/"))
        with self.db:
            self.db.execute(
                "INSERT INTO blocked(ts, tool, path_h, name_h, detail) VALUES(?,?,?,?,?)",
                (ts or time.time(), tool, self.hasher.path(path), self.hasher.name(name), detail),
            )

    def protect(self, path: str) -> bool:
        with self.db:
            cur = self.db.execute("INSERT OR IGNORE INTO protected(path, added_ts) VALUES(?, ?)",
                                  (path, time.time()))
        return cur.rowcount > 0

    def unprotect(self, path: str) -> bool:
        with self.db:
            cur = self.db.execute("DELETE FROM protected WHERE path=?", (path,))
        return cur.rowcount > 0

    def protected(self) -> List[str]:
        return [r[0] for r in self.db.execute("SELECT path FROM protected ORDER BY path")]

    # -- reading ------------------------------------------------------------
    def lookup(self, hashes: Iterable[int]) -> Dict[int, List[Tuple[int, int]]]:
        """fingerprint -> [(dest_id, first request_id), ...]"""
        hashes = list(set(hashes))
        found: Dict[int, List[Tuple[int, int]]] = {}
        for i in range(0, len(hashes), 500):
            batch = hashes[i:i + 500]
            marks = ",".join("?" * len(batch))
            for h, dest, rid in self.db.execute(
                f"SELECT h, dest_id, request_id FROM exposure WHERE h IN ({marks})", batch
            ):
                found.setdefault(h, []).append((dest, rid))
        return found

    def requests_by_id(self, ids: Iterable[int]) -> Dict[int, tuple]:
        ids = list(set(ids))
        out: Dict[int, tuple] = {}
        for i in range(0, len(ids), 500):
            batch = ids[i:i + 500]
            marks = ",".join("?" * len(batch))
            for row in self.db.execute(
                f"SELECT r.id, r.ts, r.method, r.path, d.host, d.client, d.is_llm, d.category "
                f"FROM requests r JOIN destinations d ON d.id = r.dest_id WHERE r.id IN ({marks})",
                batch,
            ):
                out[row[0]] = row[1:]
        return out

    def blocked_for(self, path: str) -> List[tuple]:
        name = os.path.basename(path.replace("\\", "/").rstrip("/"))
        return self.db.execute(
            "SELECT ts, tool, detail FROM blocked WHERE path_h=? OR name_h=? ORDER BY ts",
            (self.hasher.path(path), self.hasher.name(name)),
        ).fetchall()

    def window(self) -> Tuple[Optional[float], Optional[float], int, int]:
        """(first ts, last ts, requests, requests that could not be analysed)"""
        first, last, n = self.db.execute("SELECT MIN(ts), MAX(ts), COUNT(*) FROM requests").fetchone()
        bad = self.db.execute("SELECT COUNT(*) FROM requests WHERE new_hashes < 0").fetchone()[0]
        return first, last, n, bad

    def destinations(self) -> List[tuple]:
        return self.db.execute(
            "SELECT host, client, category, first_ts, last_ts, n_requests FROM destinations "
            "ORDER BY n_requests DESC"
        ).fetchall()
