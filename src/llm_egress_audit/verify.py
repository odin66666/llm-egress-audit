"""Compare a local file against everything the proxy has seen leave the machine."""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .categories import sort_key
from .extract import as_text
from .fingerprint import SHINGLE, SHORT_MIN, Hasher, tokens_with_lines
from .store import Store

GRADES = {
    0: "NOT SEEN",
    1: "BLOCKED",
    2: "NAME ONLY",
    3: "PARTIAL",
    4: "FULL",
}
FULL_COVERAGE = 0.90
LINE_COVERAGE = 0.80


@dataclass
class Exposure:
    host: str
    client: str
    category: str
    is_llm: bool
    first_ts: float
    method: str
    path: str
    fingerprints: int


@dataclass
class Report:
    file: str
    grade: int
    label: str
    confidence: str                 # strong | weak | n/a
    kind: str                       # text | binary | pdf
    coverage: float                 # share of the file's text fingerprints seen outside
    matched: int
    total: int
    exposed_lines: List[Tuple[int, int]] = field(default_factory=list)
    whole_file_seen: bool = False
    content_sent_to: List[Exposure] = field(default_factory=list)
    name_sent_to: List[Exposure] = field(default_factory=list)
    blocked: List[dict] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)    # where the content went, worst first
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _pdf_text(data: bytes) -> Optional[str]:
    try:
        import io

        from pypdf import PdfReader
    except ImportError:
        return None
    try:
        return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(data)).pages)
    except Exception:
        return None


def _ranges(lines: Set[int]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for n in sorted(lines):
        if out and n == out[-1][1] + 1:
            out[-1] = (out[-1][0], n)
        else:
            out.append((n, n))
    return out


def _windows(hasher: Hasher, text: str) -> Tuple[List[int], List[int], int]:
    """Fingerprint of the window starting at each token, the line of each token, window width."""
    toks, lines = tokens_with_lines(text)
    if len(toks) < SHINGLE:
        return ([hasher.shingle(toks)] if len(toks) >= SHORT_MIN else []), lines, len(toks)
    return [hasher.shingle(toks[i:i + SHINGLE]) for i in range(len(toks) - SHINGLE + 1)], lines, SHINGLE


def _exposed_lines(windows: List[int], lines: List[int], width: int, seen: Set[int]) -> Set[int]:
    """Lines whose words are mostly covered by windows seen leaving.

    A phrase repeated across the file matches wherever it occurs, so a line is
    reported only when LINE_COVERAGE of its words are covered, not on any overlap.
    """
    covered = [False] * len(lines)
    for i, h in enumerate(windows):
        if h in seen:
            for j in range(i, min(i + width, len(lines))):
                covered[j] = True
    per_line: Dict[int, List[int]] = {}
    for line, cov in zip(lines, covered):
        stats = per_line.setdefault(line, [0, 0])
        stats[0] += cov
        stats[1] += 1
    return {line for line, (c, n) in per_line.items() if c / n >= LINE_COVERAGE}


def _exposures(store: Store, hits: Dict[int, List[Tuple[int, int]]], wanted: Set[int]) -> List[Exposure]:
    per_dest: Dict[int, Tuple[int, int]] = {}      # dest -> (earliest request, fingerprints)
    for h in wanted:
        for dest, rid in hits.get(h, ()):
            first, count = per_dest.get(dest, (rid, 0))
            per_dest[dest] = (min(first, rid), count + 1)
    info = store.requests_by_id(rid for rid, _ in per_dest.values())
    out = []
    for rid, count in per_dest.values():
        ts, method, path, host, client, is_llm, category = info[rid]
        out.append(Exposure(host, client, category, bool(is_llm), ts, method, path, count))
    return sorted(out, key=lambda e: e.first_ts)


def verify_file(store: Store, path: Path) -> Report:
    hasher = store.hasher
    data = path.read_bytes()
    text = as_text(data)
    kind = "text" if text is not None else "binary"
    if text is None and data[:5] == b"%PDF-":
        kind = "pdf"
        text = _pdf_text(data)

    blob_whole = hasher.blob(data)
    chunks = set(hasher.chunk_hashes(data))
    name_h = hasher.name(path.name)
    windows, token_lines, width = _windows(hasher, text) if text else ([], [], 0)
    index = set(windows)
    n_tokens = len(token_lines)

    hits = store.lookup({blob_whole, name_h, *chunks, *index})
    text_hits = {h for h in index if h in hits}
    chunk_hits = {h for h in chunks if h in hits}
    whole = blob_whole in hits
    content_hits = text_hits | chunk_hits | ({blob_whole} if whole else set())

    total = len(index)
    coverage = len(text_hits) / total if total else (1.0 if whole else 0.0)
    if chunks and not total:
        coverage = max(coverage, len(chunk_hits) / len(chunks))

    lines = _exposed_lines(windows, token_lines, width, text_hits)

    blocked = [{"ts": ts, "tool": tool, "detail": detail}
               for ts, tool, detail in store.blocked_for(str(path.resolve()))]

    notes: List[str] = []
    confidence = "n/a"
    if whole or coverage >= FULL_COVERAGE:
        grade, confidence = 4, "strong"
    elif content_hits:
        grade = 3
        strong = len(text_hits) >= 3 or coverage >= 0.5 or bool(chunk_hits) or total <= 3
        confidence = "strong" if strong else "weak"
        if not strong:
            notes.append("Only isolated 8-word windows matched: they may be boilerplate "
                         "shared with other text (licences, headers, common phrases).")
    elif name_h in hits:
        grade = 2
        notes.append("Only the file name was seen; it may belong to another file with the "
                     "same name (agents send directory listings and git status).")
    elif blocked:
        grade = 1
    else:
        grade = 0

    if kind == "pdf" and text is None:
        notes.append("PDF text not extracted (install the 'pdf' extra): only byte-identical "
                     "uploads of this PDF can be detected.")
    if kind == "binary":
        notes.append("Binary file: detected only if sent byte-identical (images resized or "
                     "re-encoded by an agent will not match).")
    if text is not None and n_tokens < SHINGLE:
        notes.append(f"Very short text ({n_tokens} words): detected only if it was sent as a "
                     "whole string on its own. A grade 0 here is weak evidence.")

    content_sent_to = _exposures(store, hits, content_hits)
    return Report(
        file=str(path),
        grade=grade,
        label=GRADES[grade],
        confidence=confidence,
        kind=kind,
        coverage=round(coverage, 4),
        matched=len(text_hits) or len(chunk_hits),
        total=total or len(chunks),
        exposed_lines=_ranges(lines) if kind == "text" else [],
        whole_file_seen=whole,
        content_sent_to=content_sent_to,
        name_sent_to=_exposures(store, hits, {name_h}),
        blocked=blocked,
        categories=sorted({e.category for e in content_sent_to}, key=sort_key),
        notes=notes,
    )


def iter_files(paths: List[str]):
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv")]
                for f in sorted(files):
                    yield Path(root) / f
        else:
            yield path
