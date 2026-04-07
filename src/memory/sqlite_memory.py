from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

DEFAULT_DB_PATH = Path(os.getenv("AGENT_MEMORY_DB", "agent_memory.db"))

# Basic hardening limits (prevent DB pollution / runaway growth)
MAX_URL_LEN = int(os.getenv("ORIX_MAX_URL_LEN", "2048"))
MAX_TITLE_LEN = int(os.getenv("ORIX_MAX_TITLE_LEN", "256"))
MAX_SUMMARY_LEN = int(os.getenv("ORIX_MAX_SUMMARY_LEN", "2000"))
MAX_CONTENT_LEN = int(os.getenv("ORIX_MAX_CONTENT_LEN", "4000"))
MAX_METADATA_JSON_LEN = int(os.getenv("ORIX_MAX_METADATA_JSON_LEN", "12000"))

VALID_VERDICTS = {"ALLOW", "WARN", "BLOCK", "CONFIRM"}


def _clip(s: Any, n: int) -> str:
    try:
        out = "" if s is None else str(s)
    except Exception:
        out = ""
    if n > 0 and len(out) > n:
        return out[:n]
    return out


def _clamp_float(x: Any, lo: float, hi: float, default: float = 0.0) -> float:
    try:
        v = float(x)
    except Exception:
        return default
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _safe_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    meta = dict(metadata or {})

    # Normalize verdict
    verdict = meta.get("verdict")
    if verdict is not None:
        v = str(verdict).upper().strip()
        meta["verdict"] = v if v in VALID_VERDICTS else "ALLOW"

    # Clamp risk score if present
    if "risk_score" in meta:
        meta["risk_score"] = _clamp_float(meta.get("risk_score"), 0.0, 1.0, default=0.0)

    # Ensure JSON-serializable; fall back to string
    try:
        json.dumps(meta, ensure_ascii=False)
    except Exception:
        meta = {"_meta": _clip(meta, 2000)}

    return meta


@dataclass
class MemoryItem:
    id: int
    ts: float
    kind: str
    task_id: str
    url: str
    title: str
    summary: str
    content: str
    metadata: Dict[str, Any]
    score: float = 0.0

    @property
    def trusted(self) -> bool:
        return bool(self.metadata.get("trusted", False))

    @property
    def risk_score(self) -> float:
        try:
            return float(self.metadata.get("risk_score", 0.0) or 0.0)
        except Exception:
            return 0.0


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


class SQLiteMemoryStore:
    """Persistent memory store using SQLite + FTS5.

    Stores short summaries + optional full content. Retrieval uses full-text search.
    """

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(self.db_path))
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    kind TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            # FTS table for retrieval. contentless=0 so we can select stored text.
            con.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts
                USING fts5(
                    summary,
                    content,
                    url,
                    title,
                    task_id,
                    kind,
                    content='memory_items',
                    content_rowid='id'
                )
                """
            )
            # Triggers to keep FTS in sync
            con.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS memory_ai AFTER INSERT ON memory_items BEGIN
                    INSERT INTO memory_fts(rowid, summary, content, url, title, task_id, kind)
                    VALUES (new.id, new.summary, new.content, new.url, new.title, new.task_id, new.kind);
                END;

                CREATE TRIGGER IF NOT EXISTS memory_ad AFTER DELETE ON memory_items BEGIN
                    INSERT INTO memory_fts(memory_fts, rowid, summary, content, url, title, task_id, kind)
                    VALUES('delete', old.id, old.summary, old.content, old.url, old.title, old.task_id, old.kind);
                END;

                CREATE TRIGGER IF NOT EXISTS memory_au AFTER UPDATE ON memory_items BEGIN
                    INSERT INTO memory_fts(memory_fts, rowid, summary, content, url, title, task_id, kind)
                    VALUES('delete', old.id, old.summary, old.content, old.url, old.title, old.task_id, old.kind);
                    INSERT INTO memory_fts(rowid, summary, content, url, title, task_id, kind)
                    VALUES (new.id, new.summary, new.content, new.url, new.title, new.task_id, new.kind);
                END;
                """
            )

    def add(
        self,
        *,
        kind: str,
        task_id: str,
        url: str = "",
        title: str = "",
        summary: str,
        content: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        ts: Optional[float] = None,
    ) -> int:
        # Basic sanitization / hardening
        url_s = _clip(url or "", MAX_URL_LEN)
        title_s = _clip(title or "", MAX_TITLE_LEN)
        summary_s = _clip(summary or "", MAX_SUMMARY_LEN)
        content_s = _clip(content or "", MAX_CONTENT_LEN)
        meta = _safe_metadata(metadata)

        meta_json = json.dumps(meta, ensure_ascii=False)
        meta_json = _clip(meta_json, MAX_METADATA_JSON_LEN)

        now = float(ts if ts is not None else time.time())
        with self._connect() as con:
            cur = con.execute(
                """
                INSERT INTO memory_items (ts, kind, task_id, url, title, summary, content, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now, kind, task_id, url_s, title_s, summary_s, content_s, meta_json),
            )
            return int(cur.lastrowid)

    def search(
        self,
        *,
        query: str,
        limit: int = 5,
        task_id: Optional[str] = None,
        kinds: Optional[List[str]] = None,
    ) -> List[MemoryItem]:
        """Search memory via FTS.

        Uses bm25 ranking supplied by FTS5.
        """
        q = (query or "").strip()
        if not q:
            return []

        where = []
        params: List[Any] = [q]

        if task_id:
            where.append("mi.task_id = ?")
            params.append(task_id)
        if kinds:
            where.append("mi.kind IN (%s)" % ",".join(["?"] * len(kinds)))
            params.extend(kinds)

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        sql = f"""
            SELECT
                mi.id,
                mi.ts,
                mi.kind,
                mi.task_id,
                mi.url,
                mi.title,
                mi.summary,
                mi.content,
                mi.metadata_json,
                bm25(memory_fts) AS score
            FROM memory_fts
            JOIN memory_items mi ON mi.id = memory_fts.rowid
            WHERE memory_fts MATCH ?
            {('AND ' + ' AND '.join(where)) if where else ''}
            ORDER BY score ASC
            LIMIT {int(limit)}
        """

        # Note: lower bm25 is better.
        with self._connect() as con:
            rows = con.execute(sql, params).fetchall()

        out: List[MemoryItem] = []
        for r in rows:
            out.append(
                MemoryItem(
                    id=int(r["id"]),
                    ts=float(r["ts"]),
                    kind=str(r["kind"]),
                    task_id=str(r["task_id"]),
                    url=str(r["url"] or ""),
                    title=str(r["title"] or ""),
                    summary=str(r["summary"] or ""),
                    content=str(r["content"] or ""),
                    metadata=json.loads(r["metadata_json"] or "{}"),
                    score=float(r["score"] or 0.0),
                )
            )
        return out

    def rerank(
        self,
        *,
        items: List[MemoryItem],
        current_url: str = "",
        current_task: str = "",
    ) -> List[MemoryItem]:
        """Light-weight post-ranking for task success + safety.

        FTS bm25 is great, but we also want:
        - prefer trusted memories
        - prefer low-risk memories
        - prefer same-domain memories
        - prefer same-task memories
        """
        cur_host = _host(current_url)

        def key(it: MemoryItem) -> tuple:
            # lower tuple is better
            same_domain = int(bool(cur_host and _host(it.url) == cur_host))
            same_task = int(bool(current_task and it.metadata.get("user_request") == current_task))
            trusted = int(it.trusted)
            risk = it.risk_score

            # Primary: trusted, low-risk, same-domain, same-task, then bm25
            return (
                0 if trusted else 1,
                risk,
                0 if same_domain else 1,
                0 if same_task else 1,
                float(it.score or 0.0),
                -float(it.ts or 0.0),
            )

        return sorted(items, key=key)

    def build_context_snippet(self, items: List[MemoryItem], max_chars: int = 2500) -> str:
        """Format retrieved items into a prompt-ready context snippet."""
        parts: List[str] = []
        for it in items:
            tag_bits = []
            if it.trusted:
                tag_bits.append("trusted")
            if it.risk_score:
                tag_bits.append(f"risk={it.risk_score:.2f}")
            tags = (";".join(tag_bits)) if tag_bits else ""
            parts.append(
                f"- [{it.kind}] {tags} url={it.url!r} title={it.title!r} summary={it.summary!r}"
            )
        text = "\n".join(parts)
        return text[:max_chars]
