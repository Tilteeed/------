"""Persistent platform settings. No OpenClaw or Docker state is fabricated."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .policy import AgentSettings, require_owner, validate_agent_input


class RevisionConflict(ValueError):
    """Another request changed the document; reload before writing."""


class DraftStore:
    """One pending settings document per account; this is NOT a running agent."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS drafts (
                owner_id TEXT PRIMARY KEY, id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL, instructions TEXT NOT NULL,
                revision INTEGER NOT NULL, updated_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL,
                kind TEXT NOT NULL, created_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS events_owner ON events(owner_id, id)")

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _get(db, owner):
        row = db.execute(
            "SELECT id, name, instructions, revision, updated_at FROM drafts WHERE owner_id = ?",
            (owner,),
        ).fetchone()
        return dict(row) if row else None

    def get(self, owner: str):
        require_owner(owner, owner)
        with self._connection() as db:
            return self._get(db, owner)

    def save(self, owner: str, settings: AgentSettings, *, expected_revision: int):
        require_owner(owner, owner)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("Revision must be a non-negative integer")
        if not isinstance(settings, AgentSettings):
            raise ValueError("Validated settings are required")
        settings = validate_agent_input({"name": settings.name, "instructions": settings.instructions})
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            now = datetime.now(timezone.utc).isoformat()
            if expected_revision == 0:
                changed = db.execute(
                    """INSERT INTO drafts VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(owner_id) DO NOTHING""",
                    (owner, str(uuid4()), settings.name, settings.instructions, now),
                ).rowcount
            else:
                changed = db.execute(
                    """UPDATE drafts SET name=?, instructions=?,
                    revision=revision+1, updated_at=?
                    WHERE owner_id=? AND revision=?""",
                    (settings.name, settings.instructions, now, owner, expected_revision),
                ).rowcount
            if changed != 1:
                raise RevisionConflict("Settings changed; reload and try again")
            db.execute(
                "INSERT INTO events(owner_id, kind, created_at) VALUES (?, ?, ?)",
                (owner, "settings.saved", now),
            )
            db.execute(
                """DELETE FROM events WHERE owner_id=? AND id NOT IN
                (SELECT id FROM events WHERE owner_id=? ORDER BY id DESC LIMIT 100)""",
                (owner, owner),
            )
            return self._get(db, owner)

    def events(self, owner: str):
        require_owner(owner, owner)
        with self._connection() as db:
            rows = db.execute(
                """SELECT kind, created_at FROM events
                WHERE owner_id=? ORDER BY id DESC LIMIT 25""",
                (owner,),
            ).fetchall()
            return [dict(row) for row in rows]
