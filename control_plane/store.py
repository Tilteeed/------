"""Persistent platform settings. No OpenClaw or Docker state is fabricated."""

import hashlib
import math
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from .policy import AgentSettings, require_owner, validate_agent_input


class RevisionConflict(ValueError):
    """Another request changed the document; reload before writing."""


class InvalidControlUiTicket(ValueError):
    """A launch ticket is expired, consumed or bound to another origin."""


class LaunchRateLimited(ValueError):
    """The owner issued too many Control UI launch tickets in the window."""


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
            db.execute("""CREATE TABLE IF NOT EXISTS control_ui_tickets (
                ticket_hash TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                audience TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS control_ui_tickets_owner_created ON control_ui_tickets(owner_id, created_at)")
            db.execute("""CREATE TABLE IF NOT EXISTS control_ui_sessions (
                session_hash TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                audience TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked_at REAL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS control_ui_sessions_owner ON control_ui_sessions(owner_id, expires_at)")

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

    @staticmethod
    def _control_ui_origin(value):
        if type(value) is not str or len(value) > 300:
            raise ValueError('Invalid Control UI audience')
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
        except ValueError:
            raise ValueError('Invalid Control UI audience') from None
        label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        if (parsed.scheme != 'https' or not hostname or parsed.netloc != hostname
                or parsed.path or parsed.query or parsed.fragment
                or re.fullmatch(label + r'(?:\.' + label + r')*', hostname) is None):
            raise ValueError('Invalid Control UI audience')
        return value, hostname

    @staticmethod
    def _ticket_time(now):
        if now is None:
            return time.time()
        if (type(now) not in (int, float) or not math.isfinite(now) or now < 0):
            raise ValueError('Invalid ticket clock')
        return float(now)

    def issue_control_ui_ticket(self, owner, instance_id, audience, *, now=None, ttl_seconds=60):
        require_owner(owner, owner)
        if (type(instance_id) is not str or re.fullmatch(r'[0-9a-f]{32}', instance_id) is None
                or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 60):
            raise ValueError('Invalid Control UI launch target')
        audience, hostname = self._control_ui_origin(audience)
        if not hostname.startswith(instance_id + '.'):
            raise ValueError('Control UI audience does not match instance')
        now = self._ticket_time(now)
        ticket = secrets.token_urlsafe(32)
        ticket_hash = hashlib.sha256(ticket.encode('ascii')).hexdigest()
        expires_at = now + ttl_seconds
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM control_ui_tickets WHERE expires_at<=?', (now,))
            issued = db.execute(
                'SELECT COUNT(*) FROM control_ui_tickets WHERE owner_id=? AND created_at>?',
                (owner, now - 60)).fetchone()[0]
            if issued >= 10:
                raise LaunchRateLimited('control_ui_launch_rate_limited')
            db.execute('''INSERT INTO control_ui_tickets
                (ticket_hash,owner_id,instance_id,audience,created_at,expires_at,used_at)
                VALUES (?,?,?,?,?,?,NULL)''',
                (ticket_hash, owner, instance_id, audience, now, expires_at))
        return {'ticket': ticket, 'expires_at': expires_at}

    def consume_control_ui_ticket(self, ticket, *, audience, now=None):
        if type(ticket) is not str or re.fullmatch(r'[A-Za-z0-9_-]{40,64}', ticket) is None:
            raise InvalidControlUiTicket('invalid_control_ui_ticket')
        try:
            audience, _hostname = self._control_ui_origin(audience)
        except ValueError:
            raise InvalidControlUiTicket('invalid_control_ui_ticket') from None
        now = self._ticket_time(now)
        ticket_hash = hashlib.sha256(ticket.encode('ascii')).hexdigest()
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('''SELECT owner_id,instance_id,audience,expires_at,used_at
                FROM control_ui_tickets WHERE ticket_hash=?''', (ticket_hash,)).fetchone()
            if (row is None or row['used_at'] is not None or row['expires_at'] <= now
                    or row['audience'] != audience):
                raise InvalidControlUiTicket('invalid_control_ui_ticket')
            changed = db.execute('''UPDATE control_ui_tickets SET used_at=?
                WHERE ticket_hash=? AND used_at IS NULL AND expires_at>? AND audience=?''',
                (now, ticket_hash, now, audience)).rowcount
            if changed != 1:
                raise InvalidControlUiTicket('invalid_control_ui_ticket')
            return {'owner_id': row['owner_id'], 'instance_id': row['instance_id'],
                    'audience': row['audience']}

    def redeem_control_ui_ticket(self, ticket, *, audience, now=None, session_ttl_seconds=3600):
        if type(ticket) is not str or re.fullmatch(r'[A-Za-z0-9_-]{40,64}', ticket) is None:
            raise InvalidControlUiTicket('invalid_control_ui_ticket')
        if type(session_ttl_seconds) is not int or not 1 <= session_ttl_seconds <= 3600:
            raise ValueError('Invalid Control UI session lifetime')
        try:
            audience, _hostname = self._control_ui_origin(audience)
        except ValueError:
            raise InvalidControlUiTicket('invalid_control_ui_ticket') from None
        now = self._ticket_time(now)
        ticket_hash = hashlib.sha256(ticket.encode('ascii')).hexdigest()
        session_id = secrets.token_urlsafe(32)
        session_hash = hashlib.sha256(session_id.encode('ascii')).hexdigest()
        session_expires_at = now + session_ttl_seconds
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('''SELECT owner_id,instance_id,audience,expires_at,used_at
                FROM control_ui_tickets WHERE ticket_hash=?''', (ticket_hash,)).fetchone()
            if (row is None or row['used_at'] is not None or row['expires_at'] <= now
                    or row['audience'] != audience):
                raise InvalidControlUiTicket('invalid_control_ui_ticket')
            changed = db.execute('''UPDATE control_ui_tickets SET used_at=?
                WHERE ticket_hash=? AND used_at IS NULL AND expires_at>? AND audience=?''',
                (now, ticket_hash, now, audience)).rowcount
            if changed != 1:
                raise InvalidControlUiTicket('invalid_control_ui_ticket')
            db.execute('''INSERT INTO control_ui_sessions
                (session_hash,owner_id,instance_id,audience,created_at,expires_at,revoked_at)
                VALUES (?,?,?,?,?,?,NULL)''',
                (session_hash, row['owner_id'], row['instance_id'], audience,
                 now, session_expires_at))
        return {'session_id': session_id, 'owner_id': row['owner_id'],
                'instance_id': row['instance_id'], 'audience': audience,
                'expires_at': session_expires_at}

    def validate_control_ui_session(self, session_id, *, audience, now=None):
        if type(session_id) is not str or re.fullmatch(r'[A-Za-z0-9_-]{40,64}', session_id) is None:
            return None
        try:
            audience, _hostname = self._control_ui_origin(audience)
        except ValueError:
            return None
        now = self._ticket_time(now)
        session_hash = hashlib.sha256(session_id.encode('ascii')).hexdigest()
        with self._connection() as db:
            row = db.execute('''SELECT owner_id,instance_id,audience,expires_at,revoked_at
                FROM control_ui_sessions WHERE session_hash=?''', (session_hash,)).fetchone()
            if (row is None or row['revoked_at'] is not None or row['expires_at'] <= now
                    or row['audience'] != audience):
                return None
            return {'owner_id': row['owner_id'], 'instance_id': row['instance_id'],
                    'audience': row['audience']}

    def revoke_control_ui_sessions(self, owner, *, now=None):
        require_owner(owner, owner)
        now = self._ticket_time(now)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''UPDATE control_ui_tickets SET used_at=?
                WHERE owner_id=? AND used_at IS NULL AND expires_at>?''',
                (now, owner, now))
            changed = db.execute('''UPDATE control_ui_sessions SET revoked_at=?
                WHERE owner_id=? AND revoked_at IS NULL AND expires_at>?''',
                (now, owner, now)).rowcount
            return changed

    def events(self, owner: str):
        require_owner(owner, owner)
        with self._connection() as db:
            rows = db.execute(
                """SELECT kind, created_at FROM events
                WHERE owner_id=? ORDER BY id DESC LIMIT 25""",
                (owner,),
            ).fetchall()
            return [dict(row) for row in rows]
