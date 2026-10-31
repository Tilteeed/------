"""Durable service intents, independent of the Stage-3 registry/coordinator.

An intent reserves resources, NOT permission to create/start a container. Failed
and pending creates keep their reservation. Removed instances retain disk forever.
"""
import hashlib
import json
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager


class StoreError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


class RuntimeStore:
    def __init__(self, path, profile_version, profile_hash):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS binding (id INTEGER PRIMARY KEY CHECK(id=1), version TEXT NOT NULL, fingerprint TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS instances (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, active INTEGER NOT NULL,
                    state TEXT NOT NULL, settings TEXT NOT NULL, revision INTEGER NOT NULL,
                    ram INTEGER NOT NULL, cpu INTEGER NOT NULL, disk INTEGER NOT NULL,
                    gateway_token TEXT NOT NULL, storage TEXT, container_id TEXT,
                    initialized INTEGER NOT NULL DEFAULT 0);
                CREATE UNIQUE INDEX IF NOT EXISTS owner_active ON instances(actor) WHERE active=1;
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, key TEXT NOT NULL,
                    payload TEXT NOT NULL, instance_id TEXT NOT NULL REFERENCES instances(id),
                    action TEXT NOT NULL, status TEXT NOT NULL, error TEXT,
                    UNIQUE(actor,key));
            ''')
            with self.transaction():
                old = self.db.execute('SELECT version,fingerprint FROM binding WHERE id=1').fetchone()
                if old and tuple(old) != (profile_version, profile_hash):
                    raise StoreError('profile_drift')
                self.db.execute('INSERT OR IGNORE INTO binding VALUES (1,?,?)', (profile_version, profile_hash))
            self.profile_version, self.profile_hash = profile_version, profile_hash
        except BaseException:
            self.db.close()
            raise

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise

    def _payload(self, payload):
        return canonical({'request': payload, 'profile_version': self.profile_version,
                          'profile_hash': self.profile_hash})

    def lookup(self, payload):
        with self.lock:
            row = self.db.execute('SELECT * FROM operations WHERE actor=? AND key=?',
                                  (payload['actor_id'], payload['idempotency_key'])).fetchone()
            if row and row['payload'] != self._payload(payload):
                raise StoreError('idempotency_conflict')
            return dict(row) if row else None

    def saved_request(self, actor, key):
        """Read a detached copy of the immutable, owner-scoped request snapshot."""
        with self.lock:
            row = self.db.execute('SELECT payload FROM operations WHERE actor=? AND key=?',
                                  (actor, key)).fetchone()
            return json.loads(row['payload'])['request'] if row else None

    def create_retry(self, instance_id):
        with self.lock:
            row = self.db.execute("SELECT key FROM operations WHERE instance_id=? AND action='create' AND status IN ('pending','failed') LIMIT 1", (instance_id,)).fetchone()
            return row['key'] if row else None

    def retained(self, actor):
        """Owner-scoped retained datasets; never expose host paths or project IDs."""
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM instances WHERE actor=? AND active=0 AND disk>0 "
                "AND state IN ('removed','purging') ORDER BY id LIMIT 100", (actor,)).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                try:
                    settings = json.loads(item['settings'])
                    name = settings.get('name', 'Агент') if type(settings) is dict else 'Агент'
                except (ValueError, TypeError):
                    name = 'Агент'
                retry = self.purge_retry(item['id'])
                result.append({'instance_id': item['id'], 'name': name,
                               'disk_bytes': item['disk'], 'state': item['state'],
                               'pending_purge_key': retry['key'] if retry else None,
                               'pending_purge_revision': retry['revision'] if retry else None})
            return result

    def purge_retry(self, instance_id):
        with self.lock:
            row = self.db.execute(
                "SELECT key,payload FROM operations WHERE instance_id=? AND action='purge' "
                "AND status IN ('pending','failed') ORDER BY rowid DESC LIMIT 1", (instance_id,)).fetchone()
            if row is None:
                return None
            request = json.loads(row['payload'])['request']
            return {'key': row['key'], 'revision': request['settings_revision']}

    def current(self, actor):
        with self.lock:
            row = self.db.execute('SELECT * FROM instances WHERE actor=? AND active=1', (actor,)).fetchone()
            return dict(row) if row else None

    def instance(self, instance_id):
        with self.lock:
            row = self.db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not row:
                raise StoreError('instance_not_found')
            return dict(row)

    def all_instances(self):
        with self.lock:
            return [dict(row) for row in self.db.execute('SELECT * FROM instances')]

    def totals(self):
        with self.lock:
            return tuple(self.db.execute('SELECT COALESCE(SUM(ram),0),COALESCE(SUM(cpu),0),COALESCE(SUM(disk),0) FROM instances').fetchone())

    def intent(self, payload, limits, capacities):
        """Atomic replay, owner slot, reservation and operation intent."""
        with self.transaction():
            replay = self.lookup(payload)
            if replay:
                other = self.db.execute("SELECT 1 FROM operations WHERE instance_id=? AND id!=? AND status='pending'", (replay['instance_id'], replay['id'])).fetchone()
                if other and replay['status'] != 'completed' and payload['action'] not in {'stop', 'remove'}:
                    raise StoreError('operation_pending')
                return replay
            actor, action = payload['actor_id'], payload['action']
            if action not in {'create', 'start', 'stop', 'restart', 'remove', 'purge'}:
                raise StoreError('invalid_action')
            instance_id = None
            instance = None
            if action == 'purge':
                row = self.db.execute('SELECT * FROM instances WHERE id=? AND actor=?',
                                      (payload['instance_id'], actor)).fetchone()
                instance = dict(row) if row else None
                if instance is None or instance['disk'] <= 0 or instance['state'] == 'purged':
                    raise StoreError('instance_not_found')
                if not instance['active'] and instance['state'] not in {'removed', 'purging'}:
                    raise StoreError('instance_not_found')
                instance_id = instance['id']
            else:
                instance = self.current(actor)
            if action == 'create':
                if instance:
                    raise StoreError('owner_has_instance')
                if any(used + requested > capacity for used, requested, capacity
                       in zip(self.totals(), limits, capacities)):
                    raise StoreError('capacity_exhausted')
                instance_id = uuid.uuid4().hex
                self.db.execute('INSERT INTO instances (id,actor,active,state,settings,revision,ram,cpu,disk,gateway_token,storage,container_id) VALUES (?,?,1,?,?,?,?,?,?,?,NULL,NULL)',
                                (instance_id, actor, 'preparing', canonical(payload['settings']),
                                 payload['settings_revision'], *limits, secrets.token_urlsafe(32)))
            elif action != 'purge':
                if instance is None:
                    raise StoreError('instance_not_found')
                instance_id = instance['id']
            pending = self.db.execute("SELECT 1 FROM operations WHERE instance_id=? AND status='pending'", (instance_id,)).fetchone()
            if pending and action not in {'stop', 'remove'}:
                raise StoreError('operation_pending')
            if pending:
                self.db.execute("UPDATE operations SET status='failed',error='interrupted' WHERE instance_id=? AND status='pending'", (instance_id,))
            if instance_id is None:
                raise StoreError('invalid_action')
            operation_id = uuid.uuid4().hex
            self.db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,?,NULL)',
                            (operation_id, actor, payload['idempotency_key'], self._payload(payload), instance_id, action, 'pending'))
            if action == 'purge':
                self.db.execute("UPDATE instances SET state='purging' WHERE id=?", (instance_id,))
            return self.lookup(payload)

    def pending(self, operation_id):
        with self.transaction():
            self.db.execute("UPDATE operations SET status='pending',error=NULL WHERE id=? AND status!='completed'", (operation_id,))

    def storage_ready(self, instance_id, evidence):
        with self.transaction():
            self.db.execute('UPDATE instances SET storage=? WHERE id=?', (canonical(evidence), instance_id))

    def initialized(self, instance_id):
        with self.transaction():
            self.db.execute('UPDATE instances SET initialized=1 WHERE id=?', (instance_id,))

    def observe(self, instance_id, state, container_id=None):
        with self.transaction():
            self.db.execute('UPDATE instances SET state=?,container_id=? WHERE id=? AND active=1',
                            (state, container_id, instance_id))

    def complete(self, operation_id, state, container_id=None):
        with self.transaction():
            operation = self.db.execute('SELECT * FROM operations WHERE id=?', (operation_id,)).fetchone()
            if operation is None:
                raise StoreError('operation_not_found')
            if state == 'removed':
                self.db.execute("UPDATE instances SET active=0,state='removed',ram=0,cpu=0,container_id=NULL WHERE id=?", (operation['instance_id'],))
            elif state == 'purged':
                self.db.execute("UPDATE instances SET active=0,state='purged',ram=0,cpu=0,disk=0,storage=NULL,container_id=NULL WHERE id=?", (operation['instance_id'],))
            else:
                self.db.execute('UPDATE instances SET state=?,container_id=? WHERE id=? AND active=1', (state, container_id, operation['instance_id']))
            self.db.execute("UPDATE operations SET status='completed',error=NULL WHERE id=?", (operation_id,))

    def fail(self, operation_id, code):
        with self.transaction():
            self.db.execute("UPDATE operations SET status='failed',error=? WHERE id=? AND status!='completed'", (code, operation_id))
            self.db.execute("UPDATE instances SET state='failed' WHERE state='preparing' AND active=1 AND id=(SELECT instance_id FROM operations WHERE id=?)", (operation_id,))

    def close(self):
        with self.lock:
            self.db.close()
