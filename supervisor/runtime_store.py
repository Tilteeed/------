"""Durable service intents, independent of the Stage-3 registry/coordinator.

An intent reserves resources, NOT permission to create/start a container. Failed
and pending creates keep their reservation. Removed instances retain disk forever.
"""
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
            self.db.execute('PRAGMA secure_delete=ON')
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
            if row:
                saved = json.loads(row['payload'])
                if type(saved) is dict and saved.get('redacted') is True:
                    replay = saved.get('replay')
                    matches_targeted = (type(replay) is dict and payload['action'] in {'purge', 'restore'}
                                        and replay.get('action') == payload['action']
                                        and replay.get('settings_revision') == payload['settings_revision']
                                        and replay.get('instance_id') == payload.get('instance_id'))
                    if not matches_targeted:
                        raise StoreError('idempotency_conflict')
                elif row['payload'] != self._payload(payload):
                    raise StoreError('idempotency_conflict')
            return dict(row) if row else None

    def operation(self, actor, key):
        with self.lock:
            row = self.db.execute('SELECT * FROM operations WHERE actor=? AND key=?',
                                  (actor, key)).fetchone()
            return dict(row) if row else None

    def request_metadata(self, actor, key):
        """Minimal replay fields survive purge scrubbing of an operation payload."""
        with self.lock:
            row = self.db.execute('SELECT payload FROM operations WHERE actor=? AND key=?',
                                  (actor, key)).fetchone()
            if row is None:
                return None
            saved = json.loads(row['payload'])
            if type(saved) is not dict:
                return None
            request = saved.get('request')
            if type(request) is dict:
                return {name: request.get(name) for name in ('action', 'settings_revision', 'instance_id')}
            replay = saved.get('replay')
            return dict(replay) if type(replay) is dict else None

    def saved_request(self, actor, key):
        """Read a detached copy of the owner-scoped request if it is still retained."""
        with self.lock:
            row = self.db.execute('SELECT payload FROM operations WHERE actor=? AND key=?',
                                  (actor, key)).fetchone()
            if row is None:
                return None
            saved = json.loads(row['payload'])
            request = saved.get('request') if type(saved) is dict else None
            return request if type(request) is dict else None

    def create_retry(self, instance_id):
        with self.lock:
            row = self.db.execute("SELECT key FROM operations WHERE instance_id=? AND action='create' AND status IN ('pending','failed') LIMIT 1", (instance_id,)).fetchone()
            return row['key'] if row else None

    def restore_retry(self, instance_id):
        with self.lock:
            row = self.db.execute(
                "SELECT key,payload FROM operations WHERE instance_id=? AND action='restore' "
                "AND status IN ('pending','failed') ORDER BY rowid DESC LIMIT 1", (instance_id,)).fetchone()
            if row is None:
                return None
            saved = json.loads(row['payload'])
            request = saved.get('request') if type(saved) is dict else None
            if type(request) is dict:
                action = request.get('action')
                revision = request.get('settings_revision')
                target = request.get('instance_id')
            else:
                replay = saved.get('replay') if type(saved) is dict else None
                if type(saved) is not dict or saved.get('redacted') is not True or type(replay) is not dict:
                    raise StoreError('invalid_transition')
                action = replay.get('action')
                revision = replay.get('settings_revision')
                target = replay.get('instance_id')
            if (action != 'restore' or target != instance_id
                    or type(revision) is not int or not 0 <= revision <= 2**63 - 1):
                raise StoreError('invalid_transition')
            return {'key': row['key'], 'revision': revision}

    def retained_instance(self, actor, instance_id):
        """Return only an owner's inactive, non-purging retained instance."""
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM instances WHERE actor=? AND id=? AND active=0 AND disk>0 "
                "AND state='removed' AND storage IS NOT NULL",
                (actor, instance_id)).fetchone()
            return dict(row) if row else None

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
            saved = json.loads(row['payload'])
            request = saved.get('request') if type(saved) is dict else None
            if type(request) is dict:
                action = request.get('action')
                revision = request.get('settings_revision')
                target = request.get('instance_id')
            else:
                replay = saved.get('replay') if type(saved) is dict else None
                if type(saved) is not dict or saved.get('redacted') is not True or type(replay) is not dict:
                    raise StoreError('invalid_transition')
                action = replay.get('action')
                revision = replay.get('settings_revision')
                target = replay.get('instance_id')
            if (action != 'purge' or target != instance_id
                    or type(revision) is not int or not 0 <= revision <= 2**63 - 1):
                raise StoreError('invalid_transition')
            return {'key': row['key'], 'revision': revision}

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
            if action not in {'create', 'start', 'stop', 'restart', 'remove', 'purge', 'restore'}:
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
            elif action == 'restore':
                row = self.db.execute('SELECT * FROM instances WHERE id=? AND actor=?',
                                      (payload['instance_id'], actor)).fetchone()
                instance = dict(row) if row else None
                if (instance is None or instance['active'] or instance['state'] != 'removed'
                        or instance['ram'] != 0 or instance['cpu'] != 0
                        or instance['disk'] <= 0 or instance['storage'] is None):
                    raise StoreError('instance_not_found')
                if self.current(actor) is not None:
                    raise StoreError('owner_has_instance')
                used = self.totals()
                if (used[0] + limits[0] > capacities[0]
                        or used[1] + limits[1] > capacities[1]):
                    raise StoreError('capacity_exhausted')
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
            elif action not in {'purge', 'restore'}:
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
            saved_payload = (canonical({'redacted': True, 'replay': {
                'action': action, 'settings_revision': payload['settings_revision'],
                'instance_id': payload.get('instance_id')}}) if action == 'restore' else self._payload(payload))
            self.db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,?,NULL)',
                            (operation_id, actor, payload['idempotency_key'], saved_payload, instance_id, action, 'pending'))
            if action == 'purge':
                self.db.execute("UPDATE instances SET state='purging' WHERE id=?", (instance_id,))
            elif action == 'restore':
                changed = self.db.execute(
                    "UPDATE instances SET active=1,state='preparing',ram=?,cpu=? "
                    "WHERE id=? AND actor=? AND active=0 AND state='removed'",
                    (limits[0], limits[1], instance_id, actor)).rowcount
                if changed != 1:
                    raise StoreError('instance_not_found')
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
        with self.lock:
            operation = self.db.execute('SELECT * FROM operations WHERE id=?', (operation_id,)).fetchone()
            if operation is None:
                raise StoreError('operation_not_found')
            instance_id = operation['instance_id']
            if state == 'purged':
                if operation['action'] != 'purge':
                    raise StoreError('invalid_transition')
                # First scrub instance secrets/snapshots and retain only minimal
                # replay metadata. Keep the disk reservation until SQLite confirms
                # the scrubbed WAL can be checkpointed.
                with self.transaction():
                    self.db.execute("UPDATE instances SET settings='{}',gateway_token='',storage=NULL,container_id=NULL WHERE id=?",
                                    (instance_id,))
                    rows = self.db.execute(
                        'SELECT id,payload FROM operations WHERE instance_id=?',
                        (instance_id,)).fetchall()
                    for row in rows:
                        original = json.loads(row['payload'])
                        if type(original) is dict and original.get('redacted') is True:
                            redacted = row['payload']
                        else:
                            request = original.get('request') if type(original) is dict else None
                            replay = {name: request.get(name) for name in
                                     ('action', 'settings_revision', 'instance_id')} if type(request) is dict else {}
                            redacted = canonical({'redacted': True, 'replay': replay})
                        self.db.execute('UPDATE operations SET payload=? WHERE id=?',
                                        (redacted, row['id']))
                checkpoint = self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
                if checkpoint is None or checkpoint[0] != 0:
                    raise StoreError('purge_scrub_unverified')
                with self.transaction():
                    self.db.execute("UPDATE instances SET active=0,state='purged',ram=0,cpu=0,disk=0 WHERE id=?",
                                    (instance_id,))
                    self.db.execute("UPDATE operations SET status='completed',error=NULL WHERE id=?",
                                    (operation_id,))
                return

            with self.transaction():
                if state == 'removed':
                    self.db.execute("UPDATE instances SET active=0,state='removed',ram=0,cpu=0,container_id=NULL WHERE id=?",
                                    (instance_id,))
                else:
                    self.db.execute('UPDATE instances SET state=?,container_id=? WHERE id=? AND active=1',
                                    (state, container_id, instance_id))
                self.db.execute("UPDATE operations SET status='completed',error=NULL WHERE id=?",
                                (operation_id,))

    def fail(self, operation_id, code):
        with self.transaction():
            self.db.execute("UPDATE operations SET status='failed',error=? WHERE id=? AND status!='completed'", (code, operation_id))
            self.db.execute("UPDATE instances SET state='failed' WHERE state='preparing' AND active=1 AND id=(SELECT instance_id FROM operations WHERE id=?)", (operation_id,))

    def close(self):
        with self.lock:
            self.db.close()
