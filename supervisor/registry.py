"""File-backed create reservations, not authentication or a runtime executor.

The trusted service supplies actor, versioned profile and capacity snapshots.
Strings are 1..128 characters; numeric values fit signed SQLite integers.
All stored instances consume a slot and budget forever until an executor exists.
"""

import hashlib
import json
import re
import sqlite3
import unicodedata
import uuid
from contextlib import closing
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReservationCapacity:
    """Total reservation ceilings, not remaining free amounts after reservations."""
    ram_bytes: int
    cpu_units: int
    disk_bytes: int


class OneInstanceLimit(Exception):
    pass


class CapacityExceeded(Exception):
    pass


class IdempotencyConflict(Exception):
    pass


class ProfileVersionConflict(Exception):
    pass


class Registry:
    @staticmethod
    def _text(value):
        if (type(value) is not str or not 1 <= len(value) <= 128
                or not value.strip() or any(unicodedata.category(c) in
                                           ('Cc', 'Cf', 'Cs') for c in value)):
            raise ValueError('Expected 1..128 characters without controls')

    @staticmethod
    def _integer(value, minimum=1):
        if type(value) is not int or not minimum <= value <= 2**63 - 1:
            raise ValueError('Expected a strict SQLite integer within range')

    def __init__(self, path):
        self.path = path
        with closing(self._connect()) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS deployment_profiles (
                version TEXT PRIMARY KEY, fingerprint TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS instances (
                id TEXT PRIMARY KEY, owner_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL, settings_revision INTEGER NOT NULL,
                profile_version TEXT NOT NULL, ram_bytes INTEGER NOT NULL,
                cpu_units INTEGER NOT NULL, disk_bytes INTEGER NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS operations (
                id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
                instance_id TEXT NOT NULL REFERENCES instances(id),
                kind TEXT NOT NULL, status TEXT NOT NULL,
                idempotency_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
                UNIQUE(owner_id, idempotency_key))''')

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
        return db

    def reserve_create(self, actor_id, *, idempotency_key, settings_revision,
                       profile_version, ram_bytes, cpu_units, disk_bytes,
                       capacity_ram_bytes=None, capacity_cpu_units=None,
                       capacity_disk_bytes=None, admit=None, profile_fingerprint=None):
        """Bind/admit/reserve atomically, returning an existing exact replay first.

        Static capacities keep the standalone legacy interface. New coordinators
        supply a full-profile fingerprint and a quick trusted admission callback;
        no host collector or external effects belong inside that callback.
        """
        for value in (actor_id, idempotency_key, profile_version):
            self._text(value)
        for value in (ram_bytes, cpu_units, disk_bytes):
            self._integer(value)
        capacities = (capacity_ram_bytes, capacity_cpu_units, capacity_disk_bytes)
        if admit is None:
            for value in capacities:
                self._integer(value)
        elif not callable(admit) or any(value is not None for value in capacities):
            raise ValueError('Use one trusted callable capacity source, not mixed inputs')
        self._integer(settings_revision, minimum=0)
        if profile_fingerprint is not None and (
                type(profile_fingerprint) is not str
                or re.fullmatch(r'[0-9a-f]{64}', profile_fingerprint) is None):
            raise ValueError('Exact lowercase SHA256 profile fingerprint required')
        fingerprint = hashlib.sha256(json.dumps(
            [settings_revision, profile_version, ram_bytes, cpu_units, disk_bytes],
            ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            bound_profile = db.execute(
                'SELECT fingerprint FROM deployment_profiles WHERE version = ?',
                (profile_version,)).fetchone()
            if bound_profile is not None and bound_profile['fingerprint'] != profile_fingerprint:
                raise ProfileVersionConflict('Profile version is bound to different content')
            if (profile_fingerprint is not None and bound_profile is None
                    and db.execute('SELECT 1 FROM instances WHERE profile_version = ?',
                                   (profile_version,)).fetchone() is not None):
                raise ProfileVersionConflict('Legacy profile history is unknown; use a new version')
            existing = db.execute(
                'SELECT * FROM operations WHERE owner_id = ? AND idempotency_key = ?',
                (actor_id, idempotency_key)).fetchone()
            if existing is not None:
                if existing['fingerprint'] != fingerprint:
                    raise IdempotencyConflict('Key already used for another request')
                return self._operation(existing)
            if db.execute('SELECT 1 FROM instances WHERE owner_id = ?',
                          (actor_id,)).fetchone():
                raise OneInstanceLimit('Owner already has a reserved instance')
            if admit is not None:
                # Trusted, short in-memory admission only. No Docker/remote I/O here.
                # Run after replay detection and after BEGIN IMMEDIATE acquired the lock.
                capacity = admit()
                if type(capacity) is not ReservationCapacity:
                    raise ValueError('Typed reservation capacity required')
                capacities = (capacity.ram_bytes, capacity.cpu_units, capacity.disk_bytes)
                for value in capacities:
                    self._integer(value, minimum=0)
            reserves = db.execute(
                'SELECT ram_bytes, cpu_units, disk_bytes FROM instances').fetchall()
            for index, (requested, capacity) in enumerate(zip(
                    (ram_bytes, cpu_units, disk_bytes),
                    capacities)):
                if sum(row[index] for row in reserves) + requested > capacity:
                    raise CapacityExceeded('Insufficient reservation capacity')
            if profile_fingerprint is not None and bound_profile is None:
                db.execute('INSERT INTO deployment_profiles VALUES (?, ?)',
                           (profile_version, profile_fingerprint))
            instance_id, operation_id = uuid.uuid4().hex, uuid.uuid4().hex
            db.execute('INSERT INTO instances VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                       (instance_id, actor_id, 'reserved', settings_revision,
                        profile_version, ram_bytes, cpu_units, disk_bytes))
            db.execute('INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (operation_id, actor_id, instance_id, 'create', 'queued',
                        idempotency_key, fingerprint))
        return self.get_operation(actor_id, operation_id)

    def _get(self, table, actor_id, identifier):
        self._text(actor_id)
        self._text(identifier)
        query = {'instances': 'SELECT * FROM instances WHERE id = ?',
                 'operations': 'SELECT * FROM operations WHERE id = ?'}[table]
        with closing(self._connect()) as db:
            row = db.execute(query, (identifier,)).fetchone()
        if row is None:
            raise KeyError(identifier)
        if row['owner_id'] != actor_id:
            raise PermissionError('Access denied')
        return dict(row)

    def get_instance(self, actor_id, instance_id):
        return self._get('instances', actor_id, instance_id)

    @staticmethod
    def _operation(row):
        return {key: row[key] for key in
                ('id', 'owner_id', 'instance_id', 'kind', 'status')}

    def get_operation(self, actor_id, operation_id):
        return self._operation(self._get('operations', actor_id, operation_id))
