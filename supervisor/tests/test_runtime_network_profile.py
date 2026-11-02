"""Additive network-profile metadata migration; existing data is preserved."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from supervisor.runtime_store import RuntimeStore


def create_legacy_database(path, *, wal=False, keep_open=False):
    db = sqlite3.connect(path, isolation_level=None)
    if wal:
        db.execute('PRAGMA journal_mode=WAL')
    db.executescript('''
        CREATE TABLE binding (id INTEGER PRIMARY KEY CHECK(id=1), version TEXT NOT NULL, fingerprint TEXT NOT NULL);
        CREATE TABLE instances (
            id TEXT PRIMARY KEY, actor TEXT NOT NULL, active INTEGER NOT NULL,
            state TEXT NOT NULL, settings TEXT NOT NULL, revision INTEGER NOT NULL,
            ram INTEGER NOT NULL, cpu INTEGER NOT NULL, disk INTEGER NOT NULL,
            gateway_token TEXT NOT NULL, storage TEXT, container_id TEXT,
            initialized INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE operations (
            id TEXT PRIMARY KEY, actor TEXT NOT NULL, key TEXT NOT NULL,
            payload TEXT NOT NULL, instance_id TEXT NOT NULL REFERENCES instances(id),
            action TEXT NOT NULL, status TEXT NOT NULL, error TEXT,
            UNIQUE(actor,key));
    ''')
    db.execute('INSERT INTO binding VALUES (1,?,?)', ('site-v1', 'a' * 64))
    db.execute('''INSERT INTO instances
        (id,actor,active,state,settings,revision,ram,cpu,disk,gateway_token,storage,container_id,initialized)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        ('1' * 32, 'alice', 0, 'removed', '{"name":"Saved"}', 2,
         0, 0, 10, '', '{"host_path":"/synthetic"}', None, 1))
    db.commit()
    if keep_open:
        return db
    db.close()
    return None


class RuntimeNetworkProfileTests(unittest.TestCase):
    def test_old_database_is_not_mutated_implicitly(self):
        from supervisor.runtime_store import StoreError
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.sqlite3'
            create_legacy_database(path)
            with self.assertRaises(StoreError) as caught:
                RuntimeStore(path, 'site-v1', 'a' * 64)
            self.assertEqual(caught.exception.code, 'runtime_schema_migration_required')
            db = sqlite3.connect(path)
            try:
                columns = {row[1] for row in db.execute('PRAGMA table_info(instances)')}
                self.assertNotIn('network_profile', columns)
                row = db.execute('SELECT state,disk,settings FROM instances WHERE id=?',
                                 ('1' * 32,)).fetchone()
                self.assertEqual(row, ('removed', 10, '{"name":"Saved"}'))
            finally:
                db.close()

    def test_explicit_migration_creates_backup_and_preserves_retained_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.sqlite3'
            backup = Path(tmp) / 'runtime-before-network-profile.sqlite3'
            create_legacy_database(path)
            result = RuntimeStore.migrate_network_profile_schema(path, backup)
            self.assertEqual(result['legacy_rows'], 1)
            self.assertTrue(backup.is_file())

            backup_db = sqlite3.connect(backup)
            try:
                columns = {row[1] for row in backup_db.execute('PRAGMA table_info(instances)')}
                self.assertNotIn('network_profile', columns)
                self.assertEqual(backup_db.execute('SELECT COUNT(*) FROM instances').fetchone()[0], 1)
            finally:
                backup_db.close()

            store = RuntimeStore(path, 'site-v1', 'a' * 64)
            try:
                row = store.instance('1' * 32)
                self.assertEqual(row['network_profile'], 'legacy_none')
                self.assertEqual(row['state'], 'removed')
                self.assertEqual(row['disk'], 10)
                self.assertEqual(row['settings'], '{"name":"Saved"}')
                self.assertEqual(store.retained('alice')[0]['instance_id'], '1' * 32)
            finally:
                store.close()

    def test_explicit_migration_backup_includes_committed_wal_pages(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.sqlite3'
            backup = Path(tmp) / 'runtime-backup.sqlite3'
            legacy_connection = create_legacy_database(path, wal=True, keep_open=True)
            assert legacy_connection is not None
            try:
                self.assertTrue(Path(str(path) + '-wal').is_file())
                RuntimeStore.migrate_network_profile_schema(path, backup)
            finally:
                legacy_connection.close()
            backup_db = sqlite3.connect(backup)
            try:
                self.assertEqual(backup_db.execute(
                    'SELECT settings FROM instances WHERE id=?', ('1' * 32,)).fetchone()[0],
                    '{"name":"Saved"}')
            finally:
                backup_db.close()

    def test_migration_cli_requires_explicit_apply_flag(self):
        import contextlib
        import io
        from scripts.migrate_runtime_network_profile import main
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.sqlite3'
            backup = Path(tmp) / 'runtime-backup.sqlite3'
            create_legacy_database(path)
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main(['--database', str(path), '--backup', str(backup)])
            self.assertEqual(caught.exception.code, 2)
            self.assertFalse(backup.exists())
            db = sqlite3.connect(path)
            try:
                columns = {row[1] for row in db.execute('PRAGMA table_info(instances)')}
                self.assertNotIn('network_profile', columns)
            finally:
                db.close()

    def test_migration_cli_applies_only_with_explicit_flag(self):
        import contextlib
        import io
        import json
        from scripts.migrate_runtime_network_profile import main
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.sqlite3'
            backup = Path(tmp) / 'runtime-backup.sqlite3'
            create_legacy_database(path)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(['--database', str(path), '--backup', str(backup), '--apply'])
            self.assertEqual(status, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report['status'], 'migrated')
            self.assertEqual(report['legacy_rows'], 1)
            self.assertEqual(Path(report['backup_path']), backup)
            self.assertTrue(backup.is_file())

    def test_agent_proxy_profile_reserves_sidecar_ram_and_cpu_atomically(self):
        from supervisor.runtime_store import StoreError
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(Path(tmp) / 'runtime.sqlite3', 'site-v1', 'c' * 64)
            try:
                limits = (1024, 100, 10)
                proxy_ram = 128 * 1024 * 1024
                proxy_cpu = 100
                operation = store.intent({
                    'actor_id': 'alice', 'action': 'create', 'idempotency_key': 'proxy-create-1',
                    'settings_revision': 1, 'settings': {'name': 'Agent', 'instructions': ''},
                }, limits, (proxy_ram + limits[0], proxy_cpu + limits[1], limits[2]),
                    network_profile='agent_proxy_v1')
                instance = store.instance(operation['instance_id'])
                self.assertEqual(instance['network_profile'], 'agent_proxy_v1')
                self.assertEqual(store.totals(), (proxy_ram + limits[0], proxy_cpu + limits[1], limits[2]))
                store.storage_ready(instance['id'], {'quota_verified': True})
                with self.assertRaises(StoreError) as caught:
                    store.intent({
                        'actor_id': 'bob', 'action': 'create', 'idempotency_key': 'proxy-create-2',
                        'settings_revision': 1, 'settings': {'name': 'Agent 2', 'instructions': ''},
                    }, limits, (proxy_ram + 2 * limits[0] + proxy_ram - 1,
                               proxy_cpu + 2 * limits[1], 2 * limits[2]),
                        network_profile='agent_proxy_v1')
                self.assertEqual(caught.exception.code, 'capacity_exhausted')
                remove = store.intent({
                    'actor_id': 'alice', 'action': 'remove', 'idempotency_key': 'proxy-remove-1',
                    'settings_revision': 1, 'instance_id': instance['id'],
                }, limits, (proxy_ram + limits[0], proxy_cpu + limits[1], limits[2]),
                    network_profile='agent_proxy_v1')
                store.complete(remove['id'], 'removed')
                self.assertEqual(store.totals(), (0, 0, limits[2]))
                with self.assertRaises(StoreError) as restore_error:
                    store.intent({
                        'actor_id': 'alice', 'action': 'restore',
                        'idempotency_key': 'proxy-restore-1', 'settings_revision': 1,
                        'instance_id': instance['id'],
                    }, limits,
                       (proxy_ram + limits[0] - 1, proxy_cpu + limits[1] - 1, limits[2]),
                       network_profile='agent_proxy_v1')
                self.assertEqual(restore_error.exception.code, 'capacity_exhausted')
            finally:
                store.close()

    def test_agent_proxy_admission_includes_sidecar_memory_reserve(self):
        from dataclasses import asdict
        import hashlib
        import json
        from supervisor.config import validate_profile
        from supervisor.service import RuntimeService, ServiceError
        with tempfile.TemporaryDirectory() as tmp:
            profile = validate_profile({
                'schema_version': 1, 'profile_version': 'proxy-admission', 'mode': 'lab',
                'storage': {'backend': 'xfs_project_quota', 'mountpoint': '/mnt/proxy',
                            'expected_uuid': '22222222-3333-4444-8555-666666666666'},
                'agent_limits': {'ram_bytes': 1024, 'cpu_millicores': 100,
                                 'pids_limit': 32, 'disk_bytes': 1024},
            })
            fingerprint = hashlib.sha256(json.dumps(asdict(profile), sort_keys=True,
                separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
            store = RuntimeStore(Path(tmp) / 'runtime.sqlite3', profile.profile_version, fingerprint)
            class Metrics:
                def snapshot(self):
                    return {'sampled_at': 100, 'cpu_window_seconds': 60,
                            'total_ram_bytes': 1024**4,
                            'available_ram_bytes': RuntimeStore.SIDECAR_RAM_BYTES + 1024 - 1,
                            'cpu_percent': 0, 'free_disk_bytes': 1024**4,
                            'total_cpu_millicores': 1_000_000,
                            'total_disk_bytes': 1024**4}
            service = RuntimeService(
                profile, store, None, None, Metrics(),
                capacities=(1024**4, 1_000_000, 1024**4), disk_floor_bytes=0,
                clock=lambda: 100, network_profile_default='agent_proxy_v1',
                control_ui_domain='agents.example.test',
                agent_network_pool='10.240.0.0/13',
                frontend_network_pool='10.248.0.0/13')
            try:
                with self.assertRaises(ServiceError) as caught:
                    service._admit(quota=True)
                self.assertEqual(caught.exception.code, 'admission_denied')
                service.network_profile_default = 'legacy_none'
                service._admit(quota=True)
            finally:
                store.close()

    def test_new_create_stays_network_none_until_policy_is_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(Path(tmp) / 'runtime.sqlite3', 'site-v1', 'b' * 64)
            try:
                operation = store.intent({
                    'actor_id': 'alice', 'action': 'create', 'idempotency_key': 'create-1',
                    'settings_revision': 1, 'settings': {'name': 'Agent', 'instructions': ''},
                }, (10, 10, 10), (100, 100, 100))
                instance = store.instance(operation['instance_id'])
                self.assertEqual(instance['network_profile'], 'legacy_none')
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()
