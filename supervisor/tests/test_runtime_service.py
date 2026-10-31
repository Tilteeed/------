"""One portable workflow smoke; no Docker, mounts, or host mutation."""
import tempfile
import unittest
from contextlib import ExitStack, closing
from pathlib import Path


class DurableIntentSmoke(unittest.TestCase):
    def test_retained_disk_and_exact_replay(self):
        from supervisor.runtime_store import RuntimeStore, StoreError
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(Path(tmp) / 'runtime.sqlite3', 'v1', 'a' * 64)
            payload = {'actor_id': 'alice', 'action': 'create', 'idempotency_key': 'one',
                       'settings_revision': 1, 'settings': {'name': 'Agent', 'instructions': 'Hello'}}
            limits = (10, 20, 30)
            first = store.intent(payload, limits, (100, 100, 50))
            self.assertEqual(first['status'], 'pending')
            self.assertEqual(first['instance_id'], store.intent(payload, limits, (100, 100, 50))['instance_id'])
            changed = dict(payload, settings_revision=2)
            with self.assertRaises(StoreError):
                store.intent(changed, limits, (100, 100, 50))
            store.complete(first['id'], 'running', 'container')
            remove = dict(payload, action='remove', idempotency_key='remove')
            operation = store.intent(remove, limits, (100, 100, 50))
            store.complete(operation['id'], 'removed')
            self.assertIsNone(store.current('alice'))
            with self.assertRaises(StoreError):
                store.intent(dict(payload, idempotency_key='two'), limits, (100, 100, 50))
            self.assertEqual(store.intent(payload, limits, (100, 100, 50))['instance_id'], first['instance_id'])
            store.close()
            reopened = RuntimeStore(Path(tmp) / 'runtime.sqlite3', 'v1', 'a' * 64)
            self.assertEqual(reopened.totals(), (0, 0, 30))
            reopened.close()


class ServiceWorkflowSmoke(unittest.TestCase):
    def test_quota_failure_retry_same_id_and_retain(self):
        from supervisor.service import RuntimeService, ServiceError
        from supervisor.config import validate_profile
        from supervisor.runtime_store import RuntimeStore
        from dataclasses import asdict
        import hashlib
        import json
        profile = validate_profile(dict(schema_version=1, profile_version='smoke', mode='lab',
            storage=dict(backend='xfs_project_quota', mountpoint='/srv/agents', expected_uuid='12345678-1234-1234-1234-123456789abc'),
            agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
        fingerprint = hashlib.sha256(json.dumps(asdict(profile), sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()

        class Metrics:
            def snapshot(self):
                return dict(sampled_at=100, cpu_window_seconds=60, total_ram_bytes=10**14,
                            available_ram_bytes=10**14, cpu_percent=0, free_disk_bytes=10**14,
                            total_cpu_millicores=1000000, total_disk_bytes=10**14)

        class Volumes:
            valid = False
            def prepare(self, instance_id, disk_bytes):
                return self.verify(instance_id, disk_bytes)
            def verify(self, instance_id, disk_bytes):
                return dict(host_path=str(Path(tmp) / instance_id), project_id=1, disk_quota_verified=self.valid)
            def purge(self, instance_id, disk_bytes, expected_project_id=None):
                self.purge_calls += 1
                if self.purge_calls == 1:
                    raise OSError('synthetic incomplete purge')
                self.purged = True
                return dict(purged=True, project_id=expected_project_id or 1)
            purge_calls = 0
            purged = False

        class Engine:
            calls = []
            state = 'absent'
            def inspect(self, instance_id):
                return dict(state=self.state, gateway='unknown', container_id='c' if self.state != 'absent' else None)
            def create(self, instance_id, host_path, limits, token):
                self.calls.append(('create', instance_id))
                self.state = 'stopped'
                return 'c'
            def start(self, instance_id):
                self.calls.append(('start', instance_id))
                self.state = 'running'
            def stop(self, instance_id):
                self.state = 'stopped'
            def remove(self, instance_id):
                self.state = 'absent'

        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            store = stack.enter_context(closing(RuntimeStore(Path(tmp) / 'runtime.sqlite3', profile.profile_version, fingerprint)))
            volumes, engine = Volumes(), Engine()
            service = RuntimeService(profile, store, volumes, engine, Metrics(),
                                     capacities=(10**14, 1000000, 10**14), disk_floor_bytes=0,
                                     clock=lambda: 100, initialize=lambda *args: None)
            payload = dict(actor_id='alice', action='create', idempotency_key='key',
                           settings_revision=0, settings=dict(name='Agent', instructions='Hello'))
            with self.assertRaises(ServiceError):
                service.action(payload)
            instance_id = store.current('alice')['id']
            self.assertEqual(engine.calls, [])
            volumes.valid = True
            result = service.action(payload)
            self.assertEqual(result['runtime']['state'], 'running')
            self.assertEqual(result['runtime']['instance_id'], instance_id)
            service.action(dict(payload, action='remove', idempotency_key='remove'))
            self.assertEqual(store.totals(), (0, 0, profile.agent_limits.disk_bytes))
            self.assertEqual([item['instance_id'] for item in store.retained('alice')], [instance_id])
            self.assertEqual(store.retained('bob'), [])
            replay = service.action(payload)
            self.assertEqual(replay['runtime']['state'], 'removed')
            self.assertEqual(len(engine.calls), 2)
            purge = dict(payload, action='purge', idempotency_key='purge-1', instance_id=instance_id)
            foreign_purge = dict(purge, actor_id='bob', idempotency_key='foreign-purge')
            with self.assertRaises(ServiceError) as foreign_error:
                service.action(foreign_purge)
            self.assertEqual(foreign_error.exception.code, 'instance_not_found')
            self.assertEqual(volumes.purge_calls, 0, 'A foreign owner must not reach storage deletion')
            with self.assertRaises(ServiceError):
                service.action(purge)
            self.assertEqual(store.totals(), (0, 0, profile.agent_limits.disk_bytes),
                             'A failed purge must keep the retained disk reservation')
            self.assertFalse(volumes.purged)
            result = service.action(purge)
            self.assertEqual(result['runtime']['state'], 'purged')
            self.assertEqual(store.totals(), (0, 0, 0), 'Release disk only after storage purge succeeds')
            self.assertTrue(volumes.purged)
            calls_after_success = volumes.purge_calls
            replay = service.action(purge)
            self.assertEqual(replay['runtime']['state'], 'purged')
            self.assertEqual(volumes.purge_calls, calls_after_success, 'Exact replay must not repeat purge effects')


class XfsPurgeTests(unittest.TestCase):
    def test_purge_clears_only_the_recorded_tree_and_project_quota(self):
        import sqlite3
        import stat
        from types import SimpleNamespace
        from contextlib import contextmanager
        from unittest.mock import patch
        from supervisor.config import validate_profile
        from supervisor.volumes import XfsVolumes

        instance_id = 'a' * 32
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mount = base / 'mount'
            root = mount / 'instances' / instance_id
            (root / 'state').mkdir(parents=True)
            marker = root / 'state' / 'private.txt'
            marker.write_text('owned data', encoding='utf-8')
            other = mount / 'instances' / ('b' * 32)
            other.mkdir()
            other_marker = other / 'keep.txt'
            other_marker.write_text('not this owner', encoding='utf-8')
            profile = validate_profile(dict(schema_version=1, profile_version='purge-test', mode='lab',
                storage=dict(backend='xfs_project_quota', mountpoint='/mnt/purge-test',
                             expected_uuid='11111111-2222-4333-8444-555555555555'),
                agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
            volumes = XfsVolumes(profile, base / 'service-state')
            volumes.mountpoint = mount
            volumes.instances = mount / 'instances'
            volumes.db_path.parent.mkdir()
            volumes.db_path.touch()
            db = sqlite3.connect(':memory:', isolation_level=None)
            db.row_factory = sqlite3.Row
            db.executescript('''
                CREATE TABLE volume_projects (project_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id TEXT NOT NULL UNIQUE, disk_bytes INTEGER NOT NULL, stage TEXT NOT NULL);
                CREATE TABLE volume_directories (path TEXT PRIMARY KEY, device INTEGER NOT NULL,
                    inode INTEGER NOT NULL, stage TEXT NOT NULL);
            ''')
            root_info = SimpleNamespace(st_dev=123, st_ino=456)
            db.execute('INSERT INTO volume_projects VALUES (?,?,?,?)', (42, instance_id, 4096, 'ready'))
            db.execute('INSERT INTO volume_directories VALUES (?,?,?,?)',
                       (root.relative_to(mount).as_posix(), root_info.st_dev, root_info.st_ino, 'ready'))

            @contextmanager
            def fake_database(create):
                yield db

            quota_calls = []
            limits = iter([((0, 0, 4), (0, 0, 1024)),
                           ((0, 0, 4), (0, 0, 1024)), (None, None)])
            fsxattr = iter([(42, True), (0, False)])
            fake_info = SimpleNamespace(st_dev=123, st_ino=456, st_uid=0,
                                        st_mode=stat.S_IFDIR | 0o700)
            with patch.object(volumes, '_preflight'), patch.object(volumes, '_database', fake_database), \
                 patch.object(volumes, '_canonical', return_value=fake_info), patch.object(XfsVolumes, '_sync_dir'), \
                 patch('supervisor.volumes.os.path.ismount', return_value=False), \
                 patch.object(volumes, '_fsxattr', side_effect=lambda _path: next(fsxattr)), \
                 patch.object(volumes, '_limits', side_effect=lambda _project_id: next(limits)), \
                 patch.object(volumes, '_quota', side_effect=lambda command: quota_calls.append(command)):
                result = volumes.purge(instance_id, 4096, expected_project_id=42)

            self.assertEqual(result, {'purged': True, 'project_id': 42})
            self.assertFalse(root.exists())
            self.assertTrue(other_marker.exists())
            self.assertEqual(db.execute('SELECT count(*) FROM volume_projects').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM volume_directories').fetchone()[0], 0)
            self.assertTrue(any(command.startswith('project -C -p ') for command in quota_calls))
            self.assertTrue(any(command.startswith('limit -p bsoft=0 bhard=0') for command in quota_calls))
            db.close()


if __name__ == '__main__':
    unittest.main()
