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
        from types import SimpleNamespace
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
            calls_before_replay = len(engine.calls)
            replayed = service.replay({'actor_id': 'alice', 'action': 'create',
                                       'idempotency_key': 'key', 'settings_revision': 0})
            self.assertEqual(replayed['runtime']['state'], 'running')
            self.assertEqual(len(engine.calls), calls_before_replay)
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
                             'A failed volume purge must keep the retained disk reservation')
            self.assertFalse(volumes.purged)

            class BusyCheckpoint:
                def __init__(self, database):
                    self.database = database
                def execute(self, sql, *args):
                    if sql == 'PRAGMA wal_checkpoint(TRUNCATE)':
                        return SimpleNamespace(fetchone=lambda: (1, 1, 0))
                    return self.database.execute(sql, *args)
                def __getattr__(self, name):
                    return getattr(self.database, name)

            database = store.db
            setattr(store, 'db', BusyCheckpoint(database))
            try:
                with self.assertRaises(ServiceError) as checkpoint_error:
                    service.action(purge)
            finally:
                setattr(store, 'db', database)
            self.assertEqual(checkpoint_error.exception.code, 'purge_scrub_unverified')
            self.assertEqual(checkpoint_error.exception.status, 503)
            self.assertEqual(store.totals(), (0, 0, profile.agent_limits.disk_bytes),
                             'Do not release reservation before SQLite scrub is checkpointed')
            self.assertTrue(volumes.purged)

            result = service.action(purge)
            self.assertEqual(result['runtime']['state'], 'purged')
            self.assertEqual(store.totals(), (0, 0, 0), 'Release disk only after storage purge succeeds')
            self.assertTrue(volumes.purged)
            purged_instance = store.instance(instance_id)
            self.assertEqual(purged_instance['settings'], '{}')
            self.assertEqual(purged_instance['gateway_token'], '')
            self.assertIsNone(store.saved_request('alice', 'key'))
            create_payloads = [row['payload'] for row in store.db.execute(
                "SELECT payload FROM operations WHERE instance_id=? AND action='create'", (instance_id,))]
            self.assertNotIn('Hello', ''.join(create_payloads))
            redacted_record = json.loads(create_payloads[0])
            self.assertEqual(redacted_record, {'redacted': True,
                'replay': {'action': 'create', 'settings_revision': 0, 'instance_id': None}})
            replayed_create = service.replay({key: value for key, value in payload.items()
                                              if key != 'settings'})
            self.assertEqual(replayed_create['runtime']['state'], 'purged')
            with self.assertRaises(ServiceError) as redacted_create:
                service.action(payload)
            self.assertEqual(redacted_create.exception.code, 'idempotency_conflict')
            calls_after_success = volumes.purge_calls
            replay = service.replay({key: value for key, value in purge.items()
                                     if key != 'settings'})
            self.assertEqual(replay['runtime']['state'], 'purged')
            self.assertEqual(volumes.purge_calls, calls_after_success, 'Exact replay must not repeat purge effects')


class XfsPurgeTests(unittest.TestCase):
    def test_fd_cleanup_recurses_only_through_open_directory_descriptors(self):
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch
        from supervisor.volumes import XfsVolumes

        directory = SimpleNamespace(st_dev=123, st_ino=456, st_mode=stat.S_IFDIR | 0o700)
        file_info = SimpleNamespace(st_dev=123, st_ino=789, st_mode=stat.S_IFREG | 0o600)

        class Entries:
            def __init__(self, names):
                self.names = names
            def __enter__(self):
                return [SimpleNamespace(name=name) for name in self.names]
            def __exit__(self, *_args):
                return False

        def scandir(fd):
            return Entries(['state'] if fd == 10 else ['private.txt'])

        def stat_at(name, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            return directory if dir_fd == 10 and name == 'state' else file_info

        with patch('supervisor.volumes.os.scandir', side_effect=scandir), \
             patch('supervisor.volumes.os.stat', side_effect=stat_at), \
             patch('supervisor.volumes.os.open', return_value=11) as open_child, \
             patch('supervisor.volumes.os.fstat', return_value=directory), \
             patch.object(XfsVolumes, '_mount_id', return_value=7), \
             patch('supervisor.volumes.os.unlink') as unlink, \
             patch('supervisor.volumes.os.rmdir') as rmdir, \
             patch('supervisor.volumes.os.fsync'), patch('supervisor.volumes.os.close'):
            XfsVolumes._clear_contents_fd(10, device=123, mount_id=7)

        self.assertEqual(open_child.call_args.kwargs['dir_fd'], 10)
        unlink.assert_called_once_with('private.txt', dir_fd=11)
        rmdir.assert_called_once_with('state', dir_fd=10)

    def test_fd_cleanup_refuses_directory_swapped_before_open(self):
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch
        from supervisor.volumes import XfsVolumes

        directory = SimpleNamespace(st_dev=123, st_ino=456, st_mode=stat.S_IFDIR | 0o700)

        class Entries:
            def __enter__(self):
                return [SimpleNamespace(name='victim')]
            def __exit__(self, *_args):
                return False

        nofollow = 0x20000
        directory_flag = 0x10000
        with patch('supervisor.volumes.os.O_NOFOLLOW', nofollow, create=True), \
             patch('supervisor.volumes.os.O_DIRECTORY', directory_flag, create=True), \
             patch('supervisor.volumes.os.scandir', return_value=Entries()), \
             patch('supervisor.volumes.os.stat', return_value=directory), \
             patch('supervisor.volumes.os.open', side_effect=OSError('O_NOFOLLOW rejected swapped symlink')) as open_child, \
             patch('supervisor.volumes.os.unlink') as unlink, patch('supervisor.volumes.os.rmdir') as rmdir:
            with self.assertRaises(OSError):
                XfsVolumes._clear_contents_fd(10, device=123, mount_id=7)
        self.assertEqual(open_child.call_args.kwargs['dir_fd'], 10)
        flags = open_child.call_args.args[1]
        self.assertTrue(flags & nofollow)
        self.assertTrue(flags & directory_flag)
        unlink.assert_not_called()
        rmdir.assert_not_called()

    def test_database_can_write_existing_file_without_create_and_readonly_verify_stays_readonly(self):
        import os
        import sqlite3
        import stat
        import sys
        from contextlib import closing
        from types import SimpleNamespace
        from unittest.mock import patch
        from supervisor.config import validate_profile
        from supervisor.volumes import XfsVolumes

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mount = base / 'mount'
            mount.mkdir()
            state_dir = base / 'service-state'
            state_dir.mkdir(mode=0o700)
            profile = validate_profile(dict(schema_version=1, profile_version='database-mode-test', mode='lab',
                storage=dict(backend='xfs_project_quota', mountpoint='/mnt/purge-test',
                             expected_uuid='11111111-2222-4333-8444-555555555555'),
                agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
            volumes = XfsVolumes(profile, state_dir)
            volumes.mountpoint = mount
            with closing(sqlite3.connect(volumes.db_path)) as db:
                with db:
                    db.execute("CREATE TABLE volume_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    binding = volumes.profile.storage.expected_uuid.lower() + ':' + str(mount)
                    db.execute("INSERT INTO volume_meta VALUES ('binding', ?)", (binding,))
                    db.execute('CREATE TABLE probe (value TEXT NOT NULL)')
                    db.execute("INSERT INTO probe VALUES ('before')")
            (state_dir / 'storage.lock').touch()
            fake_info = SimpleNamespace(st_dev=mount.stat().st_dev + 1,
                                        st_mode=stat.S_IFDIR | 0o700, st_uid=0)

            def open_private(path, _create):
                return os.open(path, os.O_RDONLY)

            fake_fcntl = SimpleNamespace(LOCK_EX=1, flock=lambda _fd, _operation: None)
            with patch.dict(sys.modules, {'fcntl': fake_fcntl}), \
                 patch.object(volumes, '_canonical', return_value=fake_info), \
                 patch.object(volumes, '_trusted_ancestors'), \
                 patch.object(volumes, '_private_file', side_effect=open_private):
                with volumes._database(create=False) as readonly:
                    with self.assertRaises(sqlite3.OperationalError):
                        readonly.execute("UPDATE probe SET value='must-not-write'")
                with volumes._database(create=False, writable=True) as writable:
                    writable.execute("UPDATE probe SET value='after'")
                missing = state_dir / 'must-not-be-created.sqlite3'
                volumes.db_path = missing
                with self.assertRaises(FileNotFoundError):
                    with volumes._database(create=False, writable=True):
                        pass
                self.assertFalse(missing.exists())

            with closing(sqlite3.connect(base / 'service-state' / 'storage.sqlite3')) as db:
                self.assertEqual(db.execute('SELECT value FROM probe').fetchone()[0], 'after')

    def test_purge_retries_partial_tree_cleanup_and_releases_only_recorded_project(self):
        import sqlite3
        import stat
        from types import SimpleNamespace
        from contextlib import closing, contextmanager
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
            with closing(sqlite3.connect(volumes.db_path, isolation_level=None)) as db:
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
            def fake_database(create, *, writable=False):
                self.assertFalse(create)
                self.assertTrue(writable)
                connection = sqlite3.connect(volumes.db_path, isolation_level=None)
                connection.row_factory = sqlite3.Row
                try:
                    yield connection
                finally:
                    connection.close()

            quota_calls = []
            limits = iter([((0, 0, 4), (0, 0, 1024)),
                           ((0, 0, 4), (0, 0, 1024)),
                           ((0, 0, 4), (0, 0, 1024)), (None, None)])
            fsxattr = iter([(42, True), (42, True), (0, False)])
            fake_info = SimpleNamespace(st_dev=123, st_ino=456, st_uid=0,
                                        st_mode=stat.S_IFDIR | 0o700)
            clear_calls = 0
            def fake_clear(path, _device, _inode):
                nonlocal clear_calls
                clear_calls += 1
                if clear_calls == 1:
                    marker.unlink()
                    raise OSError('synthetic failure after one file was removed')
                actual = path.lstat()
                XfsVolumes._clear_contents_path(path, actual.st_dev, actual.st_ino)

            with patch.object(volumes, '_preflight'), patch.object(volumes, '_database', fake_database), \
                 patch.object(volumes, '_clear_contents', side_effect=fake_clear), \
                 patch.object(volumes, '_canonical', return_value=fake_info), patch.object(XfsVolumes, '_sync_dir'), \
                 patch('supervisor.volumes.os.path.ismount', return_value=False), \
                 patch.object(volumes, '_fsxattr', side_effect=lambda _path: next(fsxattr)), \
                 patch.object(volumes, '_limits', side_effect=lambda _project_id: next(limits)), \
                 patch.object(volumes, '_quota', side_effect=lambda command: quota_calls.append(command)):
                with self.assertRaisesRegex(OSError, 'after one file was removed'):
                    volumes.purge(instance_id, 4096, expected_project_id=42)
                self.assertFalse(marker.exists())
                self.assertTrue(other_marker.exists())
                self.assertEqual(quota_calls, [])
                with closing(sqlite3.connect(volumes.db_path.as_uri() + '?mode=ro', uri=True)) as read_db:
                    stage = read_db.execute('SELECT stage FROM volume_projects WHERE instance_id=?',
                                             (instance_id,)).fetchone()[0]
                    self.assertEqual(stage, 'purging')
                result = volumes.purge(instance_id, 4096, expected_project_id=42)

            self.assertEqual(result, {'purged': True, 'project_id': 42})
            self.assertFalse(root.exists())
            self.assertTrue(other_marker.exists())
            with closing(sqlite3.connect(volumes.db_path.as_uri() + '?mode=ro', uri=True)) as read_db:
                self.assertEqual(read_db.execute('SELECT count(*) FROM volume_projects').fetchone()[0], 0)
                self.assertEqual(read_db.execute('SELECT count(*) FROM volume_directories').fetchone()[0], 0)
            self.assertTrue(any(command.startswith('project -C -p ') for command in quota_calls))
            self.assertTrue(any(command.startswith('limit -p bsoft=0 bhard=0') for command in quota_calls))


if __name__ == '__main__':
    unittest.main()
