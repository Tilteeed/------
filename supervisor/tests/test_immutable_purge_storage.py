"""Synthetic regression for the currently unsupported immutable purge path."""
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sqlite3
import stat
import tempfile
import unittest

from supervisor.config import validate_profile
from supervisor.volumes import XfsVolumes


class ImmutablePurgeStorageTests(unittest.TestCase):
    def test_immutable_unlink_failure_retains_project_and_quota(self):
        instance_id = 'a' * 32
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mount = base / 'mount'
            root = mount / 'instances' / instance_id
            state = root / 'state'
            state.mkdir(parents=True)
            config = state / 'openclaw.json'
            config.write_text('{}', encoding='utf-8')
            profile = validate_profile(dict(
                schema_version=1, profile_version='purge-test', mode='lab',
                storage=dict(backend='xfs_project_quota', mountpoint='/mnt/purge-test',
                             expected_uuid='11111111-2222-4333-8444-555555555555'),
                agent_limits=dict(ram_bytes=1024, cpu_millicores=100,
                                  pids_limit=32, disk_bytes=4096)))
            volumes = XfsVolumes(profile, base / 'service-state')
            volumes.mountpoint, volumes.instances = mount, mount / 'instances'
            volumes.db_path.parent.mkdir()
            with closing(sqlite3.connect(volumes.db_path, isolation_level=None)) as db:
                db.executescript('''
                    CREATE TABLE volume_projects (project_id INTEGER PRIMARY KEY,
                        instance_id TEXT NOT NULL UNIQUE, disk_bytes INTEGER NOT NULL, stage TEXT NOT NULL);
                    CREATE TABLE volume_directories (path TEXT PRIMARY KEY, device INTEGER NOT NULL,
                        inode INTEGER NOT NULL, stage TEXT NOT NULL);
                ''')
                db.execute('INSERT INTO volume_projects VALUES (?,?,?,?)', (42, instance_id, 4096, 'ready'))
                db.execute('INSERT INTO volume_directories VALUES (?,?,?,?)',
                           (root.relative_to(mount).as_posix(), 123, 456, 'ready'))

            @contextmanager
            def database(create, *, writable=False):
                self.assertFalse(create)
                self.assertTrue(writable)
                with closing(sqlite3.connect(volumes.db_path, isolation_level=None)) as db:
                    db.row_factory = sqlite3.Row
                    yield db

            info = SimpleNamespace(st_dev=123, st_ino=456, st_uid=0,
                                   st_mode=stat.S_IFDIR | 0o700)
            quota_commands = []
            with patch.object(volumes, '_preflight'), patch.object(volumes, '_database', database), \
                 patch.object(volumes, '_canonical', return_value=info), \
                 patch.object(volumes, '_fsxattr', return_value=(42, True)), \
                 patch.object(volumes, '_limits', return_value=((0, 0, 4), (0, 0, 1024))), \
                 patch.object(volumes, '_quota', side_effect=quota_commands.append), \
                 patch.object(volumes, '_clear_contents', side_effect=PermissionError('immutable')), patch.object(volumes, '_purge_managed_config'):
                with self.assertRaisesRegex(PermissionError, 'immutable'):
                    volumes.purge(instance_id, 4096, expected_project_id=42)
            self.assertTrue(config.exists())
            self.assertEqual(quota_commands, [])
            with closing(sqlite3.connect(volumes.db_path)) as db:
                self.assertEqual(db.execute('SELECT project_id, stage FROM volume_projects').fetchall(),
                                 [(42, 'purging')])


if __name__ == '__main__':
    unittest.main()
