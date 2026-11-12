"""Real SQLite and temporary files; POSIX descriptors/metadata/ioctls are synthetic."""
from contextlib import closing, contextmanager, ExitStack
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
import os
import sqlite3
import stat
import tempfile
import unittest
from supervisor.config import validate_profile
from supervisor.volumes import XfsVolumes, RuntimeStorageError


class ManagedConfigPurgeTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            mount = Path(tmp) / 'mount'
            instance = 'a' * 32
            root = mount / 'instances' / instance
            state = root / 'state'
            state.mkdir(parents=True)
            config = state / 'openclaw.json'
            config.write_bytes(b'{}')
            (state / 'user.txt').write_bytes(b'user')
            profile = validate_profile(dict(schema_version=1, profile_version='purge-test', mode='lab',
                storage=dict(backend='xfs_project_quota', mountpoint='/mnt/purge-test',
                    expected_uuid='11111111-2222-4333-8444-555555555555'),
                agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
            v = XfsVolumes(profile, Path(tmp) / 'service-state')
            v.mountpoint, v.instances = mount, mount / 'instances'
            v.db_path.parent.mkdir()
            nodes = {p: NS(st_dev=123, st_ino=i, st_uid=u, st_gid=g, st_mode=m,
                          st_nlink=1, st_size=2) for p,i,u,g,m in (
                (root,456,0,0,stat.S_IFDIR|0o700), (state,457,1000,1000,stat.S_IFDIR|0o700),
                (config,458,0,1000,stat.S_IFREG|0o440))}
            with closing(sqlite3.connect(v.db_path, isolation_level=None)) as db:
                db.executescript('CREATE TABLE volume_projects(project_id INTEGER PRIMARY KEY, '
                    'instance_id TEXT, disk_bytes INTEGER, stage TEXT); '
                    'CREATE TABLE volume_directories(path TEXT PRIMARY KEY, device INTEGER, inode INTEGER, stage TEXT);')
                db.execute('INSERT INTO volume_projects VALUES(42,?,4096,?)', (instance,'ready'))
                for p in (root,state):
                    db.execute('INSERT INTO volume_directories VALUES(?,?,?,?)',
                        (p.relative_to(mount).as_posix(),123,nodes[p].st_ino,'ready'))
            @contextmanager
            def database(create, *, writable=False):
                self.assertFalse(create)
                self.assertTrue(writable)
                with closing(sqlite3.connect(v.db_path,isolation_level=None)) as db:
                    db.row_factory=sqlite3.Row
                    class Connection:
                        execute = db.execute
                        rollback = db.rollback
                        def commit(inner):
                            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                            if (f.fail == 'journal_commit' and 'volume_purge_configs' in tables
                                    and db.execute('SELECT count(*) FROM volume_purge_configs').fetchone()[0]):
                                raise sqlite3.OperationalError('injected journal commit')
                            db.commit()
                            if (f.fail == 'origin_commit_after'
                                    and db.execute('SELECT stage FROM volume_projects').fetchone()[0] == 'purging'):
                                raise sqlite3.OperationalError('injected after origin commit')
                    yield Connection()
            f=NS(v=v, instance=instance, root=root, state=state, config=config, nodes=nodes,
                 locked=True, project=True, quota=True, events=[], fail=None, swap=False, mount_drift=False)
            handles={}
            def at(name,dir_fd=None):
                return Path(name) if dir_fd is None else handles[dir_fd][0]/name
            def opened(name,flags,*,dir_fd=None):
                p=at(name,dir_fd)
                if not os.path.lexists(p): raise FileNotFoundError(str(p))
                self.assertTrue(flags & 0x20000)
                fd=100+len(handles); handles[fd]=(p,nodes[p]); return fd
            def entry(name,*,dir_fd=None,follow_symlinks=False):
                self.assertFalse(follow_symlinks)
                p=at(name,dir_fd)
                if not os.path.lexists(p): raise FileNotFoundError(str(p))
                return nodes[p]
            def unlink(name,*,dir_fd=None):
                p=at(name,dir_fd)
                if p==config:
                    if f.locked: raise PermissionError('synthetic immutable')
                    f.events.append('unlink')
                    if f.fail=='unlink_before': raise OSError('injected')
                os.unlink(p)
                if p==config and f.fail=='unlink_after': raise OSError('injected')
            def sync(fd):
                event='file_sync' if handles[fd][0]==config else 'dir_sync'
                f.events.append(event)
                if f.fail==event: raise OSError('injected')
            def clear(fd,enabled):
                self.assertFalse(enabled)
                self.assertEqual(handles[fd][0],config)
                with closing(sqlite3.connect(v.db_path)) as db:
                    self.assertEqual(db.execute('SELECT file_inode FROM volume_purge_configs').fetchone(),(458,))
                f.events.append('clear')
                if f.fail=='clear_before': raise OSError('injected')
                f.locked=False
                if f.swap: nodes[config]=NS(**{**vars(nodes[config]),'st_ino':999})
                if f.fail=='clear_after': raise OSError('injected')
                return False
            def quota(cmd):
                f.events.append(cmd)
                if cmd.startswith('project -C'): f.project=False
                if cmd.startswith('limit -p'): f.quota=False
            real=root.stat()
            def cleanup(path,device,inode):
                f.events.append('cleanup')
                if f.fail=='cleanup': raise OSError('injected')
                XfsVolumes._clear_contents_path(path,real.st_dev,real.st_ino)
            adapter=NS(**{n:getattr(os,n) for n in dir(os)})
            adapter.O_NOFOLLOW,adapter.O_DIRECTORY,adapter.O_NONBLOCK=0x20000,0x10000,0x800
            adapter.open,adapter.stat,adapter.fstat=opened,entry,lambda fd:handles[fd][1]
            adapter.close,adapter.unlink,adapter.fsync=lambda fd:None,unlink,sync
            for name,value in dict(_preflight=lambda:None,_database=database,
                _canonical=lambda p:nodes[root],_sync_dir=lambda p:None,
                _mount_id=lambda fd:78 if f.mount_drift and handles[fd][0]==config else 77,
                _fsxattr=lambda p:(42,True) if f.project else (0,False),
                _limits=lambda p:((0,0,4),(0,0,1024)) if f.quota else (None,None),
                _quota=quota,_clear_contents=cleanup).items():
                stack.enter_context(patch.object(v,name,value))
            stack.enter_context(patch('supervisor.volumes.os',adapter))
            stack.enter_context(patch('supervisor.config_lock.set_immutable',side_effect=clear))
            stack.enter_context(patch('supervisor.config_lock.is_immutable',side_effect=lambda fd:f.locked))
            yield f

    def purge(self,f): return f.v.purge(f.instance,4096,42)

    def reserved(self,f):
        self.assertTrue(f.quota)
        self.assertFalse(any(e.startswith('limit -p') for e in f.events))
        with closing(sqlite3.connect(f.v.db_path, isolation_level=None)) as db:
            self.assertEqual(db.execute('SELECT stage FROM volume_projects').fetchone(),('purging',))

    def test_purge_unlocks_only_managed_file_before_cleanup(self):
        with self.fixture() as f:
            self.assertTrue(self.purge(f)['purged'])
            self.assertFalse(f.root.exists())
            self.assertEqual(f.events.count('clear'),1)
            self.assertLess(f.events.index('clear'),f.events.index('cleanup'))
            with closing(sqlite3.connect(f.v.db_path, isolation_level=None)) as db:
                self.assertEqual(db.execute('SELECT * FROM volume_purge_configs').fetchall(),[])

    def test_interruptions_retain_quota_and_retry(self):
        for failure in ('clear_before','clear_after','file_sync','unlink_before','unlink_after','dir_sync','cleanup'):
            with self.subTest(failure=failure),self.fixture() as f:
                f.fail=failure
                with self.assertRaises(OSError): self.purge(f)
                self.reserved(f)
                f.fail=None
                self.assertTrue(self.purge(f)['purged'])

    def test_replaced_inode_on_retry_is_rejected(self):
        with self.fixture() as f:
            f.fail='clear_after'
            with self.assertRaises(OSError): self.purge(f)
            f.nodes[f.config]=NS(**{**vars(f.nodes[f.config]),'st_ino':999})
            f.fail=None
            with self.assertRaises(RuntimeStorageError): self.purge(f)
            self.reserved(f)

    def test_replacement_during_unlock_is_not_unlinked(self):
        with self.fixture() as f:
            f.swap=True
            with self.assertRaises(RuntimeStorageError): self.purge(f)
            self.assertNotIn('unlink',f.events)
            self.reserved(f)

    def test_unsafe_file_metadata_rejected_before_ioctl(self):
        for change in ({'st_nlink':2},{'st_gid':0},{'st_mode':stat.S_IFLNK|0o440},
                       {'st_mode':stat.S_IFIFO|0o440},{'st_dev':999}):
            with self.subTest(change=change),self.fixture() as f:
                f.nodes[f.config]=NS(**{**vars(f.nodes[f.config]),**change})
                with self.assertRaises(RuntimeStorageError): self.purge(f)
                self.assertNotIn('clear',f.events)
                self.reserved(f)
        with self.fixture() as f:
            f.mount_drift=True
            with self.assertRaises(RuntimeStorageError): self.purge(f)
            self.assertNotIn('clear',f.events)

    def test_legacy_config_uses_existing_cleanup_without_unlock(self):
        with self.fixture() as f:
            f.nodes[f.config]=NS(**{**vars(f.nodes[f.config]),'st_uid':1000,'st_mode':stat.S_IFREG|0o600})
            f.locked=False
            self.assertTrue(self.purge(f)['purged'])
            self.assertNotIn('clear',f.events)

    def test_absent_file_and_partial_directory_cleanup_retry(self):
        with self.fixture() as f:
            f.config.unlink(); f.fail='cleanup'
            with self.assertRaises(OSError): self.purge(f)
            (f.state/'user.txt').unlink(); f.state.rmdir(); f.fail=None
            self.assertTrue(self.purge(f)['purged'])
            self.assertNotIn('clear',f.events)

    def test_partial_state_directory_creation_is_purgeable_without_ioctl(self):
        with self.fixture() as f:
            f.config.unlink()
            f.nodes[f.state]=NS(**{**vars(f.nodes[f.state]), 'st_uid':0, 'st_gid':0})
            with closing(sqlite3.connect(f.v.db_path, isolation_level=None)) as db:
                db.execute("UPDATE volume_directories SET stage='created' WHERE inode=457")
            self.assertTrue(self.purge(f)['purged'])
            self.assertNotIn('clear',f.events)

    def test_partial_config_initialization_is_cleaned_without_ioctl(self):
        for gid in (0,1000):
            with self.subTest(gid=gid), self.fixture() as f:
                f.nodes[f.config]=NS(**{**vars(f.nodes[f.config]), 'st_gid':gid,
                                       'st_mode':stat.S_IFREG|0o600})
                f.locked=False
                self.assertTrue(self.purge(f)['purged'])
                self.assertNotIn('clear',f.events)

    def test_reserved_origin_survives_crash_after_purging_commit(self):
        for keep_root in (False,True):
            with self.subTest(keep_root=keep_root), self.fixture() as f:
                f.config.unlink()
                (f.state/'user.txt').unlink()
                f.state.rmdir()
                if not keep_root: f.root.rmdir()
                f.quota=False
                with closing(sqlite3.connect(f.v.db_path, isolation_level=None)) as db:
                    db.execute("UPDATE volume_projects SET stage='reserved'")
                    if keep_root:
                        db.execute('DELETE FROM volume_directories WHERE inode=457')
                    else:
                        db.execute('DELETE FROM volume_directories')
                f.fail='origin_commit_after'
                with self.assertRaises(sqlite3.OperationalError): self.purge(f)
                self.assertFalse(any(e.startswith('limit -p') for e in f.events))
                f.fail=None
                self.assertTrue(self.purge(f)['purged'])

    def test_config_journal_commit_failure_prevents_ioctl_and_cleanup(self):
        with self.fixture() as f:
            f.fail='journal_commit'
            with self.assertRaises(sqlite3.OperationalError): self.purge(f)
            self.assertNotIn('clear',f.events)
            self.assertNotIn('cleanup',f.events)
            self.reserved(f)
            f.fail=None
            self.assertTrue(self.purge(f)['purged'])

    def test_parent_replacement_on_retry_prevents_ioctl(self):
        with self.fixture() as f:
            f.fail='clear_before'
            with self.assertRaises(OSError): self.purge(f)
            f.nodes[f.state]=NS(**{**vars(f.nodes[f.state]), 'st_ino':999})
            f.fail=None
            previous=f.events.count('clear')
            with self.assertRaises(RuntimeStorageError): self.purge(f)
            self.assertEqual(f.events.count('clear'),previous)
            self.reserved(f)

    def test_ready_parent_cannot_be_adopted_as_partial(self):
        with self.fixture() as f:
            f.nodes[f.state]=NS(**{**vars(f.nodes[f.state]), 'st_uid':0, 'st_gid':0})
            with self.assertRaises(RuntimeStorageError): self.purge(f)
            self.assertNotIn('clear',f.events)
            self.reserved(f)

    def test_reserved_root_usage_with_zero_limits_can_be_cleaned_after_retry(self):
        with self.fixture() as f:
            f.config.unlink()
            (f.state/'user.txt').unlink()
            f.state.rmdir()
            with closing(sqlite3.connect(f.v.db_path, isolation_level=None)) as db:
                db.execute("UPDATE volume_projects SET stage='reserved'")
                db.execute('DELETE FROM volume_directories WHERE inode=457')
            def limits(_project):
                # Assigned root consumes an inode before hard limits are installed.
                return ((0,0,0),(1 if f.project else 0,0,0))
            with patch.object(f.v, '_limits', side_effect=limits):
                f.fail='origin_commit_after'
                with self.assertRaises(sqlite3.OperationalError): self.purge(f)
                self.assertFalse(any(e.startswith('limit -p') for e in f.events))
                f.fail=None
                self.assertTrue(self.purge(f)['purged'])
            self.assertFalse(f.root.exists())

    def test_remaining_usage_after_cleanup_prevents_reserved_quota_release(self):
        with self.fixture() as f:
            f.config.unlink()
            (f.state/'user.txt').unlink()
            f.state.rmdir()
            with closing(sqlite3.connect(f.v.db_path, isolation_level=None)) as db:
                db.execute("UPDATE volume_projects SET stage='reserved'")
                db.execute('DELETE FROM volume_directories WHERE inode=457')
            with patch.object(f.v, '_limits', return_value=((0,0,0),(1,0,0))):
                with self.assertRaises(RuntimeStorageError) as failure: self.purge(f)
            self.assertEqual(failure.exception.code, 'quota_usage_remaining')
            self.assertFalse(any(e.startswith('limit -p') for e in f.events))
            with closing(sqlite3.connect(f.v.db_path)) as db:
                self.assertIsNotNone(db.execute('SELECT * FROM volume_projects').fetchone())

if __name__=='__main__': unittest.main()
