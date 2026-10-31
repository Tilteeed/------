"""Fail-closed, per-instance XFS project quotas (Linux, privileged service only).

Contract: host_path is <profile.storage.mountpoint>/instances/<32lowerhex>.
Bind ONLY host_path/state and host_path/secrets into a uid=gid=1000 container;
never bind the admin-owned instance root or instances parent. state contains
workspace, credentials and persistentdata, all charged to the SAME project.
The container must have no CAP_SYS_ADMIN/CAP_FOWNER and no host mount access.
Its sandbox MUST also deny FS_IOC_FSSETXATTR (0x401c5820), FS_IOC_SETFLAGS
(native/compat forms), and fileattr_set/file_setattr equivalents: ownership
alone can permit changing project inheritance in the initial user namespace.
Dropping capabilities alone is NOT a complete protection for user-owned dirs.

state_dir/storage.sqlite3 and storage.lock live on a DIFFERENT filesystem,
outside the volume. Constructor/import perform no I/O; prepare lazily sets up
only the explicitly supplied state_dir (its parent must already exist).
verify never creates directories, a database, or a lock file.

Primary references (xfsprogs manuals): xfs_quota(8), xfs_io(8), and
ioctl_xfs_fsgetxattr(2). project -s -d 0 -p PATH NUMERIC_ID sets only a new,
empty, recorded root; -D /dev/null -P /dev/null prevent /etc mappings from
adding OTHER trees. limit bhard takes bytes; we use explicit KiB suffixes,
require divisibility by 1024, and read back numeric report -p -n -N -b/-i
-L ID -U ID (blocks in 1024-byte units). FS_IOC_FSGETXATTR supplies fsx_projid
and FS_XFLAG_PROJINHERIT; this is the same fsxattr queried by xfs_io stat.
The numeric dump additionally checks raw 512-byte limits against rounding.
Technical inode policy, not a user setting: ihard=max(1024,disk_bytes//4096).
IDs are allocated in 1..2147483646 for signed xfsprogs CLI compatibility.

Operational boundary: dedicate this filesystem/project-ID namespace to this
single durable DB. Do not delete/restore the DB independently of the volume,
run other project allocators, or change mounts/trees concurrently as root.
The flock serializes this adapter, not privileged external administrators.
No cleanup or ID recycling occurs on failure. A crash in the mkdir -> identity
commit window is intentionally blocked for manual recovery, never adopted.
Verification is a point-in-time structural/limit check, not an EDQUOT write
experiment or an atomic snapshot against a running container's renames.
"""
from contextlib import contextmanager
from dataclasses import asdict
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import sys

from .config import DeploymentProfile, validate_profile
from .probes import ProbeFailure, run_command
from .storage import inspect_storage


class RuntimeStorageError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise RuntimeStorageError(code)


def _arguments(instance_id, disk_bytes):
    _require(type(instance_id) is str and
             re.fullmatch(r'[0-9a-f]{32}', instance_id) is not None,
             'invalid_instance_id')
    _require(type(disk_bytes) is int and 0 < disk_bytes <= 2**63 - 1
             and disk_bytes % 1024 == 0, 'invalid_disk_bytes')


def _quota_row(text, project_id):
    """Parse ONE report row, never names, human units or a global ON flag."""
    lines = [line.split() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    _require(len(lines) == 1, 'invalid_quota_output')
    row = lines[0]
    # ID Used Soft Hard Warn/Grace; some versions separate Warn and Grace.
    _require(len(row) in (6, 7) and row[0] in (str(project_id), f'#{project_id}')
             and all(re.fullmatch(r'[0-9]+', value) for value in row[1:4]),
             'invalid_quota_output')
    return tuple(int(value) for value in row[1:4])


class XfsVolumes:
    def __init__(self, profile, state_dir):
        _require(type(profile) is DeploymentProfile, 'invalid_profile')
        try:
            self.profile = validate_profile(asdict(profile))
            self.state_dir = Path(state_dir)
        except (ValueError, TypeError):
            raise RuntimeStorageError('invalid_profile_or_state_dir') from None
        # Purely lexical: even constructor on Windows is inert and portable.
        self.mountpoint = Path(self.profile.storage.mountpoint)
        self.instances = self.mountpoint / 'instances'
        self.db_path = self.state_dir / 'storage.sqlite3'

    def _preflight(self):
        _require(sys.platform == 'linux', 'unsupported_platform')
        _require(os.geteuid() == 0, 'privilege_required')
        report = inspect_storage(self.profile)
        _require(report.backend_ready, 'storage_not_ready')
        self._canonical(self.mountpoint)
        self._trusted_ancestors(self.mountpoint)

    @staticmethod
    def _canonical(path):
        _require(path.is_absolute() and str(path.resolve(strict=True)) == str(path),
                 'noncanonical_path')
        info = path.lstat()
        _require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                 'unsafe_directory')
        return info

    @staticmethod
    def _trusted_ancestors(path):
        # Root-owned, non-writable ancestors prevent unprivileged path swaps.
        for parent in (path, *path.parents):
            info = parent.lstat()
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                     and not info.st_mode & 0o022, 'untrusted_ancestor')

    @staticmethod
    def _sync_dir(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _private_file(path, create):
        flags = os.O_RDWR if create else os.O_RDONLY
        if create:
            try:
                fd = os.open(path, flags | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                fd = os.open(path, flags | os.O_NOFOLLOW)
        else:
            fd = os.open(path, flags | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1):
            os.close(fd)
            raise RuntimeStorageError('unsafe_state_file')
        return fd

    @contextmanager
    def _database(self, create):
        import fcntl  # Linux-only; importing this module on Windows stays inert.
        _require(self.state_dir.is_absolute(), 'invalid_state_dir')
        _require(not self.state_dir.is_relative_to(self.mountpoint), 'state_inside_volume')
        if create and not os.path.lexists(self.state_dir):
            self._canonical(self.state_dir.parent)
            self._trusted_ancestors(self.state_dir.parent)
            try:
                self.state_dir.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self._sync_dir(self.state_dir.parent)
        info = self._canonical(self.state_dir)
        self._trusted_ancestors(self.state_dir)
        _require(stat.S_IMODE(info.st_mode) == 0o700, 'unsafe_state_dir')
        _require(info.st_dev != self.mountpoint.stat().st_dev, 'state_on_volume')
        lock = self._private_file(self.state_dir / 'storage.lock', create)
        db = None
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            fd = self._private_file(self.db_path, create)
            os.close(fd)
            uri = self.db_path.as_uri() + ('?mode=rw' if create else '?mode=ro')
            db = sqlite3.connect(uri, uri=True, timeout=10, isolation_level=None)
            db.row_factory = sqlite3.Row
            if create:
                db.execute('PRAGMA journal_mode=DELETE')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute('CREATE TABLE IF NOT EXISTS volume_meta '
                               '(key TEXT PRIMARY KEY, value TEXT NOT NULL)')
                    db.execute('CREATE TABLE IF NOT EXISTS volume_projects '
                               '(project_id INTEGER PRIMARY KEY AUTOINCREMENT '
                               'CHECK(project_id BETWEEN 1 AND 2147483646), '
                               'instance_id TEXT NOT NULL UNIQUE, disk_bytes INTEGER NOT NULL, '
                               'stage TEXT NOT NULL)')
                    db.execute('CREATE TABLE IF NOT EXISTS volume_directories '
                               '(path TEXT PRIMARY KEY, device INTEGER NOT NULL, '
                               'inode INTEGER NOT NULL, stage TEXT NOT NULL)')
                    binding = self.profile.storage.expected_uuid.lower() + ':' + str(self.mountpoint)
                    existing = db.execute("SELECT value FROM volume_meta WHERE key='binding'").fetchone()
                    if existing is None:
                        db.execute("INSERT INTO volume_meta VALUES ('binding', ?)", (binding,))
                    else:
                        _require(existing['value'] == binding, 'state_profile_mismatch')
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
                self._sync_dir(self.state_dir)
            else:
                existing = db.execute("SELECT value FROM volume_meta WHERE key='binding'").fetchone()
                binding = self.profile.storage.expected_uuid.lower() + ':' + str(self.mountpoint)
                _require(existing is not None and existing['value'] == binding,
                         'state_profile_mismatch')
            yield db
        finally:
            if db is not None:
                db.close()
            os.close(lock)

    def _quota(self, command):
        return run_command(['xfs_quota', '-x', '-D', '/dev/null', '-P', '/dev/null',
                            '-c', command, str(self.mountpoint)])

    def _limits(self, project_id):
        rows = []
        for kind in ('b', 'i'):
            output = self._quota(f'report -p -{kind} -n -N -L {project_id} -U {project_id}')
            rows.append(_quota_row(output, project_id))
        _require((rows[0] is None) == (rows[1] is None), 'invalid_quota_output')
        # report rounds 512-byte basic blocks DOWN to KiB. The documented
        # backup dump emits raw fs_disk_quota limits (512-byte units); reject
        # odd basic-block limits instead of falsely verifying a +512B drift.
        dump = self._quota(f'dump -p -L {project_id} -U {project_id}')
        lines = [line.strip() for line in dump.splitlines() if line.strip()]
        if lines:
            _require(len(lines) == 2 and re.fullmatch(r'fs = /dev/[A-Za-z0-9_./+-]+', lines[0])
                     is not None, 'invalid_quota_output')
            fields = lines[1].split()
            _require(len(fields) in (5, 7) and fields[0] == str(project_id)
                     and all(re.fullmatch(r'[0-9]+', value) for value in fields),
                     'invalid_quota_output')
            raw = tuple(int(value) for value in fields[1:])
            _require(raw[0] % 2 == 0 and raw[1] % 2 == 0
                     and not any(raw[4:]), 'unrepresentable_quota_limit')
            _require(rows[0] is not None and rows[1] is not None
                     and rows[0][1:] == (raw[0] // 2, raw[1] // 2)
                     and rows[1][1:] == raw[2:4], 'quota_output_changed')
        else:
            # dump omits entries with zero limits (even when usage exists).
            _require(all(row is None or row[1:] == (0, 0) for row in rows),
                     'quota_output_changed')
        return rows

    @staticmethod
    def _fsxattr(path):
        import fcntl
        # Linux UAPI fsxattr: five u32 fields plus eight padding bytes (28).
        # _IOR('X',31,struct fsxattr), FS_XFLAG_PROJINHERIT = 0x00000200.
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            data = fcntl.ioctl(fd, 0x801c581f, bytes(28))
            flags, _, _, project_id, _ = struct.unpack('=IIIII8x', data)
            _require(not flags & 0x101, 'realtime_storage_unsupported')
            return project_id, bool(flags & 0x200)
        finally:
            os.close(fd)

    def _directory(self, db, path, *, uid, create=False):
        """Only persisted device/inode identity permits retry of an existing dir."""
        key = str(path.relative_to(self.mountpoint))
        saved = db.execute('SELECT * FROM volume_directories WHERE path=?', (key,)).fetchone()
        if saved is None:
            _require(create and not os.path.lexists(path), 'foreign_directory')
            path.mkdir(mode=0o700)
            self._sync_dir(path.parent)
            info = self._canonical(path)
            # Commit BEFORE later quota/chown operations. Never delete on error.
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('INSERT INTO volume_directories VALUES (?, ?, ?, ?)',
                           (key, info.st_dev, info.st_ino, 'created'))
                db.commit()
            except BaseException:
                db.rollback()
                raise
            saved = db.execute('SELECT * FROM volume_directories WHERE path=?', (key,)).fetchone()
        info = self._canonical(path)
        _require(info.st_dev == self.mountpoint.stat().st_dev
                 and (info.st_dev, info.st_ino) == (saved['device'], saved['inode']),
                 'directory_identity_changed')
        _require(stat.S_IMODE(info.st_mode) == 0o700, 'unsafe_directory_mode')
        if saved['stage'] == 'created' and create:
            _require(info.st_uid in (0, uid) and info.st_gid in (0, uid),
                     'foreign_directory_owner')
            _require(not any(path.iterdir()), 'incomplete_directory_not_empty')
            if info.st_uid != uid or info.st_gid != uid:
                os.chown(path, uid, uid, follow_symlinks=False)
            self._sync_dir(path)
            db.execute("UPDATE volume_directories SET stage='ready' WHERE path=?", (key,))
        else:
            _require(saved['stage'] == 'ready', 'incomplete_volume')
            _require(info.st_uid == uid and info.st_gid == uid, 'unsafe_directory_owner')
        return path

    def _paths(self, root):
        return ((root, 0), (root / 'state', 1000), (root / 'secrets', 1000),
                (root / 'state' / 'workspace', 1000),
                (root / 'state' / 'credentials', 1000),
                (root / 'state' / 'persistentdata', 1000))

    def _verify(self, db, row, root):
        project_id, disk_bytes = row['project_id'], row['disk_bytes']
        self._directory(db, self.instances, uid=0)
        _require(self._fsxattr(self.instances) == (0, False), 'unsafe_instances_project')
        for path, uid in self._paths(root):
            self._directory(db, path, uid=uid)
            _require(self._fsxattr(path) == (project_id, True), 'project_identity_mismatch')
        blocks, inodes = self._limits(project_id)
        _require(blocks is not None and inodes is not None, 'quota_missing')
        _require(blocks[1:] == (0, disk_bytes // 1024)
                 and inodes[1:] == (0, max(1024, disk_bytes // 4096)),
                 'quota_limit_mismatch')
        return {'host_path': str(root), 'project_id': project_id,
                'disk_quota_verified': True}

    @classmethod
    def _clear_contents(cls, path, device):
        """Delete one owned tree without following symlinks or crossing devices."""
        with os.scandir(path) as entries:
            for entry in entries:
                info = os.lstat(entry.path)
                _require(info.st_dev == device and not os.path.ismount(entry.path),
                         'nested_mount')
                if stat.S_ISDIR(info.st_mode):
                    cls._clear_contents(Path(entry.path), device)
                    os.rmdir(entry.path)
                else:
                    # Symlinks and special files are unlinked, never opened/followed.
                    os.unlink(entry.path)
        cls._sync_dir(path)

    @staticmethod
    def _quota_clear(rows):
        return all(row is None or row == (0, 0, 0) for row in rows)

    @staticmethod
    def _quota_matches(rows, disk_bytes):
        return (len(rows) == 2 and rows[0] is not None and rows[1] is not None
                and rows[0][1:] == (0, disk_bytes // 1024)
                and rows[1][1:] == (0, max(1024, disk_bytes // 4096)))

    def purge(self, instance_id, disk_bytes, expected_project_id=None):
        """Delete only a journaled instance tree; keep its quota reserved on failure.

        The caller must first prove that its Docker container is absent. The storage
        DB's purging stages make every filesystem step retryable after a crash.
        """
        _arguments(instance_id, disk_bytes)
        if expected_project_id is not None:
            _require(type(expected_project_id) is int and 0 < expected_project_id <= 2147483646,
                     'invalid_project_id')
        self._preflight()
        root = self.instances / instance_id
        if not os.path.lexists(self.db_path):
            _require(not os.path.lexists(root), 'foreign_directory')
            _require(expected_project_id is None, 'storage_state_missing')
            return {'purged': True, 'project_id': None}
        try:
            with self._database(create=False) as db:
                row = db.execute('SELECT * FROM volume_projects WHERE instance_id=?',
                                 (instance_id,)).fetchone()
                root = self.instances / instance_id
                if row is None:
                    _require(not os.path.lexists(root), 'foreign_directory')
                    if expected_project_id is not None:
                        _require(self._quota_clear(self._limits(expected_project_id)),
                                 'quota_cleanup_unverified')
                    return {'purged': True, 'project_id': expected_project_id}

                project_id = row['project_id']
                _require(expected_project_id in (None, project_id), 'project_identity_mismatch')
                _require(row['disk_bytes'] == disk_bytes, 'quota_request_changed')
                stage = row['stage']
                _require(stage in ('reserved', 'assigned', 'ready', 'purging',
                                    'quota_cleared', 'quota_reset'), 'invalid_volume_state')
                original_stage = stage
                if stage not in ('purging', 'quota_cleared', 'quota_reset'):
                    db.execute('BEGIN IMMEDIATE')
                    try:
                        db.execute("UPDATE volume_projects SET stage='purging' WHERE instance_id=?",
                                   (instance_id,))
                        db.commit()
                    except BaseException:
                        db.rollback()
                        raise
                    stage = 'purging'

                root_key = root.relative_to(self.mountpoint).as_posix()
                root_record = db.execute('SELECT * FROM volume_directories WHERE path=?',
                                         (root_key,)).fetchone()
                if os.path.lexists(root):
                    _require(root_record is not None, 'foreign_directory')
                    info = self._canonical(root)
                    mount_info = self._canonical(self.mountpoint)
                    _require((info.st_dev, info.st_ino) ==
                             (root_record['device'], root_record['inode']),
                             'directory_identity_changed')
                    _require(info.st_dev == mount_info.st_dev
                             and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                             'unsafe_directory')
                    identity = self._fsxattr(root)
                    limits = self._limits(project_id)
                    if identity == (project_id, True):
                        _require((self._quota_clear(limits) or self._quota_matches(limits, disk_bytes))
                                 if original_stage == 'reserved'
                                 else self._quota_matches(limits, disk_bytes),
                                 'quota_limit_mismatch')
                        self._clear_contents(root, root.stat().st_dev)
                        self._quota(f'project -C -p {root} {project_id}')
                        identity = self._fsxattr(root)
                    else:
                        _require(identity == (0, False)
                                 and stage in ('purging', 'quota_cleared', 'quota_reset')
                                 and not any(root.iterdir())
                                 and (self._quota_matches(limits, disk_bytes)
                                      or self._quota_clear(limits)),
                                 'project_identity_mismatch')
                    _require(identity == (0, False) and not any(root.iterdir()),
                             'project_cleanup_unverified')
                    db.execute('BEGIN IMMEDIATE')
                    try:
                        db.execute("UPDATE volume_projects SET stage='quota_cleared' WHERE instance_id=?",
                                   (instance_id,))
                        db.commit()
                    except BaseException:
                        db.rollback()
                        raise
                    os.rmdir(root)
                    self._sync_dir(root.parent)
                elif original_stage == 'reserved':
                    _require(root_record is None and self._quota_clear(self._limits(project_id)),
                             'unprepared_project_has_quota')
                    db.execute('BEGIN IMMEDIATE')
                    try:
                        db.execute("UPDATE volume_projects SET stage='quota_cleared' WHERE instance_id=?",
                                   (instance_id,))
                        db.commit()
                    except BaseException:
                        db.rollback()
                        raise
                else:
                    _require(original_stage in ('quota_cleared', 'quota_reset'),
                             'purge_state_inconsistent')

                limits = self._limits(project_id)
                _require(all(item is None or item[0] == 0 for item in limits),
                         'quota_usage_remaining')
                self._quota(f'limit -p bsoft=0 bhard=0 isoft=0 ihard=0 {project_id}')
                _require(self._quota_clear(self._limits(project_id)), 'quota_cleanup_unverified')
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute("UPDATE volume_projects SET stage='quota_reset' WHERE instance_id=?",
                               (instance_id,))
                    db.execute('DELETE FROM volume_directories WHERE path=? OR path LIKE ?',
                               (root_key, root_key + '/%'))
                    db.execute('DELETE FROM volume_projects WHERE instance_id=?', (instance_id,))
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
                self._sync_dir(self.state_dir)
                return {'purged': True, 'project_id': project_id}
        finally:
            self._preflight()

    def _operate(self, instance_id, disk_bytes, create):
        _arguments(instance_id, disk_bytes)
        self._preflight()  # Before state DB setup OR any volume mutation.
        try:
            with self._database(create) as db:
                row = db.execute('SELECT * FROM volume_projects WHERE instance_id=?',
                                 (instance_id,)).fetchone()
                root = self.instances / instance_id
                if row is None:
                    _require(create, 'instance_not_prepared')
                    _require(not os.path.lexists(root), 'foreign_directory')
                    db.execute('BEGIN IMMEDIATE')
                    try:
                        db.execute('INSERT INTO volume_projects (instance_id,disk_bytes,stage) '
                                   "VALUES (?,?,'reserved')", (instance_id, disk_bytes))
                        db.commit()
                    except BaseException:
                        db.rollback()
                        raise
                    row = db.execute('SELECT * FROM volume_projects WHERE instance_id=?',
                                     (instance_id,)).fetchone()
                _require(row['disk_bytes'] == disk_bytes, 'quota_request_changed')
                _require(row['stage'] in ('reserved', 'assigned', 'ready'), 'invalid_volume_state')
                if not create or row['stage'] == 'ready':
                    _require(row['stage'] == 'ready', 'incomplete_volume')
                    return self._verify(db, row, root)
                self._directory(db, self.instances, uid=0, create=True)
                _require(self._fsxattr(self.instances) == (0, False), 'unsafe_instances_project')
                self._directory(db, root, uid=0, create=True)
                project_id = row['project_id']
                identity = self._fsxattr(root)
                if row['stage'] == 'reserved':
                    _require(not any(root.iterdir()), 'incomplete_directory_not_empty')
                    _require(identity in ((0, False), (project_id, True)),
                             'project_identity_mismatch')
                    existing = self._limits(project_id)
                    if identity == (0, False):
                        _require(all(item is None or item == (0, 0, 0) for item in existing),
                                 'foreign_project_id')
                        # Only our recorded empty root; NEVER recursively adopt data.
                        self._quota(f'project -s -d 0 -p {root} {project_id}')
                    _require(self._fsxattr(root) == (project_id, True), 'project_setup_failed')
                    self._sync_dir(root)
                    self._quota(f'limit -p bsoft=0 bhard={disk_bytes // 1024}k '
                                f'isoft=0 ihard={max(1024, disk_bytes // 4096)} {project_id}')
                    # Persist stage only after reading back exact limits.
                    blocks, inodes = self._limits(project_id)
                    _require(blocks is not None and blocks[1:] == (0, disk_bytes // 1024)
                             and inodes is not None and inodes[1:] ==
                             (0, max(1024, disk_bytes // 4096)), 'quota_limit_mismatch')
                    db.execute("UPDATE volume_projects SET stage='assigned' WHERE instance_id=?",
                               (instance_id,))
                else:
                    _require(identity == (project_id, True), 'project_identity_mismatch')
                # Inheritance is installed BEFORE any container-owned child exists.
                for path, uid in self._paths(root)[1:]:
                    self._directory(db, path, uid=uid, create=True)
                    _require(self._fsxattr(path) == (project_id, True), 'project_identity_mismatch')
                result = self._verify(db, row, root)
                db.execute("UPDATE volume_projects SET stage='ready' WHERE instance_id=?",
                           (instance_id,))
                return result
        finally:
            # Also inspect after a partial failure; never report success if remounted.
            self._preflight()

    def _call(self, instance_id, disk_bytes, create):
        try:
            return self._operate(instance_id, disk_bytes, create)
        except RuntimeStorageError:
            raise
        except ProbeFailure as error:
            raise RuntimeStorageError(error.code) from None
        except sqlite3.Error:
            raise RuntimeStorageError('storage_state_failed') from None
        except (OSError, ValueError, struct.error):
            raise RuntimeStorageError('storage_operation_failed') from None

    def prepare(self, instance_id, disk_bytes):
        return self._call(instance_id, disk_bytes, True)

    def verify(self, instance_id, disk_bytes):
        return self._call(instance_id, disk_bytes, False)
