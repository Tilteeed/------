"""Fail-closed immutable-inode helpers for managed Gateway policy files.

The flags are changed only by the privileged Supervisor. Containers run without
CAP_LINUX_IMMUTABLE and cannot clear the bit; unsupported filesystems fail closed.
"""
import errno
import os
import stat
import struct
import sys
from typing import Any


FS_IMMUTABLE_FL = 0x00000010
_FS_IOC_READ = 2
_FS_IOC_WRITE = 1
_FS_IOC_TYPE = ord('f')
_LONG_SIZE = struct.calcsize('@L')


def _ioc(direction, number):
    return (direction << 30) | (_LONG_SIZE << 16) | (_FS_IOC_TYPE << 8) | number


FS_IOC_GETFLAGS = _ioc(_FS_IOC_READ, 1)
FS_IOC_SETFLAGS = _ioc(_FS_IOC_WRITE, 2)


def _native_ioctl(fd, request, payload):
    if sys.platform != 'linux':
        raise OSError(errno.ENOTSUP, 'immutable file flags require Linux')
    import fcntl
    return fcntl.ioctl(fd, request, payload, True)


def _flags(fd, ioctl_fn):
    if type(fd) is not int or fd < 0 or not callable(ioctl_fn):
        raise ValueError('Invalid immutable-flag request')
    payload = bytearray(_LONG_SIZE)
    ioctl_fn(fd, FS_IOC_GETFLAGS, payload)
    if len(payload) != _LONG_SIZE:
        raise OSError(errno.EIO, 'filesystem flag read-back is invalid')
    return struct.unpack('@L', payload)[0]


def is_immutable(fd, *, ioctl_fn=None):
    """Return the read-back immutable bit; unsupported or malformed state raises."""
    ioctl_fn = _native_ioctl if ioctl_fn is None else ioctl_fn
    return bool(_flags(fd, ioctl_fn) & FS_IMMUTABLE_FL)


def set_immutable(fd, enabled, *, ioctl_fn=None):
    """Set/clear only FS_IMMUTABLE_FL and verify the kernel read-back exactly."""
    if type(enabled) is not bool:
        raise ValueError('Immutable state must be an explicit boolean')
    ioctl_fn = _native_ioctl if ioctl_fn is None else ioctl_fn
    current = _flags(fd, ioctl_fn)
    wanted = current | FS_IMMUTABLE_FL if enabled else current & ~FS_IMMUTABLE_FL
    if wanted != current:
        ioctl_fn(fd, FS_IOC_SETFLAGS, bytearray(struct.pack('@L', wanted)))
    observed = _flags(fd, ioctl_fn)
    if bool(observed & FS_IMMUTABLE_FL) is not enabled:
        raise OSError(errno.EIO, 'immutable flag did not persist')
    return enabled


def _read_fd(fd, limit):
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while total < limit:
        chunk = os.read(fd, min(4096, limit - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b''.join(chunks)


def initialize_config_fd(fd, data, *, require_immutable=True, fchown_fn=None,
                         fchmod_fn=None, ftruncate_fn=None, seek_fn=None,
                         write_fn=None, fsync_fn=None, set_immutable_fn=None,
                         fstat_fn=None, read_fn=None, immutable_fn=None):
    """Write one canonical config, apply root:1000/0440 protection, then read it back."""
    if (type(fd) is not int or fd < 0 or type(data) is not bytes
            or not 1 <= len(data) <= 65536 or type(require_immutable) is not bool):
        raise ValueError('Invalid managed config initialization request')
    fchown_fn = os.fchown if fchown_fn is None else fchown_fn
    fchmod_fn = os.fchmod if fchmod_fn is None else fchmod_fn
    ftruncate_fn = os.ftruncate if ftruncate_fn is None else ftruncate_fn
    seek_fn = os.lseek if seek_fn is None else seek_fn
    write_fn = os.write if write_fn is None else write_fn
    fsync_fn = os.fsync if fsync_fn is None else fsync_fn
    set_immutable_fn = set_immutable if set_immutable_fn is None else set_immutable_fn
    if any(not callable(fn) for fn in
           (fchown_fn, fchmod_fn, ftruncate_fn, seek_fn, write_fn, fsync_fn)):
        raise ValueError('Managed config initialization functions are invalid')
    fchown_fn(fd, 0, 1000)
    ftruncate_fn(fd, 0)
    seek_fn(fd, 0, os.SEEK_SET)
    offset = 0
    while offset < len(data):
        written = write_fn(fd, data[offset:])
        if type(written) is not int or written <= 0 or written > len(data) - offset:
            raise OSError(errno.EIO, 'managed config write did not complete')
        offset += written
    fsync_fn(fd)
    fchmod_fn(fd, 0o440)
    if require_immutable:
        if not callable(set_immutable_fn):
            raise ValueError('Managed config immutable operation is unavailable')
        set_immutable_fn(fd, True)
    fsync_fn(fd)
    return verify_config_fd(fd, data, require_immutable=require_immutable,
                            fstat_fn=fstat_fn, read_fn=read_fn,
                            immutable_fn=immutable_fn)


def replace_locked_config_at(parent_fd, expected_current, new_data, *, open_fn=None,
                             fstat_fn=None, stat_fn=None, read_fn=None,
                             initialize_fn=None, is_immutable_fn=None,
                             set_immutable_fn=None, replace_fn=None, unlink_fn=None,
                             fsync_fn=None, verify_fn=None, close_fn=None,
                             nofollow_flag=None):
    """Replace a config, failing closed if the installed inode cannot be verified.

    A failure after rename can leave new bytes unlocked. The caller must gate
    runtime startup on immutable-policy verification and arrange recovery. A
    failed restoration before rename can likewise leave the old inode unlocked;
    merely seeing old bytes is not proof that recovery succeeded.
    """
    if (type(parent_fd) is not int or parent_fd < 0
            or type(expected_current) is not bytes or not 1 <= len(expected_current) <= 65536
            or type(new_data) is not bytes or not 1 <= len(new_data) <= 65536
            or expected_current == new_data):
        raise ValueError('Invalid managed config replacement request')
    nofollow = getattr(os, 'O_NOFOLLOW', None) if nofollow_flag is None else nofollow_flag
    if type(nofollow) is not int:
        raise OSError(errno.ENOTSUP, 'no-follow config replacement is unavailable')
    open_fn = os.open if open_fn is None else open_fn
    fstat_fn = os.fstat if fstat_fn is None else fstat_fn
    stat_fn = os.stat if stat_fn is None else stat_fn
    read_fn = read_managed_config_fd if read_fn is None else read_fn
    initialize_fn = initialize_config_fd if initialize_fn is None else initialize_fn
    is_immutable_fn = is_immutable if is_immutable_fn is None else is_immutable_fn
    set_immutable_fn = set_immutable if set_immutable_fn is None else set_immutable_fn
    replace_fn = os.replace if replace_fn is None else replace_fn
    unlink_fn = os.unlink if unlink_fn is None else unlink_fn
    fsync_fn = os.fsync if fsync_fn is None else fsync_fn
    verify_fn = verify_config_fd if verify_fn is None else verify_fn
    close_fn = os.close if close_fn is None else close_fn
    if any(not callable(fn) for fn in
           (open_fn, fstat_fn, stat_fn, read_fn, initialize_fn, is_immutable_fn,
            set_immutable_fn, replace_fn, unlink_fn, fsync_fn, verify_fn, close_fn)):
        raise ValueError('Managed config replacement functions are invalid')

    name, temporary = 'openclaw.json', '.openclaw.json.update'
    old_fd = temp_fd = replacement_fd = None
    temp_created = replaced = old_was_immutable = old_unlocked = False
    try:
        old_fd = open_fn(name, os.O_RDONLY | nofollow, dir_fd=parent_fd)
        old_info, old_data = read_fn(old_fd, require_immutable=False)
        if old_data != expected_current:
            raise OSError(errno.EAGAIN, 'managed config changed before replacement')
        identity = (old_info.st_dev, old_info.st_ino)

        temp_fd = open_fn(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
                          0o600, dir_fd=parent_fd)
        temp_created = True
        initialize_fn(temp_fd, new_data, require_immutable=False)
        verify_fn(temp_fd, new_data, require_immutable=False)
        temp_info = fstat_fn(temp_fd)
        temp_identity = (temp_info.st_dev, temp_info.st_ino)
        fsync_fn(parent_fd)

        current = stat_fn(name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            raise OSError(errno.EAGAIN, 'managed config identity changed before replacement')
        writable_info = fstat_fn(old_fd)
        if (writable_info.st_dev, writable_info.st_ino) != identity:
            raise OSError(errno.EAGAIN, 'managed config identity changed before unlock')
        old_was_immutable = is_immutable_fn(old_fd)
        if type(old_was_immutable) is not bool:
            raise OSError(errno.EIO, 'managed config lock state is invalid')
        if old_was_immutable:
            old_unlocked = True  # The clear may take effect even if read-back raises.
            set_immutable_fn(old_fd, False)
            if is_immutable_fn(old_fd) is not False:
                raise OSError(errno.EIO, 'managed config immutable flag did not clear')
        current = stat_fn(name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            raise OSError(errno.EAGAIN, 'managed config identity changed before rename')
        candidate = stat_fn(temporary, dir_fd=parent_fd, follow_symlinks=False)
        if (candidate.st_dev, candidate.st_ino) != temp_identity:
            raise OSError(errno.EAGAIN, 'temporary config identity changed before rename')
        replace_fn(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_created = False
        replaced = True
        # Lock through the retained descriptor, never a potentially substituted path.
        set_immutable_fn(temp_fd, True)
        verify_fn(temp_fd, new_data, require_immutable=True)
        fsync_fn(temp_fd)
        fsync_fn(parent_fd)
        replacement_fd = open_fn(name, os.O_RDONLY | nofollow, dir_fd=parent_fd)
        installed = fstat_fn(replacement_fd)
        if (installed.st_dev, installed.st_ino) != temp_identity:
            raise OSError(errno.EAGAIN, 'installed config identity changed after replacement')
        result = verify_fn(replacement_fd, new_data, require_immutable=True)
        installed = stat_fn(name, dir_fd=parent_fd, follow_symlinks=False)
        if (installed.st_dev, installed.st_ino) != temp_identity:
            raise OSError(errno.EAGAIN, 'installed config identity changed during verification')
        return result
    except Exception as error:
        if replaced:
            raise OSError(errno.EIO, 'managed config replaced but protection or identity is unverified; recovery required') from error
        if old_unlocked and not replaced and old_fd is not None:
            try:
                set_immutable_fn(old_fd, True)
                if is_immutable_fn(old_fd) is not True:
                    raise OSError(errno.EIO, 'managed config immutable flag did not restore')
            except Exception:
                raise OSError(errno.EIO, 'managed config replacement left an unverified lock state') from None
        raise
    finally:
        if temp_created and temp_fd is not None:
            try:
                temp_now = fstat_fn(temp_fd)
                named_temp = stat_fn(temporary, dir_fd=parent_fd, follow_symlinks=False)
                if (temp_now.st_dev, temp_now.st_ino) == (named_temp.st_dev, named_temp.st_ino):
                    if is_immutable_fn(temp_fd) is True:
                        set_immutable_fn(temp_fd, False)
                    unlink_fn(temporary, dir_fd=parent_fd)
                    fsync_fn(parent_fd)
            except Exception:
                pass
        for fd in (replacement_fd, temp_fd, old_fd):
            if fd is not None:
                close_fn(fd)


def read_managed_config_fd(fd, *, require_immutable=True, fstat_fn=None,
                           read_fn=None, immutable_fn=None):
    """Read bounded bytes after verifying root ownership and immutable status."""
    if (type(fd) is not int or fd < 0 or type(require_immutable) is not bool):
        raise ValueError('Invalid managed config verification request')
    fstat_fn = os.fstat if fstat_fn is None else fstat_fn
    read_fn = _read_fd if read_fn is None else read_fn
    immutable_fn = is_immutable if immutable_fn is None else immutable_fn
    if not callable(fstat_fn) or not callable(read_fn):
        raise ValueError('Managed config verification functions are invalid')
    info: Any = fstat_fn(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 1000
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o440
            or type(info.st_size) is not int or not 1 <= info.st_size <= 65536):
        raise OSError(errno.EACCES, 'managed config metadata verification failed')
    if require_immutable:
        if not callable(immutable_fn) or immutable_fn(fd) is not True:
            raise OSError(errno.EACCES, 'managed config immutable flag is absent')
    content = read_fn(fd, 65537)
    if type(content) is not bytes or len(content) != info.st_size:
        raise OSError(errno.EIO, 'managed config content read-back failed')
    return info, content


def verify_config_fd(fd, expected, *, require_immutable=True, fstat_fn=None,
                     read_fn=None, immutable_fn=None):
    """Verify root ownership, read-only group access, exact bytes and optional immutability."""
    if (type(expected) is not bytes or not 1 <= len(expected) <= 65536
            or type(require_immutable) is not bool):
        raise ValueError('Invalid managed config verification request')
    info, content = read_managed_config_fd(
        fd, require_immutable=require_immutable, fstat_fn=fstat_fn,
        read_fn=read_fn, immutable_fn=immutable_fn)
    if content != expected:
        raise OSError(errno.EIO, 'managed config content verification failed')
    return info
