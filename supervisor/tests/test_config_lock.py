import os
import stat
import struct
import tempfile
import unittest
from types import SimpleNamespace

from supervisor.config_lock import (FS_IMMUTABLE_FL, initialize_config_fd, is_immutable,
                                    replace_locked_config_at, set_immutable,
                                    read_managed_config_fd, verify_config_fd)


class ImmutableConfigFlagTests(unittest.TestCase):
    def make_ioctl(self, initial_flags, *, ignore_set=False):
        state = {'flags': initial_flags, 'requests': []}

        def ioctl(_fd, request, payload, mutate_flag=True):
            state['requests'].append(request)
            if not mutate_flag or not isinstance(payload, bytearray):
                raise AssertionError('expected a mutable ioctl buffer')
            if request == state['get_request']:
                payload[:] = struct.pack('@L', state['flags'])
            elif request == state['set_request']:
                if not ignore_set:
                    state['flags'] = struct.unpack('@L', payload)[0]
            else:
                raise AssertionError('unexpected ioctl request')
            return 0

        return state, ioctl

    def test_set_and_clear_immutable_preserves_other_filesystem_flags(self):
        from supervisor.config_lock import FS_IOC_GETFLAGS, FS_IOC_SETFLAGS

        flags = 0x8000
        state, ioctl = self.make_ioctl(flags)
        state['get_request'] = FS_IOC_GETFLAGS
        state['set_request'] = FS_IOC_SETFLAGS

        self.assertTrue(set_immutable(17, True, ioctl_fn=ioctl))
        self.assertTrue(is_immutable(17, ioctl_fn=ioctl))
        self.assertEqual(state['flags'], flags | FS_IMMUTABLE_FL)

        self.assertFalse(set_immutable(17, False, ioctl_fn=ioctl))
        self.assertFalse(is_immutable(17, ioctl_fn=ioctl))
        self.assertEqual(state['flags'], flags)

    def test_immutable_set_fails_if_filesystem_does_not_read_back_the_flag(self):
        from supervisor.config_lock import FS_IOC_GETFLAGS, FS_IOC_SETFLAGS

        state, ioctl = self.make_ioctl(0, ignore_set=True)
        state['get_request'] = FS_IOC_GETFLAGS
        state['set_request'] = FS_IOC_SETFLAGS
        with self.assertRaises(OSError):
            set_immutable(17, True, ioctl_fn=ioctl)

    def test_enabled_must_be_a_boolean(self):
        with self.assertRaises(ValueError):
            set_immutable(17, 1, ioctl_fn=lambda *_args, **_kwargs: None)
    @staticmethod
    def _config_stat(expected):
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_uid=0, st_gid=1000,
                               st_nlink=1, st_size=len(expected))

    def test_initialize_config_fd_writes_exact_bytes_and_verifies_protection(self):
        expected = b'{"models":{"providers":{"ollama":{}}}}\n'
        info = self._config_stat(expected)
        calls = []
        with tempfile.TemporaryFile() as stream:
            fd = stream.fileno()
            result = initialize_config_fd(
                fd, expected, require_immutable=True,
                fchown_fn=lambda fd, uid, gid: calls.append(('chown', fd, uid, gid)),
                fchmod_fn=lambda fd, mode: calls.append(('chmod', fd, mode)),
                fsync_fn=lambda fd: calls.append(('fsync', fd)),
                set_immutable_fn=lambda fd, enabled: calls.append(('immutable', fd, enabled)),
                fstat_fn=lambda _fd: info, immutable_fn=lambda _fd: True)
            os.lseek(fd, 0, os.SEEK_SET)
            self.assertEqual(os.read(fd, len(expected) + 1), expected)
        self.assertIs(result, info)
        self.assertIn(('chown', fd, 0, 1000), calls)
        self.assertIn(('chmod', fd, 0o440), calls)
        self.assertIn(('immutable', fd, True), calls)

    def test_replace_locked_config_at_atomically_swaps_only_expected_policy_bytes(self):
        class FakeFilesystem:
            def __init__(self, initial):
                self.files = {'openclaw.json': self._new_file(initial, 1, True)}
                self.handles = {}
                self.next_fd = 10
            @staticmethod
            def _new_file(content, inode, immutable):
                return {'content': content, 'immutable': immutable, 'info': SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o440, st_uid=0, st_gid=1000,
                    st_nlink=1, st_size=len(content), st_dev=1, st_ino=inode)}
            def open(self, name, _flags, _mode=None, *, dir_fd=None):
                if name not in self.files:
                    if _flags & os.O_CREAT:
                        self.files[name] = self._new_file(b'', 2, False)
                    else:
                        raise FileNotFoundError(name)
                fd = self.next_fd
                self.next_fd += 1
                self.handles[fd] = self.files[name]
                return fd
            def fstat(self, fd):
                return self.handles[fd]['info']
            def stat(self, name, *, dir_fd=None, follow_symlinks=True):
                return self.files[name]['info']
            def read(self, fd, *, require_immutable=True):
                item = self.handles[fd]
                if require_immutable and not item['immutable']:
                    raise OSError('not immutable')
                return item['info'], item['content']
            def initialize(self, fd, data, *, require_immutable=True):
                item = self.handles[fd]
                item['content'] = data
                item['info'].st_size = len(data)
                item['immutable'] = require_immutable
                return item['info']
            def is_immutable(self, fd):
                return self.handles[fd]['immutable']
            def set_immutable(self, fd, enabled):
                self.handles[fd]['immutable'] = enabled
            def replace(self, source, target, *, src_dir_fd=None, dst_dir_fd=None):
                self.files[target] = self.files.pop(source)
            def unlink(self, name, *, dir_fd=None):
                del self.files[name]
            def verify(self, fd, expected, *, require_immutable=True):
                item = self.handles[fd]
                if item['content'] != expected or (require_immutable and not item['immutable']):
                    raise OSError('verification failed')
                return item['info']
            @staticmethod
            def fsync(_fd):
                return None

        old = b'{"gateway":{},"models":{"selected":"old"}}\n'
        new = b'{"gateway":{},"models":{"selected":"new"}}\n'
        fs = FakeFilesystem(old)
        replace_locked_config_at(
            99, old, new, open_fn=fs.open, fstat_fn=fs.fstat, stat_fn=fs.stat,
            read_fn=fs.read, initialize_fn=fs.initialize,
            is_immutable_fn=fs.is_immutable, set_immutable_fn=fs.set_immutable,
            replace_fn=fs.replace, unlink_fn=fs.unlink, fsync_fn=fs.fsync,
            verify_fn=fs.verify, close_fn=lambda _fd: None, nofollow_flag=1)
        self.assertEqual(fs.files['openclaw.json']['content'], new)
        self.assertTrue(fs.files['openclaw.json']['immutable'])
        self.assertNotIn('.openclaw.json.update', fs.files)

    def test_read_managed_config_fd_returns_verified_bounded_bytes(self):
        expected = b'{"models":{}}\n'
        info = self._config_stat(expected)
        observed_info, content = read_managed_config_fd(
            11, fstat_fn=lambda _fd: info,
            read_fn=lambda _fd, _limit: expected,
            immutable_fn=lambda _fd: True)
        self.assertIs(observed_info, info)
        self.assertEqual(content, expected)

    def test_verify_config_fd_accepts_exact_locked_root_owned_config(self):
        expected = b'{"models":{}}\n'
        info = self._config_stat(expected)
        result = verify_config_fd(
            11, expected, fstat_fn=lambda _fd: info,
            read_fn=lambda _fd, _limit: expected,
            immutable_fn=lambda _fd: True)
        self.assertIs(result, info)

    def test_verify_config_fd_rejects_untrusted_owner_or_metadata(self):
        expected = b'{"models":{}}\n'
        for changes in ({'st_uid': 1000}, {'st_gid': 1000 + 1}, {'st_nlink': 2},
                        {'st_mode': stat.S_IFREG | 0o640}):
            with self.subTest(changes=changes):
                values = vars(self._config_stat(expected)).copy()
                values.update(changes)
                with self.assertRaises(OSError):
                    verify_config_fd(
                        11, expected, fstat_fn=lambda _fd, info=SimpleNamespace(**values): info,
                        read_fn=lambda _fd, _limit: expected,
                        immutable_fn=lambda _fd: True)

    def test_verify_config_fd_rejects_content_drift_and_missing_immutable_flag(self):
        expected = b'{"models":{}}\n'
        info = self._config_stat(expected)
        with self.assertRaises(OSError):
            verify_config_fd(11, expected, fstat_fn=lambda _fd: info,
                             read_fn=lambda _fd, _limit: b'{"models":{}}',
                             immutable_fn=lambda _fd: True)
        with self.assertRaises(OSError):
            verify_config_fd(11, expected, fstat_fn=lambda _fd: info,
                             read_fn=lambda _fd, _limit: expected,
                             immutable_fn=lambda _fd: False)

    def test_verify_config_fd_can_verify_read_only_mount_without_immutable_flag(self):
        expected = b'{"models":{}}\n'
        info = self._config_stat(expected)
        self.assertIs(
            verify_config_fd(11, expected, require_immutable=False,
                             fstat_fn=lambda _fd: info,
                             read_fn=lambda _fd, _limit: expected,
                             immutable_fn=lambda _fd: False),
            info)


if __name__ == '__main__':
    unittest.main()
