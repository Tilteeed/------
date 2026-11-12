import stat
import sys
import types
import unittest
from contextlib import ExitStack
from pathlib import PurePosixPath
from types import SimpleNamespace
from unittest.mock import Mock, patch

from supervisor import service


class FakePath:
    def __init__(self, value): self.value = str(value)
    @property
    def parent(self): return FakePath(PurePosixPath(self.value).parent)
    @property
    def name(self): return PurePosixPath(self.value).name
    def __truediv__(self, other): return FakePath(PurePosixPath(self.value) / str(other))
    def __eq__(self, other): return isinstance(other, FakePath) and self.value == other.value
    def __str__(self): return self.value
    def is_relative_to(self, other): return False
    def lstat(self): return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
    def resolve(self, **kwargs): return self
    def is_symlink(self): return False


class ReadinessShutdownTests(unittest.TestCase):
    def test_production_startup_failure_closes_cache_and_other_resources(self):
        profile = SimpleNamespace(storage=SimpleNamespace(mountpoint='/srv/pool'), profile_version=1)
        config = dict(profile_path='/etc/profile', state_dir='/var/lib/svc', socket_path='/run/svc/control.sock',
                      token_file='/var/lib/svc/service.token', image='image', agent_network_pool='a',
                      frontend_network_pool='b', capacity_ram_bytes=1, capacity_cpu_millicores=1,
                      capacity_disk_bytes=1, disk_floor_bytes=0, network_profile_default='none', control_ui_domain=None)
        metrics = Mock(); metrics.snapshot.return_value = dict(total_ram_bytes=2, total_cpu_millicores=2, total_disk_bytes=2)
        store = Mock(); controller = Mock(); controller._sample.side_effect = RuntimeError('stop')
        fcntl = types.SimpleNamespace(flock=Mock(), LOCK_EX=1, LOCK_NB=2)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {'fcntl': fcntl}))
            for name, value in [('Path', FakePath), ('load_profile', Mock(return_value=profile)),
                                ('_trusted_directory', Mock()), ('_runtime_firewall', Mock()),
                                ('HostMetrics', Mock(return_value=metrics)), ('_root_file', Mock(return_value=123)),
                                ('_service_token', Mock()), ('RuntimeStore', Mock(return_value=store)),
                                ('RuntimeService', Mock(return_value=controller)), ('asdict', Mock(return_value={}))]:
                stack.enter_context(patch.object(service, name, value))
            stack.enter_context(patch.object(service.os, 'umask'))
            stack.enter_context(patch.object(service.os, 'close'))
            stack.enter_context(patch.object(service.os.path, 'lexists', return_value=False))
            stack.enter_context(patch('supervisor.docker_engine.DockerEngine'))
            stack.enter_context(patch('supervisor.volumes.XfsVolumes'))
            with self.assertRaisesRegex(RuntimeError, 'stop'): service.serve(config)
        controller.model_status_cache.close.assert_called_once_with()
        metrics.close.assert_called_once_with()
        store.close.assert_called_once_with()
