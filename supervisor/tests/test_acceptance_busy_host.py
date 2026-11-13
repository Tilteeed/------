"""Portable policy tests. Synthetic adapters are NOT Linux acceptance evidence."""
import dataclasses
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]


def helper():
    spec = importlib.util.spec_from_file_location("acceptance_busy_host", ROOT / "scripts/acceptance_busy_host.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BudgetAndLauncherTests(unittest.TestCase):
    def test_launcher_is_quiet_to_preserve_child_json_stdout(self):
        h, p, _ = fixture()
        argv = h.launcher_argv(p, ('/usr/bin/python3', '/opt/acceptance.py'))
        self.assertIn('--quiet', argv[:argv.index('--')])

    def test_explicit_frozen_budget_constructs_whole_job_launcher(self):
        h = helper()
        budget = h.ApprovedBudget(cpu_quota_percent=25, memory_bytes=268435456,
            swap_bytes=0, tasks=64, runtime_seconds=60, stop_seconds=5,
            tmpfs_bytes=67108864, tmpfs_inodes=1024,
            io=h.IOLimit('/dev/vda', 252, 0, 1048576, 1048576, 100, 100))
        plan = h.JobPlan('acceptance-' + 'a' * 32 + '.service', budget)
        argv = h.launcher_argv(plan, ('/usr/bin/python3', '/opt/acceptance.py'))
        for item in ('--wait', '--pipe', '--collect', '--unit=' + plan.unit,
                     '--property=CPUQuota=25%', '--property=MemoryMax=268435456',
                     '--property=MemorySwapMax=0', '--property=TasksMax=64',
                     '--property=RuntimeMaxSec=60s', '--property=KillMode=control-group',
                     '--property=OOMPolicy=kill', '--property=DevicePolicy=closed',
                     '--property=PrivateDevices=no', '--property=ProtectSystem=strict', '--property=Delegate=yes',
                     '--property=IOReadBandwidthMax=/dev/vda 1048576',
                     '--property=IOWriteIOPSMax=/dev/vda 100'):
            self.assertIn(item, argv)
        self.assertEqual(argv[-3:], ('--', '/usr/bin/python3', '/opt/acceptance.py'))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            budget.tasks = 999
        for key, value in [('cpu_quota_percent', 0), ('memory_bytes', True),
                           ('swap_bytes', -1), ('tmpfs_bytes', budget.memory_bytes),
                           ('tmpfs_inodes', 0), ('runtime_seconds', 0)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                dataclasses.replace(budget, **{key: value})
        with self.assertRaises(ValueError):
            h.JobPlan('docker.service', budget)
        with self.assertRaises(ValueError):
            h.launcher_argv(plan, ('relative-command',))


class SyntheticLinux:
    """Deterministic filesystem/process/command adapter; NEVER probes the host."""
    def __init__(self, h, plan):
        import stat
        from types import SimpleNamespace
        self.h, self.plan = h, plan
        self.pid, self.uid = 701, 0
        self.invocation_id = 'b' * 32
        self.commands, self.writes, self.events = [], [], []
        self.systemctl_available = True
        self.busctl_overrides = {}
        self.cg = '/sys/fs/cgroup' + plan.cgroup
        b, io = plan.budget, plan.budget.io
        self.files = {
            '/etc/os-release': 'ID=ubuntu\nVERSION_ID="22.04"\n',
            '/proc/sys/kernel/osrelease': '5.15.0-synthetic\n',
            '/proc/self/cgroup': '0::' + plan.cgroup + '\n',
            self.cg + '/cgroup.type': 'domain\n',
            self.cg + '/cgroup.controllers': 'cpu io memory pids\n',
            self.cg + '/cgroup.subtree_control': '',
            self.cg + '/cgroup.procs': '701\n',
            self.cg + '/cpu.max': '25000 100000\n',
            self.cg + '/memory.max': str(b.memory_bytes),
            self.cg + '/memory.swap.max': str(b.swap_bytes),
            self.cg + '/memory.oom.group': '1',
            self.cg + '/pids.max': str(b.tasks),
            self.cg + '/io.max': f'{io.major}:{io.minor} rbps={io.read_bps} wbps={io.write_bps} riops={io.read_iops} wiops={io.write_iops}\n',
            '/proc/self/mountinfo': (
                '10 1 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n'
                '90 1 0:5 / /dev rw - devtmpfs udev rw\n'
                '91 90 0:6 / /dev/pts rw - devpts devpts rw\n'
                '92 1 0:7 / /tmp rw - tmpfs inherited rw\n'
                '93 1 0:8 / /var/tmp rw - tmpfs inherited rw\n'
                '94 1 0:30 / /run ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=67108864,mode=755\n'
                f'95 94 0:30 /{plan.unit[:-8]} {plan.workspace} rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=67108864,mode=755\n'
            ),
        }
        self.namespaces = {('self', 'mnt'): 'mnt:[2]', ('1', 'mnt'): 'mnt:[1]',
                           ('self', 'net'): 'net:[2]', ('1', 'net'): 'net:[1]',
                           ('self', 'cgroup'): 'cgroup:[1]', ('1', 'cgroup'): 'cgroup:[1]'}
        self.stats = {}
        for path in ('/', '/run', plan.workspace, '/sys', '/sys/fs', '/sys/fs/cgroup', '/sys/fs/cgroup/system.slice', self.cg):
            self.stats[path] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | (0o700 if path == plan.workspace else 0o755), st_dev=9, st_ino=len(self.stats) + 1)
        self.stats[io.device] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFBLK | 0o600, st_rdev=(io.major << 8) | io.minor)
        self.children = {plan.workspace: [], self.cg: []}
        self.props = {
            'Id': plan.unit, 'LoadState': 'loaded', 'ActiveState': 'active',
            'SubState': 'running', 'Transient': 'yes', 'MainPID': '701',
            'InvocationID': self.invocation_id, 'ControlGroup': plan.cgroup,
            'Delegate': 'yes', 'DevicePolicy': 'closed',
            'PrivateMounts': 'yes', 'PrivateNetwork': 'no', 'PrivateDevices': 'no',
            'ProtectSystem': 'strict', 'ReadWritePaths': plan.workspace + ' /sys/fs/cgroup' + plan.cgroup,
            'KillMode': 'control-group', 'OOMPolicy': 'kill', 'SendSIGKILL': 'yes',
            'RuntimeMaxUSec': '1min', 'TimeoutStopUSec': '5s',
            'CPUQuotaPerSecUSec': '250ms', 'CPUQuotaPeriodUSec': '100ms',
            'MemoryMax': str(b.memory_bytes), 'MemorySwapMax': str(b.swap_bytes),
            'TasksMax': str(b.tasks), 'User': 'root', 'Group': 'root',
            'RuntimeDirectory': plan.unit[:-8], 'RuntimeDirectoryMode': '0700',
            'RuntimeDirectoryPreserve': 'no',
        }
        self.device_allow = 'a(ss) 0\n'
        for name, value in [('IOReadBandwidthMax', io.read_bps), ('IOWriteBandwidthMax', io.write_bps),
                            ('IOReadIOPSMax', io.read_iops), ('IOWriteIOPSMax', io.write_iops)]:
            self.props[name] = io.device + ' ' + str(value)
        self.bpf = '[{"id":17,"attach_type":"device","attach_flags":"multi","name":""}]'
        self.mounted = False
        self.visible_ids = {'/run': '94', plan.workspace: '95'}

    def visible_mount_id(self, path):
        return self.visible_ids[path]

    def busctl_property(self, interface, name):
        import json
        if name in self.busctl_overrides:
            return self.busctl_overrides[name]
        if name == 'DeviceAllow':
            return self.device_allow
        value = self.props[name]
        if interface == 'org.freedesktop.systemd1.Unit':
            if name == 'InvocationID':
                return 'ay 16 ' + ' '.join(str(byte) for byte in bytes.fromhex(value))
            if name == 'Transient':
                return 'b yes' if value == 'yes' else 'b no'
            return 's ' + json.dumps(value)
        if name in ('Delegate', 'PrivateDevices', 'PrivateMounts', 'PrivateNetwork', 'SendSIGKILL'):
            return 'b yes' if value == 'yes' else 'b no'
        if name in ('ReadWritePaths', 'RuntimeDirectory'):
            values = value.split()
            return 'as ' + str(len(values)) + ''.join(' ' + json.dumps(item) for item in values)
        if name == 'RuntimeDirectoryMode':
            return 'u ' + str(int(value, 8))
        if name.startswith('IO'):
            device, amount = value.rsplit(' ', 1)
            return 'a(st) 1 ' + json.dumps(device) + ' ' + amount
        if name in ('MainPID',):
            return 'u ' + value
        if name in ('MemoryMax', 'MemorySwapMax', 'TasksMax'):
            return 't ' + value
        if name == 'RuntimeMaxUSec':
            return 't 60000000'
        if name == 'TimeoutStopUSec':
            return 't 5000000'
        if name == 'CPUQuotaPerSecUSec':
            return 't 250000'
        if name == 'CPUQuotaPeriodUSec':
            return 't 100000'
        return 's ' + json.dumps(value)

    def clone_mount_namespace(self):
        """Model CLONE_NEWNS: all mount IDs change, backing identities do not."""
        self.namespaces[('self', 'mnt')] = 'mnt:[3]'
        lines = []
        remap = {}
        for line in self.files['/proc/self/mountinfo'].splitlines():
            fields = line.split()
            remap[fields[0]] = str(int(fields[0]) + 100)
        for line in self.files['/proc/self/mountinfo'].splitlines():
            fields = line.split()
            fields[0] = remap[fields[0]]
            fields[1] = remap.get(fields[1], fields[1])
            lines.append(' '.join(fields))
        self.files['/proc/self/mountinfo'] = '\n'.join(lines) + '\n'
        self.visible_ids = {path: remap[value] for path, value in self.visible_ids.items()}

    def read(self, path):
        return self.files[path]

    def mkdir(self, path):
        import stat
        from types import SimpleNamespace
        if path in self.stats:
            raise FileExistsError(path)
        parent, _, name = path.rpartition('/')
        self.children.setdefault(parent, []).append(name)
        self.children[path] = []
        self.stats[path] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700,
                                          st_dev=10 if path.startswith(self.plan.workspace + '/') else 9,
                                          st_ino=100 + len(self.stats))
        if path.startswith(self.cg + '/'):
            self.files[path + '/cgroup.procs'] = ''
            self.files[path + '/cgroup.subtree_control'] = ''

    def write(self, path, value, *, create=False):
        if create and path in self.files:
            raise FileExistsError(path)
        self.writes.append((path, value))
        self.files[path] = value
        if path.endswith('/cgroup.subtree_control'):
            self.files[path] = ' '.join(x.lstrip('+') for x in value.split())
        if path == self.cg + '/supervisor/cgroup.procs':
            self.files[self.cg + '/cgroup.procs'] = ''
            self.files['/proc/self/cgroup'] = '0::' + self.plan.cgroup + '/supervisor'
            self.files['/proc/701/cgroup'] = self.files['/proc/self/cgroup']

    def statvfs(self, path):
        from types import SimpleNamespace
        return SimpleNamespace(f_frsize=4096, f_blocks=self.plan.budget.tmpfs_bytes // 4096,
                               f_files=self.plan.budget.tmpfs_inodes)

    def mknod(self, path, major, minor):
        import stat
        from types import SimpleNamespace
        parent, _, name = path.rpartition('/')
        self.events.append(('mknod', name))
        self.children[parent].append(name)
        self.stats[path] = SimpleNamespace(st_mode=stat.S_IFCHR | 0o666, st_rdev=(major << 8) | minor)

    def symlink(self, target, path):
        parent, _, name = path.rpartition('/')
        self.children[parent].append(name)

    def device_numbers(self, observed):
        return observed.st_rdev >> 8, observed.st_rdev & 255

    def namespace(self, who, kind):
        return self.namespaces[(who, kind)]

    def stat(self, path):
        if self.mounted and (path == '/dev' or path.startswith('/dev/')):
            path = self.plan.workspace + path
        elif self.mounted and path in ('/tmp', '/var/tmp'):
            path = self.plan.workspace + '/tmp'
        return self.stats[path]

    def listdir(self, path):
        if self.mounted and (path == '/dev' or path.startswith('/dev/')):
            path = self.plan.workspace + path
        return tuple(self.children.get(path, ()))

    def run(self, argv):
        self.commands.append(tuple(argv))
        if argv[:2] == ('systemctl', 'list-units'):
            return self.unit_listing
        if argv[:2] == ('systemctl', 'list-unit-files'):
            if '--' in argv and not any(
                row.split() and row.split()[0] == self.plan.unit
                for row in self.file_listing.splitlines()
            ):
                # systemctl list-unit-files <missing-unit> exits with status 1.
                raise self.h.Rejected('diagnostic command failed: systemctl')
            return self.file_listing
        if argv[:2] == ('systemctl', 'show'):
            if not self.systemctl_available:
                raise self.h.Rejected('systemctl unavailable in synthetic private PID namespace')
            return '\n'.join(k + '=' + v for k, v in self.props.items())
        if argv[:3] == ('busctl', '--system', 'get-property'):
            interface = argv[5]
            return '\n'.join(self.busctl_property(interface, name) for name in argv[6:])
        if argv == ('systemd-run', '--version'):
            return 'systemd 249 (249.11-synthetic)\n'
        if argv == ('dockerd', '--version'):
            return 'Docker version 29.0.0, build synthetic\n'
        if argv[:3] == ('bpftool', '-j', 'cgroup'):
            return self.bpf
        if argv[0] == 'mount':
            self.events.append(('command', tuple(argv)))
            if argv[1:3] == ('-t', 'tmpfs'):
                self.mounted = True
                self.stats[self.plan.workspace].st_dev = 10
                self.stats[self.plan.workspace].st_ino = 1
                parent = self.visible_ids[self.plan.workspace]
                self.files['/proc/self/mountinfo'] += f'11 {parent} 0:28 / {self.plan.workspace} rw,nodev,nosuid - tmpfs {self.plan.unit[:-8]} rw\n'
                self.visible_ids[self.plan.workspace] = '11'
            elif argv[1] == '--bind' and argv[-1] == '/dev':
                self.files['/proc/self/mountinfo'] += f'12 1 0:28 /dev /dev rw,nosuid - tmpfs {self.plan.unit[:-8]} rw\n'
                self.visible_ids['/dev'] = '12'
            elif argv[1] == '--bind' and argv[-1] in ('/tmp', '/var/tmp'):
                mount_id = '13' if argv[-1] == '/tmp' else '15'
                self.files['/proc/self/mountinfo'] += f'{mount_id} 1 0:28 /tmp {argv[-1]} rw,nodev,nosuid - tmpfs {self.plan.unit[:-8]} rw\n'
                self.visible_ids[argv[-1]] = mount_id
            elif argv[1:3] == ('-t', 'devpts'):
                self.files['/proc/self/mountinfo'] += f'14 1 0:29 / /dev/pts rw,nosuid - devpts devpts rw,max={self.plan.budget.tasks}\n'
                self.visible_ids['/dev/pts'] = '14'
            return ''
        if argv[0] == 'dockerd' and argv[-1] == '--validate':
            return 'configuration OK\n'
        raise AssertionError('unexpected synthetic command: ' + repr(argv))


def fixture(unit='acceptance-' + 'a' * 32 + '.service'):
    h = helper()
    b = h.ApprovedBudget(25, 268435456, 0, 64, 60, 5, 67108864, 1024,
                        h.IOLimit('/dev/vda', 252, 0, 1048576, 1048576, 100, 100))
    p = h.JobPlan(unit, b)
    return h, p, SyntheticLinux(h, p)


class LinuxOpsReadTests(unittest.TestCase):
    def test_os_release_canonical_symlink_is_followed_to_regular_target(self):
        import errno
        import io
        import os
        import stat
        from types import SimpleNamespace
        from unittest.mock import call, patch
        h = helper()
        ops = h.LinuxOps.__new__(h.LinuxOps)
        data = b'ID=ubuntu\nVERSION_ID="22.04"\n'
        flags = os.O_RDONLY | 0x20000
        with patch.object(os, 'O_NOFOLLOW', 0x20000, create=True), \
             patch.object(os, 'open', side_effect=(OSError(errno.ELOOP, 'symlink'), 42)) as opened, \
             patch.object(os, 'readlink', return_value='../usr/lib/os-release') as readlink, \
             patch.object(os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644)), \
             patch.object(os, 'fdopen', return_value=io.BytesIO(data)) as fdopen, \
             patch.object(os, 'close') as closed:
            self.assertEqual(ops.read('/etc/os-release'), data.decode())
        self.assertEqual(opened.call_args_list, [
            call('/etc/os-release', flags),
            call('/usr/lib/os-release', flags),
        ])
        readlink.assert_called_once_with('/etc/os-release')
        fdopen.assert_called_once_with(42, 'rb', closefd=False)
        closed.assert_called_once_with(42)

    def test_os_release_rejects_noncanonical_symlink_target(self):
        import errno
        import os
        from unittest.mock import patch
        h = helper()
        ops = h.LinuxOps.__new__(h.LinuxOps)
        with patch.object(os, 'O_NOFOLLOW', 0x20000, create=True), \
             patch.object(os, 'open', side_effect=OSError(errno.ELOOP, 'symlink')) as opened, \
             patch.object(os, 'readlink', return_value='/tmp/os-release'):
            with self.assertRaisesRegex(h.Rejected, 'unsupported /etc/os-release symlink target'):
                ops.read('/etc/os-release')
        opened.assert_called_once_with('/etc/os-release', os.O_RDONLY | 0x20000)


class VisibleMountAdapterTests(unittest.TestCase):
    def test_fdinfo_missing_malformed_or_duplicate_mount_id_closes_fd_and_rejects(self):
        import os
        from unittest.mock import Mock, patch
        h = helper()
        for text in ('pos: 0\n', 'mnt_id: -1\n', 'mnt_id: 0\n',
                     'mnt_id: 12 extra\n', 'mnt_id: 01\n',
                     'mnt_id: 12\nmnt_id: 13\n'):
            with self.subTest(text=text):
                ops = h.LinuxOps.__new__(h.LinuxOps)
                ops.read = Mock(return_value=text)
                with patch.object(os, 'O_PATH', 0x200000, create=True), \
                     patch.object(os, 'O_NOFOLLOW', 0x20000, create=True), \
                     patch.object(os, 'O_CLOEXEC', 0x80000, create=True), \
                     patch.object(os, 'open', return_value=37), \
                     patch.object(os, 'close') as closed:
                    with self.assertRaises(h.Rejected):
                        ops.visible_mount_id('/dev')
                    closed.assert_called_once_with(37)

    def test_fdinfo_read_is_bounded_and_closes_path_fd_on_read_failure(self):
        import io
        import os
        from unittest.mock import call, patch
        h = helper()
        ops = h.LinuxOps.__new__(h.LinuxOps)
        for data, expected in ((b'mnt_id:\t47\n', '47'),
                               (b'mnt_id:\t47\n' + b'x' * h._READ_LIMIT, None)):
            with self.subTest(oversized=expected is None):
                with patch.object(os, 'O_PATH', 0x200000, create=True), \
                     patch.object(os, 'O_NOFOLLOW', 0x20000, create=True), \
                     patch.object(os, 'O_CLOEXEC', 0x80000, create=True), \
                     patch.object(os, 'open', side_effect=(37, 38)) as opened, \
                     patch.object(os, 'close') as closed, \
                     patch.object(os, 'fdopen', return_value=io.BytesIO(data)) as fdopen:
                    if expected is None:
                        with self.assertRaisesRegex(h.Rejected, 'diagnostic bound'):
                            ops.visible_mount_id('/dev')
                    else:
                        self.assertEqual(ops.visible_mount_id('/dev'), expected)
                    self.assertEqual(opened.call_args_list[1].args[0], '/proc/self/fdinfo/37')
                    fdopen.assert_called_once_with(38, 'rb', closefd=False)
                    self.assertEqual(closed.call_args_list, [call(38), call(37)])

    def test_fdinfo_uses_nofollow_path_fd_and_closes_it(self):
        import os
        from unittest.mock import Mock, patch
        h = helper()
        ops = h.LinuxOps.__new__(h.LinuxOps)
        ops.read = Mock(return_value='pos:\t0\nflags:\t010000000\nmnt_id:\t47\nino:\t1\n')
        with patch.object(os, 'O_PATH', 0x200000, create=True), \
             patch.object(os, 'O_NOFOLLOW', 0x20000, create=True), \
             patch.object(os, 'O_CLOEXEC', 0x80000, create=True), \
             patch.object(os, 'open', return_value=37) as opened, \
             patch.object(os, 'close') as closed:
            self.assertEqual(ops.visible_mount_id('/dev'), '47')
            self.assertEqual(opened.call_args.args[0], '/dev')
            self.assertEqual(opened.call_args.args[1] & (os.O_PATH | os.O_NOFOLLOW),
                             os.O_PATH | os.O_NOFOLLOW)
            ops.read.assert_called_once_with('/proc/self/fdinfo/37')
            closed.assert_called_once_with(37)


class LinuxOpsCommandTests(unittest.TestCase):
    def test_run_closes_pipe_stdin_without_opening_devnull(self):
        import errno
        import os
        import selectors
        import subprocess
        from unittest.mock import patch

        h = helper()
        ops = h.LinuxOps.__new__(h.LinuxOps)
        events = []

        class Pipe:
            def close(self):
                events.append('stdin_closed')

        class Stdout:
            def fileno(self):
                return 47

        class Child:
            stdin = Pipe()
            stdout = Stdout()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                events.append('child_exit')

            def wait(self, timeout=None):
                events.append('child_wait')
                return 0

            def poll(self):
                return 0

        child = Child()

        def popen(argv, **kwargs):
            events.append('popen')
            if kwargs['stdin'] is subprocess.DEVNULL:
                raise PermissionError(errno.EACCES, 'Permission denied', '/dev/null')
            if kwargs['stdin'] is not subprocess.PIPE:
                raise AssertionError('stdin must be a pipe')
            return child

        class Selector:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def register(self, fileobj, event):
                self.fileobj = fileobj

            def select(self, timeout):
                events.append('select')
                return [(self.fileobj, selectors.EVENT_READ)]

        with patch('subprocess.Popen', side_effect=popen), \
             patch('selectors.DefaultSelector', Selector), \
             patch.object(os, 'read', return_value=b''):
            self.assertEqual(ops.run(('mount', '-o', 'remount,bind,rw,dev,nosuid', '/dev')), '')

        self.assertLess(events.index('stdin_closed'), events.index('select'))
        self.assertIn('child_wait', events)


class ChildInspectionTests(unittest.TestCase):
    def test_workspace_self_bind_accepts_gpu_server_mountinfo_readwrite_exception(self):
        unit_name = 'acceptance-c9ef84a2bd7cc67c2e0f72463b77756c.service'
        h, p, ops = fixture(unit_name)
        workspace = p.workspace
        run_mount = (
            '882 876 0:25 / /run ro,nosuid,nodev,noexec,relatime shared:353 master:5 '
            '- tmpfs tmpfs rw,size=13187376k,mode=755,inode64')
        workspace_mount = (
            f'916 882 0:25 /{p.unit[:-8]} {workspace} rw,nosuid,nodev,noexec,relatime '
            'shared:358 master:5 - tmpfs tmpfs rw,size=13187376k,mode=755,inode64')
        retained = [line for line in ops.files['/proc/self/mountinfo'].splitlines()
                    if line.split()[4] not in ('/run', workspace)]
        ops.files['/proc/self/mountinfo'] = '\n'.join(retained + [run_mount, workspace_mount]) + '\n'
        ops.visible_ids.update({'/run': '882', workspace: '916'})

        observed = h.inspect_owned_job(p, ops=ops)

        self.assertEqual(observed.workspace_identity, (9, ops.stats[workspace].st_ino))
        self.assertFalse(ops.writes)
        self.assertFalse(any(command[0] == 'mount' for command in ops.commands))

    def test_reads_exact_identity_kernel_limits_and_device_bpf_before_mutation(self):
        h, p, ops = fixture()
        observed = h.inspect_owned_job(p, ops=ops)
        self.assertEqual(observed.invocation_id, ops.invocation_id)
        self.assertEqual(observed.cgroup_path, ops.cg)
        self.assertEqual(observed.workspace_identity, (9, ops.stats[p.workspace].st_ino))
        self.assertFalse(ops.writes)
        self.assertFalse(any(c[0] == 'mount' or (c[0] == 'dockerd' and c != ('dockerd', '--version')) for c in ops.commands))

    def test_workspace_accepts_only_exact_systemd_readwritepaths_self_bind(self):
        cases = (
            ('wrong parent', lambda row: row.replace('95 94 ', '95 1 ', 1)),
            ('wrong device', lambda row: row.replace('0:30', '0:31', 1)),
            ('wrong root', lambda row: row.replace('/acceptance-' + 'a' * 32, '/', 1)),
            ('read only', lambda row: row.replace(' rw,nosuid', ' ro,nosuid', 1)),
            ('wrong filesystem', lambda row: row.replace('tmpfs tmpfs', 'ext4 /dev/fake', 1)),
            ('unexpected mount options', lambda row: row.replace('relatime -', 'relatime,exec -', 1)),
        )
        for name, corrupt in cases:
            with self.subTest(case=name):
                h, p, ops = fixture()
                lines = ops.files['/proc/self/mountinfo'].splitlines()
                index = next(i for i, line in enumerate(lines) if line.startswith('95 '))
                lines[index] = corrupt(lines[index])
                ops.files['/proc/self/mountinfo'] = '\n'.join(lines) + '\n'
                with self.assertRaises(h.Rejected):
                    h.prepare_owned_job(p, ops=ops)
                self.assertFalse(ops.writes)
                self.assertFalse(any(command[0] == 'mount' for command in ops.commands))

        h, p, ops = fixture()
        lines = ops.files['/proc/self/mountinfo'].splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith('94 '))
        lines[index] = lines[index].replace(' /run ro,', ' /run rw,', 1)
        ops.files['/proc/self/mountinfo'] = '\n'.join(lines) + '\n'
        with self.assertRaisesRegex(h.Rejected, 'ReadWritePaths bind'):
            h.prepare_owned_job(p, ops=ops)
        self.assertFalse(ops.writes)
        self.assertFalse(any(command[0] == 'mount' for command in ops.commands))

        h, p, ops = fixture()
        ops.files['/proc/self/mountinfo'] += (
            f'96 94 0:30 /{p.unit[:-8]} {p.workspace} rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=67108864,mode=755\n')
        with self.assertRaisesRegex(h.Rejected, 'workspace mount stack'):
            h.prepare_owned_job(p, ops=ops)
        self.assertFalse(ops.writes)
        self.assertFalse(any(command[0] == 'mount' for command in ops.commands))

    def test_device_allow_requires_typed_empty_dbus_array_and_stays_strict(self):
        h, p, ops = fixture()
        # The systemctl output omits DeviceAllow; only a typed D-Bus empty
        # array is accepted as proof that no explicit exception is configured.
        observed = h._unit_properties(p, ops)
        self.assertEqual(observed['DeviceAllow'], '')
        self.assertEqual(ops.props['DevicePolicy'], 'closed')
        show = next(command for command in ops.commands if command[:2] == ('systemctl', 'show'))
        self.assertNotIn('DeviceAllow', show[4])
        busctl = next(command for command in ops.commands if command[:3] == ('busctl', '--system', 'get-property'))
        self.assertEqual(busctl[-3:], (
            self.path_for(p), 'org.freedesktop.systemd1.Service', 'DeviceAllow'))

        for readback, reason in (
            ('a(ss) 1 "/dev/fake" "rw"\n', 'count mismatch'),
            ('a(ss) 0 trailing\n', 'entry list'),
            ('s ""\n', 'D-Bus property'),
            ('', 'D-Bus property'),
        ):
            ops.device_allow = readback
            with self.subTest(readback=readback), self.assertRaisesRegex(h.Rejected, reason):
                h._unit_properties(p, ops)

        ops.device_allow = 'a(ss) 0\n'
        ops.props['DevicePolicy'] = 'auto'
        with self.assertRaisesRegex(h.Rejected, 'unit property mismatch: DevicePolicy'):
            h._unit_properties(p, ops)

    @staticmethod
    def path_for(plan):
        return '/org/freedesktop/systemd1/unit/' + plan.unit.replace('-', '_2d').replace('.', '_2e')


class PreparationTests(unittest.TestCase):
    def test_os_errors_report_fixed_substage_operation_and_errno(self):
        import errno

        cases = (
            ('cgroup_setup', 'create_supervisor_cgroup', 'mkdir'),
            ('tmpfs_setup', 'mount_workspace_tmpfs', 'tmpfs_mount'),
            ('device_creation', 'mknod_null', 'mknod'),
            ('config_setup', 'write_daemon_json', 'daemon_config'),
        )
        for substage, operation, failpoint in cases:
            with self.subTest(substage=substage, operation=operation):
                h, p, ops = fixture()
                denied = PermissionError(errno.EACCES, 'Permission denied', '/secret/never-report')
                if failpoint == 'mkdir':
                    ops.mkdir = lambda path: (_ for _ in ()).throw(denied)
                elif failpoint == 'tmpfs_mount':
                    original = ops.run
                    def run(argv):
                        if argv[:3] == ('mount', '-t', 'tmpfs'):
                            raise denied
                        return original(argv)
                    ops.run = run
                elif failpoint == 'mknod':
                    ops.mknod = lambda path, major, minor: (_ for _ in ()).throw(denied)
                else:
                    original = ops.write
                    def write(path, value, *, create=False):
                        if path.endswith('/daemon.json'):
                            raise denied
                        return original(path, value, create=create)
                    ops.write = write

                with self.assertRaises(h.PreparationOperationFailure) as caught:
                    h.prepare_owned_job(p, ops=ops)
                self.assertEqual(caught.exception.substage, substage)
                self.assertEqual(caught.exception.operation, operation)
                self.assertEqual(caught.exception.errno, errno.EACCES)
                self.assertEqual(caught.exception.exception_name, 'PermissionError')
                self.assertNotIn('/secret/never-report', str(caught.exception))

    def test_nested_workspace_mount_after_preparation_is_rejected(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        ops.files['/proc/self/mountinfo'] += (
            f'999 {ready.workspace_mount_id} 0:99 / {p.workspace}/foreign rw - tmpfs foreign rw\n')
        with self.assertRaisesRegex(h.Rejected, 'nested workspace mount'):
            h.verify_prepared_job(p, ready, ops=ops)

    def test_visible_overmounts_accept_hidden_old_mountinfo_records(self):
        h, p, ops = fixture()
        # Hidden IDs deliberately exceed the new visible IDs: max(ID) is wrong.
        ops.files['/proc/self/mountinfo'] += (
            '900 1 0:5 / /dev rw - devtmpfs udev rw\n'
            '901 900 0:6 / /dev/pts rw - devpts devpts rw\n'
            '902 1 0:7 / /tmp rw - tmpfs inherited rw\n'
            '903 1 0:8 / /var/tmp rw - tmpfs inherited rw\n'
        )
        ready = h.prepare_owned_job(p, ops=ops)
        self.assertEqual(ready.device_mount_id, '12')
        h.verify_prepared_job(p, ready, ops=ops)

    def test_wrong_visible_top_never_uses_a_matching_hidden_row_or_highest_id(self):
        for target in ('workspace', '/dev', '/dev/pts', '/tmp', '/var/tmp'):
            for wrong_id in ('2', '999'):
                with self.subTest(target=target, wrong_id=wrong_id):
                    h, p, ops = fixture()
                    ready = h.prepare_owned_job(p, ops=ops)
                    target_path = p.workspace if target == 'workspace' else target
                    ops.files['/proc/self/mountinfo'] += (
                        f'{wrong_id} 1 0:99 / {target_path} rw - foreignfs foreign rw\n')
                    ops.visible_ids[target_path] = wrong_id
                    with self.assertRaises(h.Rejected):
                        h.verify_prepared_job(p, ready, ops=ops)

    def test_missing_duplicate_or_wrong_path_visible_id_is_rejected(self):
        for case in ('missing', 'duplicate', 'wrong_path', 'malformed'):
            with self.subTest(case=case):
                h, p, ops = fixture()
                ready = h.prepare_owned_job(p, ops=ops)
                if case == 'missing':
                    ops.visible_ids['/dev'] = '999'
                elif case == 'duplicate':
                    ops.files['/proc/self/mountinfo'] += '12 1 0:99 / /foreign rw - tmpfs foreign rw\n'
                elif case == 'wrong_path':
                    ops.visible_ids['/dev'] = ops.visible_ids['/tmp']
                else:
                    ops.visible_ids['/dev'] = '../12'
                with self.assertRaises(h.Rejected):
                    h.verify_prepared_job(p, ready, ops=ops)

    def test_private_pid_one_verifies_against_captured_outer_main_pid(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        # Preparation ran as the manager's exact MainPID. The private PID child
        # has a different local PID but remains in the same supervisor leaf.
        ops.pid = 1
        ops.files['/proc/1/cgroup'] = ops.files['/proc/self/cgroup']
        h.verify_prepared_job(p, ready, pids=(1,), ops=ops)
        self.assertEqual(ready.owned.main_pid, 701)
        ops.props['MainPID'] = '1'
        with self.assertRaisesRegex(h.Rejected, 'MainPID'):
            h.verify_prepared_job(p, ready, ops=ops)

    def test_private_pid_child_must_still_prove_its_own_cgroup(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        ops.pid = 1
        ops.files['/proc/self/cgroup'] = '0::/foreign/supervisor'
        with self.assertRaisesRegex(h.Rejected, 'supervisor escaped owned leaf'):
            h.verify_prepared_job(p, ready, ops=ops)

    def test_prepare_rejects_non_main_pid_before_any_mutation(self):
        h, p, ops = fixture()
        ops.pid = 1
        with self.assertRaisesRegex(h.Rejected, 'MainPID'):
            h.prepare_owned_job(p, ops=ops)
        self.assertFalse(ops.writes)
        self.assertFalse(any(c[0] == 'mount' for c in ops.commands))

    def test_prepares_only_owned_subtree_and_private_bounded_storage(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        self.assertEqual(ready.container_cgroup_parent, p.cgroup + '/containers')
        self.assertEqual(ops.files[ops.cg + '/cgroup.procs'], '')
        self.assertEqual(ops.files[ops.cg + '/supervisor/cgroup.procs'], '701')
        self.assertEqual(ops.files[ops.cg + '/cgroup.subtree_control'], 'cpu io memory pids')
        self.assertTrue(all(path.startswith(ops.cg + '/') or path.startswith(p.workspace + '/') for path, _ in ops.writes))
        self.assertIn(('mount', '--make-rprivate', '/'), ops.commands)
        self.assertIn(('mount', '-t', 'tmpfs', '-o', 'size=67108864,nr_inodes=1024,mode=0700,uid=0,gid=0,nodev,nosuid',
                       'acceptance-' + 'a' * 32, p.workspace), ops.commands)
        null_creation = ops.events.index(('mknod', 'null'))
        private_dev_bind = ops.events.index(('command', ('mount', '--bind', p.workspace + '/dev', '/dev')))
        private_dev_remount = ops.events.index(('command', ('mount', '-o', 'remount,bind,rw,dev,nosuid', '/dev')))
        self.assertLess(null_creation, private_dev_bind)
        self.assertLess(private_dev_bind, private_dev_remount)
        self.assertIn('--storage-driver=vfs', ready.daemon_argv)
        self.assertIn('--cgroup-parent=' + ready.container_cgroup_parent, ready.daemon_argv)
        self.assertIn('--exec-opt=native.cgroupdriver=cgroupfs', ready.daemon_argv)
        self.assertIn('--host=unix://' + p.workspace + '/docker.sock', ready.daemon_argv)
        self.assertIn('--config-file=' + p.workspace + '/daemon.json', ready.daemon_argv)
        self.assertEqual(ready.docker_prefix, ('docker', '--config', p.workspace + '/client', '--host', 'unix://' + p.workspace + '/docker.sock'))
        self.assertFalse(any(k.startswith('DOCKER_') or 'PROXY' in k for k, _ in ready.environment))
        h.verify_prepared_job(p, ready, pids=(701,), ops=ops)
        self.assertFalse(any(c[0] == 'dockerd' and c != ('dockerd', '--version') and c[-1] != '--validate' for c in ops.commands))


class NamespaceRebindTests(unittest.TestCase):
    def test_rebind_uses_unit_and_service_dbus_when_systemctl_is_unavailable(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        parent_namespace = ops.namespace('self', 'mnt')
        ops.clone_mount_namespace()
        ops.pid = 1
        ops.files['/proc/1/cgroup'] = ops.files['/proc/self/cgroup']
        ops.systemctl_available = False
        command_start = len(ops.commands)

        child = h.rebind_prepared_namespace(p, ready,
            parent_mnt_namespace=parent_namespace, ops=ops)

        commands = ops.commands[command_start:]
        self.assertFalse(any(command[:2] == ('systemctl', 'show') for command in commands))
        property_calls = [command for command in commands
                          if command[:3] == ('busctl', '--system', 'get-property')]
        self.assertEqual(len(property_calls), 3)
        self.assertEqual(property_calls[0][5], 'org.freedesktop.systemd1.Unit')
        self.assertEqual(property_calls[1][5], 'org.freedesktop.systemd1.Service')
        self.assertEqual(property_calls[2][-1], 'DeviceAllow')
        self.assertEqual(child.mount_namespace, 'mnt:[3]')

        # Resource limits are still read back from the actual cgroup files.
        ops.files[ops.cg + '/memory.max'] = 'max'
        with self.assertRaisesRegex(h.Rejected, 'kernel bound mismatch: memory.max'):
            h.verify_prepared_job(p, child, pids=(1,), ops=ops, unit_properties_via_dbus=True)

    def test_dbus_rebind_keeps_service_identity_and_policy_checks_strict(self):
        cases = (
            ('DevicePolicy', 'auto', 'unit property mismatch: DevicePolicy'),
            ('ControlGroup', '/foreign', 'unit property mismatch: ControlGroup'),
            ('MainPID', '702', 'transient MainPID identity mismatch'),
            ('InvocationID', 'c' * 32, 'invocation identity mismatch'),
        )
        for property_name, changed_value, reason in cases:
            with self.subTest(property=property_name):
                h, p, ops = fixture()
                ready = h.prepare_owned_job(p, ops=ops)
                command_start = len(ops.commands)
                parent_namespace = ops.namespace('self', 'mnt')
                ops.clone_mount_namespace()
                ops.pid = 1
                ops.files['/proc/1/cgroup'] = ops.files['/proc/self/cgroup']
                ops.systemctl_available = False
                ops.props[property_name] = changed_value
                with self.assertRaisesRegex(h.Rejected, reason):
                    h.rebind_prepared_namespace(p, ready,
                        parent_mnt_namespace=parent_namespace, ops=ops)
                self.assertFalse(any(command[:2] == ('systemctl', 'show')
                                     for command in ops.commands[command_start:]))

    def test_child_rebind_accepts_fresh_ids_and_preserves_frozen_backing_and_owner(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        parent_namespace = ops.namespace('self', 'mnt')
        ops.clone_mount_namespace()
        ops.pid = 1
        ops.files['/proc/1/cgroup'] = ops.files['/proc/self/cgroup']
        before_commands, before_writes = len(ops.commands), list(ops.writes)
        child = h.rebind_prepared_namespace(p, ready,
            parent_mnt_namespace=parent_namespace, ops=ops)
        self.assertIsNot(child, ready)
        self.assertEqual(child.mount_namespace, 'mnt:[3]')
        self.assertEqual(ready.mount_namespace, parent_namespace)
        self.assertEqual(child.workspace_mount_id, '111')
        self.assertEqual(child.device_mount_id, '112')
        for name in ('owned', 'workspace_identity', 'container_cgroup_parent',
                     'daemon_argv', 'docker_prefix', 'environment'):
            self.assertEqual(getattr(child, name), getattr(ready, name))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            child.mount_namespace = 'mnt:[99]'
        self.assertEqual(ops.writes, before_writes)
        self.assertFalse(any(c[0] == 'mount' for c in ops.commands[before_commands:]))
        h.verify_prepared_job(p, child, pids=(1,), ops=ops)
        with self.assertRaisesRegex(h.Rejected, 'mount namespace'):
            h.verify_prepared_job(p, ready, ops=ops)

    def test_later_child_local_remount_is_rejected_even_with_identical_backing(self):
        for target in ('workspace', '/dev', '/tmp', '/var/tmp', '/dev/pts'):
            with self.subTest(target=target):
                h, p, ops = fixture()
                ready = h.prepare_owned_job(p, ops=ops)
                ops.clone_mount_namespace()
                child = h.rebind_prepared_namespace(p, ready,
                    parent_mnt_namespace=ready.mount_namespace, ops=ops)
                target = p.workspace if target == 'workspace' else target
                old_id = ops.visible_ids[target]
                old = next(line for line in ops.files['/proc/self/mountinfo'].splitlines()
                           if line.split()[0] == old_id)
                ops.files['/proc/self/mountinfo'] += '999 ' + old.split(' ', 1)[1] + '\n'
                ops.visible_ids[target] = '999'
                with self.assertRaises(h.Rejected):
                    h.verify_prepared_job(p, child, ops=ops)

    def test_wrong_parent_or_unchanged_or_malformed_current_namespace_is_rejected(self):
        cases = (('mnt:[99]', 'mnt:[3]'), ('net:[2]', 'mnt:[3]'),
                 (None, 'mnt:[3]'), ('mnt:[2]', 'mnt:[2]'),
                 ('mnt:[2]', 'net:[3]'), ('mnt:[2]', ''), ('mnt:[2]', 'mnt:[0]'))
        for parent, current in cases:
            with self.subTest(parent=parent, current=current):
                h, p, ops = fixture()
                ready = h.prepare_owned_job(p, ops=ops)
                ops.clone_mount_namespace()
                ops.namespaces[('self', 'mnt')] = current
                before = (list(ops.writes), len(ops.commands))
                with self.assertRaises(h.Rejected):
                    h.rebind_prepared_namespace(p, ready,
                        parent_mnt_namespace=parent, ops=ops)
                self.assertEqual(ops.writes, before[0])
                self.assertEqual(len(ops.commands), before[1])

    def test_rebind_rejects_foreign_backing_and_retains_all_resource_proofs(self):
        changes = (
            ('workspace inode', lambda h, p, o: setattr(o.stats[p.workspace], 'st_ino', 999)),
            ('workspace device', lambda h, p, o: setattr(o.stats[p.workspace], 'st_dev', 999)),
            ('cgroup identity', lambda h, p, o: setattr(o.stats[o.cg], 'st_ino', 999)),
            ('invocation', lambda h, p, o: setattr(o, 'invocation_id', 'c' * 32)),
            ('MainPID', lambda h, p, o: o.props.update(MainPID='999')),
            ('own cgroup', lambda h, p, o: o.files.update({'/proc/self/cgroup': '0::/foreign/supervisor'})),
            ('memory', lambda h, p, o: o.files.update({o.cg + '/memory.max': 'max'})),
            ('device BPF', lambda h, p, o: setattr(o, 'bpf', '[]')),
            ('private devices', lambda h, p, o: o.children[p.workspace + '/dev'].append('unexpected')),
            ('tmpfs bytes', lambda h, p, o: setattr(o, 'statvfs', lambda path:
                type('VFS', (), dict(f_frsize=4096, f_blocks=1, f_files=p.budget.tmpfs_inodes))())),
            ('tmpfs inodes', lambda h, p, o: setattr(o, 'statvfs', lambda path:
                type('VFS', (), dict(f_frsize=4096, f_blocks=p.budget.tmpfs_bytes // 4096, f_files=1))())),
            ('devpts bound', lambda h, p, o: o.files.update({'/proc/self/mountinfo':
                o.files['/proc/self/mountinfo'].replace('max=64', 'max=65')})),
            ('tmp bind', lambda h, p, o: o.files.update({'/proc/self/mountinfo':
                o.files['/proc/self/mountinfo'].replace('/tmp /tmp', '/foreign /tmp')})),
        )
        for name, change in changes:
            with self.subTest(proof=name):
                h, p, ops = fixture()
                ready = h.prepare_owned_job(p, ops=ops)
                ops.clone_mount_namespace()
                change(h, p, ops)
                before_writes, start = list(ops.writes), len(ops.commands)
                with self.assertRaises(h.Rejected):
                    h.rebind_prepared_namespace(p, ready,
                        parent_mnt_namespace=ready.mount_namespace, ops=ops)
                self.assertEqual(ops.writes, before_writes)
                self.assertFalse(any(c[0] == 'mount' for c in ops.commands[start:]))

    def test_rebind_rejects_wrong_visible_top_despite_matching_hidden_mount(self):
        for target in ('workspace', '/dev', '/dev/pts', '/tmp', '/var/tmp'):
            with self.subTest(target=target):
                h, p, ops = fixture()
                ready = h.prepare_owned_job(p, ops=ops)
                ops.clone_mount_namespace()
                target_path = p.workspace if target == 'workspace' else target
                ops.files['/proc/self/mountinfo'] += (
                    f'999 1 0:99 / {target_path} rw - foreignfs foreign rw\n')
                ops.visible_ids[target_path] = '999'
                with self.assertRaises(h.Rejected):
                    h.rebind_prepared_namespace(p, ready,
                        parent_mnt_namespace=ready.mount_namespace, ops=ops)

    def test_verification_rejects_namespace_change_even_with_unchanged_mount_ids(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        ops.namespaces[('self', 'mnt')] = 'mnt:[3]'
        with self.assertRaisesRegex(h.Rejected, 'mount namespace'):
            h.verify_prepared_job(p, ready, ops=ops)


class PublicAPITests(unittest.TestCase):
    def test_mapping_requires_every_budget_and_unknown_keys_are_rejected(self):
        h, p, _ = fixture()
        mapping = dataclasses.asdict(p.budget)
        self.assertEqual(h.Budget.from_mapping(mapping), p.budget)
        for bad in ({}, dict(mapping, unexplained=1), dict(mapping, tasks='64'),
                    dict(mapping, io=dict(mapping['io'], hidden=1))):
            with self.subTest(mapping=bad), self.assertRaises(ValueError):
                h.Budget.from_mapping(bad)
        self.assertEqual(h.systemd_run_argv(p, ('/usr/bin/true',)), h.launcher_argv(p, ('/usr/bin/true',)))

    def test_absence_check_rejects_loaded_or_installed_unit(self):
        h, p, ops = fixture()
        similar_name = p.unit[:-8] + '-other.service'
        ops.unit_listing = ''
        ops.file_listing = f'{similar_name} static\nother.service enabled\n'
        h.assert_unit_absent(p, ops=ops)
        self.assertEqual(
            ops.commands,
            [
                ('systemctl', 'list-units', '--all', '--full', '--no-legend', '--no-pager', '--', p.unit),
                ('systemctl', 'list-unit-files', '--all', '--full', '--no-legend', '--no-pager'),
            ],
        )
        for loaded, installed in [
            (f'{p.unit} loaded active running', ''),
            ('', f'{p.unit} static'),
        ]:
            ops.unit_listing, ops.file_listing = loaded, installed
            with self.subTest(loaded=loaded, installed=installed), self.assertRaises(h.Rejected):
                h.assert_unit_absent(p, ops=ops)


class RejectionTests(unittest.TestCase):
    def test_missing_or_foreign_preconditions_never_mount_or_write(self):
        changes = (
            lambda h, p, o: o.props.update(InvocationID='c' * 32),
            lambda h, p, o: o.props.update(Id='docker.service'),
            lambda h, p, o: o.props.update(ControlGroup='/foreign'),
            lambda h, p, o: setattr(o, 'device_allow', 'a(ss) 1 "/dev/fake" "rw"'),
            lambda h, p, o: o.props.pop('RuntimeMaxUSec'),
            lambda h, p, o: o.props.update(ProtectSystem='no'),
            lambda h, p, o: o.files.update({o.cg + '/memory.max': 'max'}),
            lambda h, p, o: o.files.update({o.cg + '/memory.swap.max': '1'}),
            lambda h, p, o: o.files.update({o.cg + '/cpu.max': 'max 100000'}),
            lambda h, p, o: o.files.update({o.cg + '/pids.max': 'max'}),
            lambda h, p, o: o.files.update({o.cg + '/memory.oom.group': '0'}),
            lambda h, p, o: o.files.update({o.cg + '/io.max': '252:1 rbps=1 wbps=1 riops=1 wiops=1'}),
            lambda h, p, o: o.files.update({o.cg + '/cgroup.controllers': 'cpu memory pids'}),
            lambda h, p, o: o.files.update({o.cg + '/cgroup.procs': '701 702'}),
            lambda h, p, o: o.files.update({'/proc/self/cgroup': '0::/foreign'}),
            lambda h, p, o: setattr(o, 'bpf', '[]'),
            lambda h, p, o: setattr(o, 'bpf', '[{"id":2,"attach_type":"ingress"}]'),
            lambda h, p, o: setattr(o.stats[p.workspace], 'st_uid', 1000),
            lambda h, p, o: setattr(o.stats[p.workspace], 'st_mode', 0o120700),
            lambda h, p, o: setattr(o.stats[p.workspace], 'st_mode', 0o40777),
            lambda h, p, o: o.children[p.workspace].append('preexisting'),
            lambda h, p, o: o.namespaces.update({('self', 'mnt'): o.namespaces[('1', 'mnt')]}),
        )
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                h, p, ops = fixture()
                change(h, p, ops)
                with self.assertRaises(h.Rejected):
                    h.prepare_owned_job(p, ops=ops)
                self.assertFalse(ops.writes)
                self.assertFalse(any(c[0] == 'mount' for c in ops.commands))

    def test_later_limit_identity_mount_device_and_pid_drift_is_rejected(self):
        changes = (
            lambda h, p, r, o: o.props.update(InvocationID='c' * 32),
            lambda h, p, r, o: o.files.update({o.cg + '/memory.max': 'max'}),
            lambda h, p, r, o: setattr(o.stats[o.cg], 'st_ino', 999),
            lambda h, p, r, o: setattr(o.stats[p.workspace], 'st_ino', 999),
            lambda h, p, r, o: o.children[p.workspace + '/dev'].append('nvidia_SYNTHETIC'),
            lambda h, p, r, o: o.files.update({'/proc/701/cgroup': '0::' + p.cgroup + '-foreign/x'}),
            lambda h, p, r, o: o.files.update({o.cg + '/cgroup.procs': '999'}),
        )
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                h, p, ops = fixture()
                ready = h.prepare_owned_job(p, ops=ops)
                change(h, p, ready, ops)
                with self.assertRaises(h.Rejected):
                    h.verify_prepared_job(p, ready, pids=(701,), ops=ops)

    def test_tmp_bind_must_be_read_back_not_merely_commanded(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        ops.files['/proc/self/mountinfo'] = '\n'.join(line for line in ops.files['/proc/self/mountinfo'].splitlines() if ' /tmp ' not in line)
        with self.assertRaises(h.Rejected):
            h.verify_prepared_job(p, ready, ops=ops)

    def test_container_pid_must_be_below_exact_container_parent(self):
        h, p, ops = fixture()
        ready = h.prepare_owned_job(p, ops=ops)
        ops.files['/proc/702/cgroup'] = '0::' + p.cgroup + '/containers/id'
        h.verify_prepared_job(p, ready, container_pids=(702,), ops=ops)
        ops.files['/proc/702/cgroup'] = '0::' + p.cgroup + '/supervisor'
        with self.assertRaises(h.Rejected):
            h.verify_prepared_job(p, ready, container_pids=(702,), ops=ops)


if __name__ == '__main__':
    unittest.main()
