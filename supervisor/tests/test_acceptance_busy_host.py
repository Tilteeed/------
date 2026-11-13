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
        self.commands, self.writes = [], []
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
            'Delegate': 'yes', 'DevicePolicy': 'closed', 'DeviceAllow': '',
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
        for name, value in [('IOReadBandwidthMax', io.read_bps), ('IOWriteBandwidthMax', io.write_bps),
                            ('IOReadIOPSMax', io.read_iops), ('IOWriteIOPSMax', io.write_iops)]:
            self.props[name] = io.device + ' ' + str(value)
        self.bpf = '[{"id":17,"attach_type":"device","attach_flags":"multi","name":""}]'
        self.mounted = False
        self.visible_ids = {}

    def visible_mount_id(self, path):
        return self.visible_ids[path]

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
            return '\n'.join(k + '=' + v for k, v in self.props.items())
        if argv == ('systemd-run', '--version'):
            return 'systemd 249 (249.11-synthetic)\n'
        if argv == ('dockerd', '--version'):
            return 'Docker version 29.0.0, build synthetic\n'
        if argv[:3] == ('bpftool', '-j', 'cgroup'):
            return self.bpf
        if argv[0] == 'mount':
            if argv[1:3] == ('-t', 'tmpfs'):
                self.mounted = True
                self.stats[self.plan.workspace].st_dev = 10
                self.stats[self.plan.workspace].st_ino = 1
                self.files['/proc/self/mountinfo'] += f'11 1 0:28 / {self.plan.workspace} rw,nodev,nosuid - tmpfs {self.plan.unit[:-8]} rw\n'
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


def fixture():
    h = helper()
    b = h.ApprovedBudget(25, 268435456, 0, 64, 60, 5, 67108864, 1024,
                        h.IOLimit('/dev/vda', 252, 0, 1048576, 1048576, 100, 100))
    p = h.JobPlan('acceptance-' + 'a' * 32 + '.service', b)
    return h, p, SyntheticLinux(h, p)


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
        from unittest.mock import patch
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
                     patch('builtins.open', return_value=io.BytesIO(data)):
                    if expected is None:
                        with self.assertRaisesRegex(h.Rejected, 'diagnostic bound'):
                            ops.visible_mount_id('/dev')
                    else:
                        self.assertEqual(ops.visible_mount_id('/dev'), expected)
                    self.assertEqual(opened.call_args_list[1].args[0], '/proc/self/fdinfo/37')
                    closed.assert_called_once_with(37)

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


class ChildInspectionTests(unittest.TestCase):
    def test_reads_exact_identity_kernel_limits_and_device_bpf_before_mutation(self):
        h, p, ops = fixture()
        observed = h.inspect_owned_job(p, ops=ops)
        self.assertEqual(observed.invocation_id, ops.invocation_id)
        self.assertEqual(observed.cgroup_path, ops.cg)
        self.assertEqual(observed.workspace_identity, (9, ops.stats[p.workspace].st_ino))
        self.assertFalse(ops.writes)
        self.assertFalse(any(c[0] == 'mount' or (c[0] == 'dockerd' and c != ('dockerd', '--version')) for c in ops.commands))


class PreparationTests(unittest.TestCase):
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
            lambda h, p, o: o.props.update(DeviceAllow='/dev/fake rw'),
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
