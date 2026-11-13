"""Bounded, opt-in Linux acceptance job. No operations occur on import.

The caller approves every budget explicitly; these are not production defaults.
This is resource containment for trusted acceptance code, NOT a security boundary
against hostile root, nor a promise of zero impact on a shared kernel.

Compatibility references (official upstream, checked against target versions):
https://www.freedesktop.org/software/systemd/man/249/systemd.resource-control.html
https://www.freedesktop.org/software/systemd/man/249/systemd-run.html
https://www.freedesktop.org/software/systemd/man/249/systemd.exec.html
https://www.freedesktop.org/software/systemd/man/249/systemd.service.html
https://www.kernel.org/doc/html/v5.15/admin-guide/cgroup-v2.html
https://www.kernel.org/doc/html/v5.15/filesystems/tmpfs.html
https://docs.docker.com/reference/cli/dockerd/
"""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class IOLimit:
    device: str
    major: int
    minor: int
    read_bps: int
    write_bps: int
    read_iops: int
    write_iops: int

    def __post_init__(self):
        if not re.fullmatch(r'/dev/[A-Za-z0-9_/-]+', self.device) or '..' in self.device.split('/'):
            raise ValueError('explicit block device path required')
        for name in ('major', 'minor', 'read_bps', 'write_bps', 'read_iops', 'write_iops'):
            value = getattr(self, name)
            if type(value) is not int or value < (0 if name in ('major', 'minor') else 1):
                raise ValueError('invalid I/O budget: ' + name)


@dataclass(frozen=True)
class ApprovedBudget:
    cpu_quota_percent: int
    memory_bytes: int
    swap_bytes: int
    tasks: int
    runtime_seconds: int
    stop_seconds: int
    tmpfs_bytes: int
    tmpfs_inodes: int
    io: IOLimit

    @classmethod
    def from_mapping(cls, value):
        """Strict JSON-shaped schema; every numeric field and I/O device explicit."""
        from dataclasses import fields
        from collections.abc import Mapping
        if not isinstance(value, Mapping) or set(value) != {f.name for f in fields(cls)}:
            raise ValueError('budget must provide exactly all approved fields')
        io = value['io']
        if not isinstance(io, Mapping) or set(io) != {f.name for f in fields(IOLimit)}:
            raise ValueError('io must provide exactly all approved device fields')
        return cls(**dict(value, io=IOLimit(**io)))

    def __post_init__(self):
        for name in ('cpu_quota_percent', 'memory_bytes', 'swap_bytes', 'tasks',
                     'runtime_seconds', 'stop_seconds', 'tmpfs_bytes', 'tmpfs_inodes'):
            value = getattr(self, name)
            if type(value) is not int or value < (0 if name == 'swap_bytes' else 1):
                raise ValueError('invalid approved budget: ' + name)
        if not isinstance(self.io, IOLimit) or self.tmpfs_bytes >= self.memory_bytes:
            raise ValueError('tmpfs must leave approved RAM for processes and metadata')
        if self.tmpfs_bytes % 4096 or self.memory_bytes % 4096:
            raise ValueError('memory/storage budgets must be page aligned')


@dataclass(frozen=True)
class JobPlan:
    unit: str
    budget: ApprovedBudget

    def __post_init__(self):
        if not re.fullmatch(r'acceptance-[0-9a-f]{32}\.service', self.unit):
            raise ValueError('fresh acceptance-<32 lowercase hex>.service required')
        if not isinstance(self.budget, ApprovedBudget):
            raise ValueError('explicit immutable approved budget required')

    @property
    def workspace(self):
        return '/run/' + self.unit[:-8]

    @property
    def cgroup(self):
        return '/system.slice/' + self.unit


def launcher_argv(plan: JobPlan, command: tuple[str, ...]) -> tuple[str, ...]:
    """Construct only. systemd StartTransientUnit fails if the name exists.

    Use assert_unit_absent before launching; the manager supplies the atomic
    no-replace check. The child MUST call prepare_owned_job before any daemon.
    """
    if not command or not command[0].startswith('/') or any('\x00' in x for x in command):
        raise ValueError('absolute executable and NUL-free argv required')
    b, io = plan.budget, plan.budget.io
    properties = (
        'Type=exec', 'Slice=system.slice', 'User=root', 'Group=root',
        'CPUQuota=' + str(b.cpu_quota_percent) + '%', 'CPUQuotaPeriodSec=100ms',
        'MemoryMax=' + str(b.memory_bytes), 'MemorySwapMax=' + str(b.swap_bytes),
        'TasksMax=' + str(b.tasks), 'RuntimeMaxSec=' + str(b.runtime_seconds) + 's',
        'TimeoutStopSec=' + str(b.stop_seconds) + 's', 'KillMode=control-group',
        'SendSIGKILL=yes', 'OOMPolicy=kill', 'Delegate=yes', 'DevicePolicy=closed',
        # PrivateDevices=yes removes CAP_MKNOD in systemd 249 and breaks runc.
        # prepare_owned_job builds a private, bounded /dev instead.
        'PrivateDevices=no', 'PrivateMounts=yes', 'ProtectControlGroups=no',
        'ProtectSystem=strict', 'ReadWritePaths=' + plan.workspace + ' /sys/fs/cgroup' + plan.cgroup,
        'InaccessiblePaths=-/run/docker.sock -/run/containerd -/etc/docker -/etc/containerd -/etc/cdi -/run/cdi',
        'RuntimeDirectory=' + plan.unit[:-8], 'RuntimeDirectoryMode=0700',
        'RuntimeDirectoryPreserve=no', 'UMask=0077',
        'IOReadBandwidthMax=' + io.device + ' ' + str(io.read_bps),
        'IOWriteBandwidthMax=' + io.device + ' ' + str(io.write_bps),
        'IOReadIOPSMax=' + io.device + ' ' + str(io.read_iops),
        'IOWriteIOPSMax=' + io.device + ' ' + str(io.write_iops),
    )
    return ('systemd-run', '--system', '--no-ask-password', '--quiet', '--wait', '--pipe', '--collect',
            '--unit=' + plan.unit) + tuple('--property=' + p for p in properties) + ('--',) + tuple(command)


Budget = ApprovedBudget
systemd_run_argv = launcher_argv


def assert_unit_absent(plan: JobPlan, *, ops=None) -> None:
    """OUTER read-only check. StartTransientUnit(mode=fail) closes the race.

    Call with a freshly generated UUID unit name; do not retry/reuse a collected
    name. This API does not start anything or mutate manager configuration.
    """
    ops = LinuxOps() if ops is None else ops
    loaded = ops.run((
        'systemctl', 'list-units', '--all', '--full',
        '--no-legend', '--no-pager', '--', plan.unit,
    ))
    _need(not loaded.strip(), 'unit name already loaded')

    # list-unit-files <unknown-name> exits with code 1, which is expected for
    # a fresh UUID. Enumerate installed units and compare the unit-name column.
    installed = ops.run((
        'systemctl', 'list-unit-files', '--all', '--full',
        '--no-legend', '--no-pager',
    ))
    _need(
        not any(
            row.split() and row.split()[0] == plan.unit
            for row in installed.splitlines()
        ),
        'unit name already installed',
    )


# Diagnostic limits, not workload resource defaults.
_READ_LIMIT = 262144
_DIAGNOSTIC_SECONDS = 10


class Rejected(RuntimeError):
    """Required isolation evidence is absent, contradictory, or unsupported."""


def _need(condition, message):
    if not condition:
        raise Rejected(message)


@dataclass(frozen=True)
class OwnedJob:
    invocation_id: str
    cgroup_path: str
    cgroup_identity: tuple[int, int]
    workspace_identity: tuple[int, int]
    main_pid: int


class LinuxOps:
    """Real Linux adapter. Construction is read-only; mutations are explicit.

    Tests supply a wholly synthetic adapter, not this class. Commands use a
    fixed PATH, closed environment, no shell/preexec, a deadline and output cap.
    """
    def __init__(self):
        import os
        import sys
        _need(sys.platform == 'linux', 'Linux required')
        self.pid, self.uid = os.getpid(), os.geteuid()
        self.invocation_id = os.environ.get('INVOCATION_ID', '')

    def read(self, path):
        import errno
        import os
        import stat

        flags = os.O_RDONLY | os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as error:
            if path != '/etc/os-release' or error.errno != errno.ELOOP:
                raise
            # Ubuntu ships /etc/os-release as this canonical relative symlink.
            # Follow only that known target, then open it with O_NOFOLLOW too.
            target = os.readlink(path)
            if target not in ('../usr/lib/os-release', '/usr/lib/os-release'):
                raise Rejected('unsupported /etc/os-release symlink target') from None
            fd = os.open('/usr/lib/os-release', flags)
        try:
            if path == '/etc/os-release':
                _need(stat.S_ISREG(os.fstat(fd).st_mode), 'OS release file must be regular')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(_READ_LIMIT + 1)
        finally:
            os.close(fd)
        _need(len(data) <= _READ_LIMIT, 'readback exceeds diagnostic bound')
        return data.decode('utf-8', 'strict')

    def visible_mount_id(self, path):
        """Resolve the accessible mount, never a covered mountinfo lookalike.

        fdinfo is read through the bounded no-follow reader while the O_PATH
        descriptor stays open. Only our numeric descriptor enters the proc path.
        """
        import os
        fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            text = self.read('/proc/self/fdinfo/' + str(fd))
            rows = [line for line in text.splitlines() if line.startswith('mnt_id:')]
            _need(len(rows) == 1, 'missing or ambiguous fdinfo mount ID')
            match = re.fullmatch(r'mnt_id:\s*([1-9][0-9]*)', rows[0])
            _need(match is not None, 'invalid fdinfo mount ID')
            return match[1]
        finally:
            os.close(fd)

    def mkdir(self, path):
        import os
        os.mkdir(path, 0o700)

    def write(self, path, value, *, create=False):
        import os
        flags = os.O_WRONLY | os.O_NOFOLLOW
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        with open(os.open(path, flags, 0o600), 'w', closefd=True) as stream:
            stream.write(value)

    def statvfs(self, path):
        import os
        return os.statvfs(path)

    def mknod(self, path, major, minor):
        import os
        import stat
        os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(major, minor))

    def symlink(self, target, path):
        import os
        os.symlink(target, path)

    def device_numbers(self, observed):
        import os
        return os.major(observed.st_rdev), os.minor(observed.st_rdev)

    def namespace(self, who, kind):
        import os
        return os.readlink('/proc/' + who + '/ns/' + kind)

    def stat(self, path):
        import os
        return os.lstat(path)

    def listdir(self, path):
        import os
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                names.append(entry.name)
                _need(len(names) <= 4096, 'directory exceeds diagnostic bound')
        return tuple(names)

    def run(self, argv):
        import os
        import selectors
        import subprocess
        import time
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
               'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'}
        with subprocess.Popen(tuple(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, env=env, shell=False) as child:
            output = bytearray()
            end = time.monotonic() + _DIAGNOSTIC_SECONDS
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    while True:
                        left = end - time.monotonic()
                        _need(left > 0, 'diagnostic command deadline exceeded')
                        if not selector.select(left):
                            raise Rejected('diagnostic command deadline exceeded')
                        part = os.read(child.stdout.fileno(), 16384)
                        if not part:
                            break
                        output.extend(part)
                        _need(len(output) <= _READ_LIMIT, 'diagnostic command output exceeded bound')
                rc = child.wait(timeout=max(0.001, end - time.monotonic()))
                _need(rc == 0, 'diagnostic command failed: ' + argv[0])
                return output.decode('utf-8', 'strict')
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()


def _identity(st):
    return st.st_dev, st.st_ino


def _secure_directory(ops, path):
    import stat
    from pathlib import PurePosixPath
    current = ''
    for part in PurePosixPath(path).parts[1:]:
        current += '/' + part
        observed = ops.stat(current)
        _need(stat.S_ISDIR(observed.st_mode) and observed.st_uid == 0 and
              observed.st_mode & 0o022 == 0, 'unsafe root-owned directory: ' + current)
    return ops.stat(path)


def _duration_us(text):
    # systemctl show prints human-readable timespans even for *USec properties.
    factors = {'us': 1, 'ms': 1000, 's': 1000000, 'min': 60000000, 'h': 3600000000}
    parts = text.split()
    _need(bool(parts), 'missing duration')
    total = 0
    from decimal import Decimal
    for part in parts:
        match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(us|ms|s|min|h)', part)
        _need(match is not None, 'unsupported duration: ' + text)
        total += Decimal(match[1]) * factors[match[2]]
    return total


def _expected_properties(plan):
    b, io = plan.budget, plan.budget.io
    values = dict(Id=plan.unit, LoadState='loaded', ActiveState='active', SubState='running',
                  Transient='yes', ControlGroup=plan.cgroup, Delegate='yes',
                  DevicePolicy='closed', PrivateDevices='no',
                  PrivateMounts='yes', PrivateNetwork='no', ProtectSystem='strict',
                  ReadWritePaths=plan.workspace + ' /sys/fs/cgroup' + plan.cgroup,
                  KillMode='control-group',
                  OOMPolicy='kill', SendSIGKILL='yes', MemoryMax=str(b.memory_bytes),
                  MemorySwapMax=str(b.swap_bytes), TasksMax=str(b.tasks), User='root', Group='root',
                  RuntimeDirectory=plan.unit[:-8], RuntimeDirectoryMode='0700', RuntimeDirectoryPreserve='no')
    for name, value in (('IOReadBandwidthMax', io.read_bps), ('IOWriteBandwidthMax', io.write_bps),
                        ('IOReadIOPSMax', io.read_iops), ('IOWriteIOPSMax', io.write_iops)):
        values[name] = io.device + ' ' + str(value)
    return values


def _verify_device_allow_empty(plan, ops):
    """Read DeviceAllow as its typed D-Bus array; systemctl cannot print a(ss)."""
    import shlex

    # systemd 249 exposes DeviceAllow as a(ss). Query the Service interface
    # directly so a missing/unprintable `systemctl show` line is never treated
    # as an empty allow-list.
    object_path = ('/org/freedesktop/systemd1/unit/' +
                   plan.unit.replace('-', '_2d').replace('.', '_2e'))
    text = ops.run((
        'busctl', '--system', 'get-property', 'org.freedesktop.systemd1',
        object_path, 'org.freedesktop.systemd1.Service', 'DeviceAllow',
    ))
    try:
        parts = shlex.split(text)
    except ValueError:
        raise Rejected('malformed DeviceAllow D-Bus readback') from None
    _need(len(parts) >= 2 and parts[0] == 'a(ss)' and
          re.fullmatch(r'(?:0|[1-9][0-9]*)', parts[1]) is not None,
          'missing or malformed DeviceAllow D-Bus property')
    count = int(parts[1])
    _need(count <= 4096 and len(parts) == 2 + count * 2,
          'malformed DeviceAllow D-Bus entry list')
    _need(count == 0,
          'DeviceAllow explicit entry count mismatch: expected 0, actual ' + str(count))
    return ''


def _unit_properties(plan, ops, *, main_pid=None):
    names = tuple(_expected_properties(plan)) + ('MainPID', 'InvocationID', 'RuntimeMaxUSec',
             'TimeoutStopUSec', 'CPUQuotaPerSecUSec', 'CPUQuotaPeriodUSec')
    text = ops.run(('systemctl', 'show', '--no-pager', '--all', '--property=' + ','.join(names), '--', plan.unit))
    props = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        _need(bool(sep) and key not in props, 'ambiguous unit readback')
        props[key] = value
    for key, expected in _expected_properties(plan).items():
        _need(props.get(key) == expected, 'unit property mismatch: ' + key)
    props['DeviceAllow'] = _verify_device_allow_empty(plan, ops)
    b = plan.budget
    for key, expected in (('RuntimeMaxUSec', b.runtime_seconds * 1000000),
                          ('TimeoutStopUSec', b.stop_seconds * 1000000),
                          ('CPUQuotaPerSecUSec', b.cpu_quota_percent * 10000),
                          ('CPUQuotaPeriodUSec', 100000)):
        _need(_duration_us(props.get(key, '')) == expected, 'unit duration mismatch: ' + key)
    expected_pid = ops.pid if main_pid is None else main_pid
    _need(type(expected_pid) is int and expected_pid > 0 and
          props.get('MainPID') == str(expected_pid), 'transient MainPID identity mismatch')
    _need(re.fullmatch('[0-9a-f]{32}', ops.invocation_id) is not None and
          props.get('InvocationID') == ops.invocation_id, 'invocation identity mismatch')
    return props


def _mounts(ops):
    mounts = []
    for line in ops.read('/proc/self/mountinfo').splitlines():
        left, sep, right = line.partition(' - ')
        a, z = left.split(), right.split()
        _need(bool(sep) and len(a) >= 6 and len(z) >= 3, 'malformed mountinfo')
        mounts.append((a, z))
    return mounts


def _visible_mount(path, ops, *, mounts=None):
    mount_id = ops.visible_mount_id(path)
    _need(isinstance(mount_id, str) and re.fullmatch(r'[1-9][0-9]*', mount_id) is not None,
          'invalid visible mount ID')
    rows = [(a, z) for a, z in (_mounts(ops) if mounts is None else mounts)
            if a[0] == mount_id]
    _need(len(rows) == 1 and rows[0][0][4] == path,
          'visible mount identity missing or ambiguous: ' + path)
    return rows[0]


def _systemd_readwrite_workspace_mount(plan, ops, mounts, entry):
    """Prove the pre-existing mount is systemd's ReadWritePaths self-bind."""
    a, z = entry
    run_a, run_z = _visible_mount('/run', ops, mounts=mounts)
    run_options = set(run_a[5].split(','))
    run_super_options = set(run_z[2].split(','))
    mount_options = set(a[5].split(','))
    _need(
        run_a[3] == '/' and run_z[0] == 'tmpfs' and
        'rw' in run_options and 'rw' in run_super_options and
        a[1] == run_a[0] and a[2] == run_a[2] and
        a[3] == '/' + plan.unit[:-8] and a[4] == plan.workspace and
        mount_options == run_options and 'rw' in mount_options and 'ro' not in mount_options and
        z[0] == run_z[0] and z[1] == run_z[1] and z[2] == run_z[2],
        'workspace mount is not the expected systemd ReadWritePaths bind',
    )
    return a[0]


def _systemd_readwrite_workspace_mount_id(plan, ops, *, mounts=None):
    mounts = _mounts(ops) if mounts is None else mounts
    rows = [(a, z) for a, z in mounts if a[4] == plan.workspace]
    _need(len(rows) == 1, 'unexpected workspace mount stack before preparation')
    return _systemd_readwrite_workspace_mount(plan, ops, mounts, rows[0])


def _kernel_limits(plan, ops):
    cg, b, io = '/sys/fs/cgroup' + plan.cgroup, plan.budget, plan.budget.io
    _need(ops.read(cg + '/cpu.max').split() == [str(b.cpu_quota_percent * 1000), '100000'],
          'CPU quota not enforced')
    for name, expected in (('memory.max', b.memory_bytes), ('memory.swap.max', b.swap_bytes),
                            ('pids.max', b.tasks), ('memory.oom.group', 1)):
        _need(ops.read(cg + '/' + name).strip() == str(expected), 'kernel bound mismatch: ' + name)
    rows = ops.read(cg + '/io.max').splitlines()
    _need(len(rows) == 1, 'I/O device bounds ambiguous')
    values = rows[0].split()
    _need(values[0] == f'{io.major}:{io.minor}' and len(values) == 5, 'I/O device identity mismatch')
    _need(dict(x.split('=', 1) for x in values[1:]) ==
          dict(rbps=str(io.read_bps), wbps=str(io.write_bps), riops=str(io.read_iops), wiops=str(io.write_iops)),
          'I/O kernel bounds mismatch')


def _device_proof(plan, ops):
    import json
    records = json.loads(ops.run(('bpftool', '-j', 'cgroup', 'show', '/sys/fs/cgroup' + plan.cgroup)))
    # Direct attachment, not an unrelated ancestor's permissive program.
    _need(isinstance(records, list) and any(isinstance(r, dict) and
          r.get('attach_type') == 'device' and type(r.get('id')) is int and r['id'] > 0
          for r in records), 'no device BPF attached to exact owned unit')


def inspect_owned_job(plan: JobPlan, *, ops=None) -> OwnedJob:
    """Read-only child preflight. No daemon, mount, or controller writes.

    Missing bpftool is a blocker, not permission to trust configuration alone.
    Only the pinned Ubuntu 22.04/systemd 249/Linux 5.15/Docker 29 target is admitted.
    """
    import os
    import stat
    ops = LinuxOps() if ops is None else ops
    _need(ops.uid == 0, 'root-owned system job required')
    release = dict(line.split('=', 1) for line in ops.read('/etc/os-release').splitlines() if '=' in line)
    _need(release.get('ID') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '22.04',
          'unsupported OS target')
    _need(re.match(r'^5\.15\.', ops.read('/proc/sys/kernel/osrelease')), 'unsupported kernel target')
    _need(re.match(r'^systemd 249\b', ops.run(('systemd-run', '--version'))), 'systemd 249 required')
    _need(re.match(r'^Docker version 29\.', ops.run(('dockerd', '--version'))), 'Docker 29 required')
    _need(ops.namespace('self', 'mnt') != ops.namespace('1', 'mnt'), 'private mnt namespace required')
    _need(ops.namespace('self', 'cgroup') == ops.namespace('1', 'cgroup'), 'host cgroup namespace required for exact paths')
    _unit_properties(plan, ops)
    _need(ops.read('/proc/self/cgroup').strip() == '0::' + plan.cgroup, 'caller cgroup identity mismatch')
    cg = '/sys/fs/cgroup' + plan.cgroup
    cgstat = _secure_directory(ops, cg)
    mounts = [(a, z) for a, z in _mounts(ops) if a[4] == '/sys/fs/cgroup']
    _need(len(mounts) == 1 and mounts[0][0][3] == '/' and mounts[0][1][0] == 'cgroup2' and
          'rw' in mounts[0][0][5].split(','), 'full writable cgroup v2 mount required')
    _need(ops.read(cg + '/cgroup.type').strip() == 'domain', 'domain cgroup required')
    _need(set(ops.read(cg + '/cgroup.controllers').split()) >= {'cpu', 'io', 'memory', 'pids'}, 'required controller absent')
    _need(not ops.read(cg + '/cgroup.subtree_control').strip(), 'job subtree already configured')
    _need(ops.read(cg + '/cgroup.procs').split() == [str(ops.pid)], 'job must contain only its launcher')
    _need(not any(name in ('supervisor', 'containers') for name in ops.listdir(cg)), 'owned subtree already exists')
    _kernel_limits(plan, ops)
    observed = ops.stat(plan.budget.io.device)
    _need(stat.S_ISBLK(observed.st_mode) and ops.device_numbers(observed) ==
          (plan.budget.io.major, plan.budget.io.minor), 'approved block device identity mismatch')
    _device_proof(plan, ops)
    workspace = _secure_directory(ops, plan.workspace)
    _need(stat.S_IMODE(workspace.st_mode) == 0o700 and not ops.listdir(plan.workspace), 'workspace must be fresh private empty directory')
    mounts = _mounts(ops)
    _need(not any(a[4].startswith(plan.workspace + '/') for a, _ in mounts),
          'nested workspace mount present')
    _systemd_readwrite_workspace_mount_id(plan, ops, mounts=mounts)
    return OwnedJob(ops.invocation_id, cg, _identity(cgstat), _identity(workspace), ops.pid)


@dataclass(frozen=True)
class PreparedJob:
    owned: OwnedJob
    container_cgroup_parent: str
    workspace_identity: tuple[int, int]
    workspace_mount_id: str
    device_mount_id: str
    daemon_argv: tuple[str, ...]
    docker_prefix: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    mount_namespace: str
    tmp_mount_id: str
    var_tmp_mount_id: str
    devpts_mount_id: str


_SAFE_DEVICES = (('null', 1, 3), ('zero', 1, 5), ('full', 1, 7),
                 ('random', 1, 8), ('urandom', 1, 9), ('tty', 5, 0))


def _workspace_mount(plan, ops):
    mounts = _mounts(ops)
    _need(not any(field.startswith(('shared:', 'master:')) for a, _ in mounts for field in a[6:]),
          'mount propagation is not private')
    _need(not any(a[4].startswith(plan.workspace + '/') for a, _ in mounts),
          'nested workspace mount present')
    a, z = _visible_mount(plan.workspace, ops, mounts=mounts)
    workspace_rows = [(row_a, row_z) for row_a, row_z in mounts if row_a[4] == plan.workspace]
    _need(len(workspace_rows) == 2, 'unexpected workspace mount stack after preparation')
    underlay = [(row_a, row_z) for row_a, row_z in workspace_rows if row_a[0] != a[0]]
    _need(len(underlay) == 1, 'workspace bind underlay is missing or ambiguous')
    _systemd_readwrite_workspace_mount(plan, ops, mounts, underlay[0])
    _need(a[1] == underlay[0][0][0], 'bounded workspace tmpfs is not directly over the systemd bind')
    _need(a[3] == '/' and z[0] == 'tmpfs' and z[1] == plan.unit[:-8] and
          {'rw', 'nodev', 'nosuid'} <= set(a[5].split(',')), 'private tmpfs mount proof missing')
    vfs = ops.statvfs(plan.workspace)
    b = plan.budget
    _need(vfs.f_frsize * vfs.f_blocks == b.tmpfs_bytes and vfs.f_files == b.tmpfs_inodes,
          'tmpfs bytes/inodes differ from approved bounds')
    return a[0]


def _private_devices(plan, ops):
    import stat
    a, z = _visible_mount('/dev', ops)
    _need(z[0] == 'tmpfs' and z[1] == plan.unit[:-8] and a[3] == '/dev' and
          'nodev' not in a[5].split(',') and 'nosuid' in a[5].split(','), 'private /dev mount proof missing')
    _need(_identity(ops.stat('/dev')) == _identity(ops.stat(plan.workspace + '/dev')), '/dev escapes bounded tmpfs')
    expected = {name for name, _, _ in _SAFE_DEVICES} | {'fd', 'stdin', 'stdout', 'stderr', 'pts', 'ptmx', 'shm'}
    _need(set(ops.listdir('/dev')) == expected, 'unexpected device (including GPU) in private /dev')
    for name, major, minor in _SAFE_DEVICES:
        node = ops.stat('/dev/' + name)
        _need(stat.S_ISCHR(node.st_mode) and ops.device_numbers(node) == (major, minor), 'private device identity mismatch')
    return a[0]


def prepare_owned_job(plan: JobPlan, *, ops=None) -> PreparedJob:
    """CHILD ONLY: preflight, move self to leaf, delegate ONLY owned subtrees,
    then mount fresh bounded tmpfs and build private /dev/tmp and Docker config.

    Never starts dockerd. Failure is terminal: exit the child; systemd kills the
    complete unit and private mounts disappear. Do not retry partially prepared
    jobs, recursively remove cgroups, or attempt host-controller repair.
    Caller must use the returned argv/environment unchanged and verify live PIDs
    after launching dockerd/containerd and after each container launch. No host
    Docker config/socket/network publishing is used. Lab owns network/PID unshare.
    """
    import json
    ops = LinuxOps() if ops is None else ops
    owned = inspect_owned_job(plan, ops=ops)
    cg, root = owned.cgroup_path, plan.workspace
    systemd_workspace_mount_id = _systemd_readwrite_workspace_mount_id(plan, ops)
    _need(_identity(ops.stat(cg)) == owned.cgroup_identity and
          _identity(ops.stat(root)) == owned.workspace_identity, 'identity drift before mutation')
    ops.mkdir(cg + '/supervisor')
    ops.write(cg + '/supervisor/cgroup.procs', str(ops.pid))
    _need(not ops.read(cg + '/cgroup.procs').strip() and
          ops.read('/proc/self/cgroup').strip() == '0::' + plan.cgroup + '/supervisor', 'failed to move launcher into leaf')
    ops.write(cg + '/cgroup.subtree_control', '+cpu +io +memory +pids')
    _need(set(ops.read(cg + '/cgroup.subtree_control').split()) == {'cpu', 'io', 'memory', 'pids'}, 'owned controllers not enabled')
    ops.mkdir(cg + '/containers')
    _need(not ops.read(cg + '/containers/cgroup.procs').strip(), 'container parent must be empty')
    ops.write(cg + '/containers/cgroup.subtree_control', '+cpu +io +memory +pids')
    _need(set(ops.read(cg + '/containers/cgroup.subtree_control').split()) == {'cpu', 'io', 'memory', 'pids'}, 'nested controllers not enabled')
    ops.run(('mount', '--make-rprivate', '/'))
    _need(_systemd_readwrite_workspace_mount_id(plan, ops) == systemd_workspace_mount_id,
          'systemd workspace mount identity drift before tmpfs')
    b = plan.budget
    options = f'size={b.tmpfs_bytes},nr_inodes={b.tmpfs_inodes},mode=0700,uid=0,gid=0,nodev,nosuid'
    ops.run(('mount', '-t', 'tmpfs', '-o', options, plan.unit[:-8], root))
    mount_id = _workspace_mount(plan, ops)
    _need(not ops.listdir(root), 'new tmpfs not empty')
    for name in ('dev', 'tmp', 'data', 'exec', 'client', 'home', 'cdi'):
        ops.mkdir(root + '/' + name)
    for name in ('pts', 'shm'):
        ops.mkdir(root + '/dev/' + name)
    for name, major, minor in _SAFE_DEVICES:
        ops.mknod(root + '/dev/' + name, major, minor)
    for name, target in (('fd', '/proc/self/fd'), ('stdin', '/proc/self/fd/0'),
                         ('stdout', '/proc/self/fd/1'), ('stderr', '/proc/self/fd/2'), ('ptmx', 'pts/ptmx')):
        ops.symlink(target, root + '/dev/' + name)
    ops.run(('mount', '--bind', root + '/dev', '/dev'))
    ops.run(('mount', '-o', 'remount,bind,rw,dev,nosuid', '/dev'))
    ops.run(('mount', '-t', 'devpts', '-o', f'newinstance,ptmxmode=0666,mode=0620,max={b.tasks}', 'devpts', '/dev/pts'))
    for target in ('/tmp', '/var/tmp'):
        ops.run(('mount', '--bind', root + '/tmp', target))
    dev_mount_id = _private_devices(plan, ops)
    config = {'features': {'containerd-snapshotter': False, 'cdi': False},
              'log-driver': 'none', 'live-restore': False}
    ops.write(root + '/daemon.json', json.dumps(config, sort_keys=True) + '\n', create=True)
    ops.write(root + '/client/config.json', '{}\n', create=True)
    daemon = ('dockerd', '--config-file=' + root + '/daemon.json', '--data-root=' + root + '/data',
              '--exec-root=' + root + '/exec', '--pidfile=' + root + '/dockerd.pid',
              '--host=unix://' + root + '/docker.sock', '--storage-driver=vfs',
              '--exec-opt=native.cgroupdriver=cgroupfs', '--cgroup-parent=' + plan.cgroup + '/containers',
              '--default-cgroupns-mode=private', '--containerd-namespace=' + plan.unit[:-8],
              '--containerd-plugins-namespace=' + plan.unit[:-8] + '-plugins',
              '--bridge=none', '--iptables=false', '--ip6tables=false', '--ip-forward=false', '--ip-masq=false',
              '--userland-proxy=false')
    environment = tuple(sorted({'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
                                'HOME': root + '/home', 'TMPDIR': root + '/tmp',
                                'XDG_CONFIG_HOME': root + '/home', 'XDG_RUNTIME_DIR': root + '/exec'}.items()))
    ready = PreparedJob(owned, plan.cgroup + '/containers', _identity(ops.stat(root)), mount_id,
                        dev_mount_id, daemon,
                        ('docker', '--config', root + '/client', '--host', 'unix://' + root + '/docker.sock'),
                        environment, ops.namespace('self', 'mnt'),
                        _visible_mount('/tmp', ops)[0][0],
                        _visible_mount('/var/tmp', ops)[0][0],
                        _visible_mount('/dev/pts', ops)[0][0])
    verify_prepared_job(plan, ready, pids=(ops.pid,), ops=ops)
    # Docker validates its real configuration/flags without starting the daemon.
    ops.run(daemon + ('--validate',))
    return ready


def rebind_prepared_namespace(plan: JobPlan, prepared: PreparedJob, *,
                              parent_mnt_namespace, ops=None) -> PreparedJob:
    """Read-only re-proof after a validated inherited namespace transition.

    The caller MUST first validate the complete inherited typed net/mnt/PID FD
    set (Lab constructor), then pass readlink of that bound parent-mount FD,
    never a pathname guess or the current namespace. Call before resource_check.
    Only namespace-local mount IDs change; immutable backing/ownership and all
    kernel/device/tmpfs checks are independently verified before returning.
    """
    from dataclasses import replace
    ops = LinuxOps() if ops is None else ops
    _need(isinstance(parent_mnt_namespace, str) and
          re.fullmatch(r'mnt:\[[1-9][0-9]*\]', parent_mnt_namespace) is not None and
          parent_mnt_namespace == prepared.mount_namespace,
          'bound parent mount namespace mismatch')
    current = ops.namespace('self', 'mnt')
    _need(isinstance(current, str) and re.fullmatch(r'mnt:\[[1-9][0-9]*\]', current) is not None and
          current != parent_mnt_namespace, 'new child mount namespace required')
    rebound = replace(prepared, mount_namespace=current,
                      workspace_mount_id=_workspace_mount(plan, ops),
                      device_mount_id=_private_devices(plan, ops),
                      tmp_mount_id=_visible_mount('/tmp', ops)[0][0],
                      var_tmp_mount_id=_visible_mount('/var/tmp', ops)[0][0],
                      devpts_mount_id=_visible_mount('/dev/pts', ops)[0][0])
    verify_prepared_job(plan, rebound, pids=(ops.pid,), ops=ops)
    return rebound


def verify_prepared_job(plan: JobPlan, prepared: PreparedJob, *, pids=(), container_pids=(), ops=None) -> None:
    """Read back limits, identities, mounts and explicit live descendant PIDs.

    Supply dockerd, managed containerd and each container's host PID. The parent
    must additionally compare daemon info CgroupDriver/Driver/DockerRootDir and
    container HostConfig.CgroupParent against this independent prepared object.
    The manager MainPID must still match the one captured before PID unshare;
    the current child independently proves its own /proc/self/cgroup below.
    This function does not invent daemon/container readiness evidence.
    """
    ops = LinuxOps() if ops is None else ops
    _need(ops.namespace('self', 'mnt') == prepared.mount_namespace,
          'prepared mount namespace drift')
    _unit_properties(plan, ops, main_pid=prepared.owned.main_pid)
    _need(prepared.owned.invocation_id == ops.invocation_id, 'prepared invocation drift')
    _need(prepared.owned.cgroup_path == '/sys/fs/cgroup' + plan.cgroup and
          _identity(ops.stat(prepared.owned.cgroup_path)) == prepared.owned.cgroup_identity, 'owned cgroup replaced')
    _kernel_limits(plan, ops)
    _device_proof(plan, ops)
    cg = prepared.owned.cgroup_path
    _need(not ops.read(cg + '/cgroup.procs').strip(), 'no-internal-process constraint violated')
    for suffix in ('', '/containers'):
        _need(set(ops.read(cg + suffix + '/cgroup.subtree_control').split()) == {'cpu', 'io', 'memory', 'pids'}, 'controller drift')
    _need(not ops.read(cg + '/containers/cgroup.procs').strip(), 'container parent populated')
    _need(ops.read('/proc/self/cgroup').strip() == '0::' + plan.cgroup + '/supervisor', 'supervisor escaped owned leaf')
    _need(prepared.container_cgroup_parent == plan.cgroup + '/containers', 'unexpected container cgroup parent')
    _need(_identity(ops.stat(plan.workspace)) == prepared.workspace_identity and
          _workspace_mount(plan, ops) == prepared.workspace_mount_id and
          _private_devices(plan, ops) == prepared.device_mount_id, 'private storage identity drift')
    mounts = _mounts(ops)
    for target in ('/tmp', '/var/tmp'):
        a, z = _visible_mount(target, ops, mounts=mounts)
        _need(a[0] == (prepared.tmp_mount_id if target == '/tmp' else prepared.var_tmp_mount_id),
              'temporary storage mount identity drift')
        _need(a[3] == '/tmp' and z[0] == 'tmpfs' and z[1] == plan.unit[:-8] and
              {'rw', 'nodev', 'nosuid'} <= set(a[5].split(',')), 'temporary storage bind escaped bounded tmpfs')
        _need(_identity(ops.stat(target)) == _identity(ops.stat(plan.workspace + '/tmp')), 'temporary directory identity mismatch')
    a, z = _visible_mount('/dev/pts', ops, mounts=mounts)
    _need(a[0] == prepared.devpts_mount_id, 'devpts mount identity drift')
    _need(z[0] == 'devpts' and
          'max=' + str(plan.budget.tasks) in z[2].split(','), 'devpts instance is not bounded')
    for pid, parent in tuple((pid, plan.cgroup) for pid in pids) + tuple((pid, prepared.container_cgroup_parent) for pid in container_pids):
        _need(type(pid) is int and pid > 0, 'invalid descendant PID')
        value = ops.read('/proc/' + str(pid) + '/cgroup').strip()
        _need(value.startswith('0::' + parent + '/') and len(value.splitlines()) == 1 and
              '..' not in value.split('/'), 'descendant escaped exact owned cgroup parent')
