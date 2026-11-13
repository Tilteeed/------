"""Real transient-unit -> bounded workspace -> private packet-lab wiring.

No import side effects. Internal Python entries are not public opt-in flags.
Caller approval is enforced by gpu_host_acceptance; trusted root is the boundary.
"""
import dataclasses
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from types import SimpleNamespace

from scripts import acceptance_busy_host as resources
from scripts import gpu_acceptance_receipts as receipts
from scripts import ollama_route_acceptance as route
from scripts import proxy_packet_acceptance as base
from scripts.ollama_route_linux import Lab

ROOT = Path(__file__).resolve().parents[1]


def _contract(check):
    if check not in receipts.CHECKS:
        raise ValueError('Unknown fixed packet check')
    return base if check in base.CHECKS else route


def _read_input():
    raw = sys.stdin.buffer.read(route.LIMIT + 1)
    if len(raw) > route.LIMIT:
        raise ValueError('Bounded private job input required')
    return route.strict_json(raw.decode('utf-8'))


def run_unit(config, check, run_id, unit, *, ops=None, enter=None):
    """Transient MainPID only: resource proof precedes any namespace lab/daemon."""
    from scripts.gpu_host_acceptance import parse_config
    config = parse_config(config)
    _contract(check)
    if re.fullmatch('[0-9a-f]{32}', run_id) is None:
        raise ValueError('Fresh packet run ID required')
    plan = resources.JobPlan(unit, resources.ApprovedBudget.from_mapping(config['budget']))
    prepared = resources.prepare_owned_job(plan, ops=ops)
    return (enter or _enter_private)(config, check, run_id, plan, prepared)


def unit_main(check, run_id, unit):
    """Fixed systemd child bootstrap; receives configuration on a private pipe."""
    try:
        text = run_unit(_read_input(), check, run_id, unit)
        print(text)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print('FAIL: bounded acceptance unit failed', file=sys.stderr)
        return 1


def _enter_private(config, check, run_id, plan, prepared):
    descriptors = {}
    try:
        for kind in ('net', 'mnt', 'pid'):
            descriptors[kind] = os.open('/proc/self/ns/' + kind, os.O_RDONLY)
        payload = dict(config=config, check=check, run_id=run_id, unit=plan.unit,
                       prepared=dataclasses.asdict(prepared))
        bootstrap = ('import sys;sys.path.insert(0,sys.argv[1]);'
                     'from scripts.gpu_acceptance_job import namespace_main;'
                     'raise SystemExit(namespace_main(sys.argv[2:]))')
        argv = ['unshare', '--mount', '--net', '--pid', '--fork', '--kill-child=SIGKILL',
                '--mount-proc', '--propagation', 'private', '--', sys.executable, '-c',
                bootstrap, str(ROOT), *(str(descriptors[k]) for k in ('net', 'mnt', 'pid'))]
        env = dict(prepared.environment, INVOCATION_ID=prepared.owned.invocation_id)
        return route.command(argv, input_text=json.dumps(payload, allow_nan=False),
            pass_fds=tuple(descriptors.values()), env=env,
            timeout=plan.budget.runtime_seconds, start_new_session=False)
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)


def _prepared(value):
    if type(value) is not dict or set(value) != {f.name for f in dataclasses.fields(resources.PreparedJob)}:
        raise ValueError('Exact prepared job record required')
    value = dict(value)
    owned = dict(value['owned'])
    for key in ('cgroup_identity', 'workspace_identity'):
        owned[key] = tuple(owned[key])
    value['owned'] = resources.OwnedJob(**owned)
    value['workspace_identity'] = tuple(value['workspace_identity'])
    for key in ('daemon_argv', 'docker_prefix'):
        value[key] = tuple(value[key])
    value['environment'] = tuple(tuple(row) for row in value['environment'])
    return resources.PreparedJob(**value)


class BoundedLabMixin(Lab):
    """Reuse actual packet matrices; override only resource/daemon transport hooks."""
    job_plan: resources.JobPlan
    prepared_job: resources.PreparedJob
    managed_containerd_pid: int | None

    def resource_check(self, *, container_pids=()):
        pids = [os.getpid()]
        if self.daemon is not None and self.daemon.poll() is None:
            pids.append(self.daemon.pid)
            if self.managed_containerd_pid is not None:
                pids.append(self.managed_containerd_pid)
        # After daemon exit, namespace exit and manager/cgroup absence are the
        # authoritative descendant teardown proof; stale PID numbers are not.
        resources.verify_prepared_job(self.job_plan, self.prepared_job,
            pids=tuple(pids), container_pids=container_pids)

    def prepare_runtime(self):
        # Do not mount a new /run over the already-bounded job workspace.
        self.resource_check()

    def daemon_workspace_valid(self, base):
        self.resource_check()
        return str(base) == self.job_plan.workspace

    def daemon_command(self, base):
        if not self.daemon_workspace_valid(base):
            raise ValueError('Daemon workspace escaped bounded job')
        return list(self.prepared_job.daemon_argv)

    def container_options(self):
        return ['--cgroup-parent', self.prepared_job.container_cgroup_parent]

    def run(self, argv, **kwargs):
        self.guard()
        self.resource_check()
        kwargs['env'] = dict(self.prepared_job.environment,
                             INVOCATION_ID=self.prepared_job.owned.invocation_id)
        return route.command(argv, **kwargs)

    def spawn(self, argv):
        self.guard()
        self.resource_check()
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, shell=False,
            env=dict(self.prepared_job.environment, INVOCATION_ID=self.prepared_job.owned.invocation_id))
        self.processes.append(process)
        return process

    def verify_daemon_ready(self):
        info = route.strict_json(self.dc(['info', '--format', '{{json .}}']))
        if (info.get('CgroupDriver') != 'cgroupfs' or info.get('CgroupVersion') != '2'
                or info.get('Driver') != 'vfs'
                or info.get('DockerRootDir') != self.job_plan.workspace + '/data'):
            raise RuntimeError('Private daemon driver/cgroup/storage readback failed')
        path = self.job_plan.workspace + '/exec/containerd/containerd.pid'
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, 32).decode('ascii').strip()
            if not raw.isdecimal() or int(raw) <= 0:
                raise ValueError('Exact managed containerd PID required')
        finally:
            os.close(fd)
        self.managed_containerd_pid = int(raw)
        self.resource_check()

    def verify_started_container(self, data):
        host = data.get('HostConfig', {})
        if (host.get('CgroupParent') != self.prepared_job.container_cgroup_parent
                or host.get('DeviceRequests') not in (None, [])):
            raise RuntimeError('Container resource/device configuration drift')
        self.resource_check(container_pids=(data['State']['Pid'],))


def namespace_main(fd_args):
    """Private bootstrap only; namespace FD and systemd/cgroup proofs are mandatory."""
    import signal
    def interrupted(signum, frame):
        raise RuntimeError('Private bounded check interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        payload = _read_input()
        if type(payload) is not dict or set(payload) != {'config', 'check', 'run_id', 'unit', 'prepared'}:
            raise ValueError('Invalid private job payload')
        from scripts.gpu_host_acceptance import parse_config
        from scripts import ollama_route_linux as transport
        from scripts.proxy_acceptance_linux import ProxyLab
        config = parse_config(payload['config'])
        check, run_id = payload['check'], payload['run_id']
        contract = _contract(check)
        plan = resources.JobPlan(payload['unit'], resources.ApprovedBudget.from_mapping(config['budget']))
        prepared = _prepared(payload['prepared'])
        if len(fd_args) != 3 or not all(x.isdecimal() for x in fd_args):
            raise ValueError('Complete private namespace descriptor bundle required')
        args = SimpleNamespace(**{'parent_' + k + 'ns_fd': int(v)
            for k, v in zip(('net', 'mnt', 'pid'), fd_args)}, lab_dir=plan.workspace,
            endpoint=config['site']['ollama_endpoint_ip'], interface=config['site']['egress_interface'],
            image_archive=config['image_archive'], probe_image=config['probe_image'], run_id=run_id)
        # Constructors validate all namespace identities before any mutation.
        parent = ProxyLab if contract is base else transport.Lab
        cls = type('BoundedPacketLab', (BoundedLabMixin, parent), {})
        packet_config = receipts.site_binding(config['site'], receipts.machine_id_sha256())[
            'base' if contract is base else 'route']
        lab = cls(args, packet_config, check == contract.CHECKS[1])
        # Namespace cloning changes mount IDs, but not the verified bounded
        # backing objects. Rebind once using the inherited, already-typed FD.
        prepared = resources.rebind_prepared_namespace(plan, prepared,
            parent_mnt_namespace=os.readlink('/proc/self/fd/' + str(args.parent_mntns_fd)))
        lab.job_plan, lab.prepared_job = plan, prepared
        lab.managed_containerd_pid = None
        report = None
        try:
            lab.resource_check()
            lab.setup()
            report = lab.exercise()
        finally:
            lab.cleanup()
        report['cleanup'] = True
        contract.validate_report(report, packet_config, check, run_id)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, subprocess.SubprocessError):
        print('FAIL: private bounded packet check failed', file=sys.stderr)
        return 1


class LinuxJobs:
    """Fixed four-check backend; manager-owned cleanup precedes receipt writes."""
    def __init__(self, config):
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ValueError('Linux root required for busy-host acceptance')
        # Do not trigger global module autoload merely to create a private lab.
        # Built-in components represented in /sys/module are also accepted.
        required = ('bridge', 'br_netfilter', 'nf_tables', 'nft_meta_bridge',
                    'nft_ct', 'nf_conntrack', 'nf_conntrack_bridge')
        if any(not (Path('/sys/module') / name).is_dir() for name in required):
            raise ValueError('Required kernel components must already be loaded; never modprobe here')
        from scripts.gpu_host_acceptance import secure_file
        # A privileged run must use a root-controlled release and input archive,
        # not the editable developer checkout. Nothing is copied or installed.
        secure_file(ROOT / 'scripts/gpu_host_acceptance.py')
        secure_file(ROOT / 'scripts/gpu_acceptance_job.py')
        archive = secure_file(config['image_archive'])
        approved = resources.ApprovedBudget.from_mapping(config['budget']).io
        device = Path('/sys/dev/block') / f'{os.major(archive.st_dev)}:{os.minor(archive.st_dev)}'
        if not device.exists():
            raise ValueError('Archive I/O backing device cannot be proved')
        device = device.resolve()
        if (device / 'partition').exists():
            device = device.parent
        actual = (device / 'dev').read_text(encoding='ascii').strip()
        if actual != f'{approved.major}:{approved.minor}' or any((device / 'slaves').iterdir()):
            raise ValueError('Archive must use the explicitly bounded non-stacked block device')
        self.config = config
        self.ops = resources.LinuxOps()
        self.caller_inode = str(os.stat('/proc/self/ns/net').st_ino)
        self.plans = []
        self.finished = []

    def run_check(self, check, binding, run_id):
        contract = _contract(check)
        plan = resources.JobPlan('acceptance-' + secrets.token_hex(16) + '.service',
                                resources.ApprovedBudget.from_mapping(self.config['budget']))
        resources.assert_unit_absent(plan, ops=self.ops)
        self.plans.append(plan)
        bootstrap = ('import sys;sys.path.insert(0,sys.argv[1]);'
                     'from scripts.gpu_acceptance_job import unit_main;'
                     'raise SystemExit(unit_main(*sys.argv[2:]))')
        child = (sys.executable, '-c', bootstrap, str(ROOT), check, run_id, plan.unit)
        output = route.command(resources.launcher_argv(plan, child),
            input_text=json.dumps(self.config, allow_nan=False),
            timeout=plan.budget.runtime_seconds + plan.budget.stop_seconds + 30,
            env=dict(receipts.READ_ENV))
        packet_config = binding['base' if contract is base else 'route']
        packet = contract.validate_report(route.strict_json(output), packet_config, check, run_id)
        if packet['caller_netns_inode'] != self.caller_inode:
            raise ValueError('Unit packet caller namespace drift')
        self._absent(plan)
        self.finished.append(check)
        return dict(check=check, binding=binding, run_id=run_id, cleanup=True, passed=True, evidence=packet)

    def _absent(self, plan):
        resources.assert_unit_absent(plan, ops=self.ops)
        if os.path.lexists('/sys/fs/cgroup' + plan.cgroup) or os.path.lexists(plan.workspace):
            raise RuntimeError('Owned unit resources remain; no receipt')

    def cleanup_verifier(self):
        # Fail closed rather than by-name stopping an unexpectedly replaced unit.
        # RuntimeMaxSec/TimeoutStopSec/KillMode bound even interrupted jobs.
        for plan in self.plans:
            self._absent(plan)
        complete = self.finished == list(receipts.CHECKS)
        return dict(complete=complete, resources_absent=True, checks=list(self.finished))
