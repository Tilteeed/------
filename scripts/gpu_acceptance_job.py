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
from scripts.ollama_route_linux import (
    CLEANUP_FAILURE_OPERATIONS, CLEANUP_FAILURE_REASONS,
    CLEANUP_LINK_SUBSTAGES, CLEANUP_LINK_TYPES, Lab,
)

ROOT = Path(__file__).resolve().parents[1]
_FAILURE_PREFIX = 'BEZR_ACCEPTANCE_DIAGNOSTIC '
_FAILURE_STAGES = frozenset((
    'unit_input', 'configuration', 'check_contract', 'run_id',
    'systemd_cgroup_preparation', 'namespace_entry', 'namespace_payload',
    'namespace_configuration', 'namespace_contract', 'namespace_descriptors',
    'namespace_rebind', 'namespace_validation', 'resource_verification',
    'network_setup', 'docker_setup', 'packet_check', 'cleanup',
    'report_validation', 'systemd_preflight', 'systemd_launch',
    'systemd_unit', 'report_readback', 'cleanup_verification',
    'host_preflight',
))
_RULESET_DIAGNOSTIC_FIELDS = frozenset((
    'tables', 'semantics_validated', 'table', 'chains', 'rules', 'family', 'name',
    'comment', 'type', 'hook', 'prio', 'policy', 'chain', 'expr', 'match', 'left',
    'op', 'right', 'meta', 'key', 'payload', 'protocol', 'field', 'prefix',
    'accept', 'drop', 'reject', 'verdict', 'ct', 'state', 'mark', 'counter',
    'notrack', 'set', 'map', 'numgen', 'jhash', 'th', 'tcp', 'udp', 'icmp',
    'icmpv6', 'ether', 'other',
))
_RULESET_DIFFERENCES = frozenset((
    'missing_field', 'extra_field', 'type_mismatch', 'value_mismatch', 'order_mismatch',
))


def _valid_ruleset_diagnostic(value):
    if (type(value) is not dict
            or set(value) != {'family', 'section', 'chain', 'rule_index', 'field', 'difference'}
            or value['family'] not in ('inet', 'bridge')
            or value['section'] not in ('table', 'chains', 'rules')
            or (value['chain'] is not None and value['chain'] not in ('input', 'output', 'forward'))
            or type(value['difference']) is not str or value['difference'] not in _RULESET_DIFFERENCES
            or type(value['field']) is not str or not value['field'] or len(value['field']) > 160
            or any(ord(char) < 32 for char in value['field'])):
        return False
    rule_index = value['rule_index']
    if rule_index is not None and (type(rule_index) is not int or not 0 <= rule_index <= 65535):
        return False
    for component in value['field'].split('.'):
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)(?:\[(0|[1-9][0-9]{0,4})\])?', component)
        if (match is None or match[1] not in _RULESET_DIAGNOSTIC_FIELDS
                or (match[2] is not None and int(match[2]) > 65535)):
            return False
    return True


def _valid_cleanup_diagnostics(value):
    if type(value) is not list or not 1 <= len(value) <= 64:
        return False
    for item in value:
        if type(item) is not dict:
            return False
        base_fields = {'operation', 'exception', 'reason', 'errno'}
        link_fields = base_fields | {'substage', 'resource_type'}
        expected_fields = link_fields if item.get('operation') == 'delete_owned_link' else base_fields
        if (set(item) != expected_fields
                or type(item['operation']) is not str
                or item['operation'] not in CLEANUP_FAILURE_OPERATIONS
                or type(item['exception']) is not str
                or re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', item['exception']) is None
                or type(item['reason']) is not str
                or item['reason'] not in CLEANUP_FAILURE_REASONS):
            return False
        if expected_fields == link_fields and (
                type(item['substage']) is not str
                or item['substage'] not in CLEANUP_LINK_SUBSTAGES
                or type(item['resource_type']) is not str
                or item['resource_type'] not in CLEANUP_LINK_TYPES):
            return False
        errno_value = item['errno']
        if errno_value is not None and (type(errno_value) is not int or not 0 <= errno_value <= 65535):
            return False
    return True


def _safe_condition(error):
    """Return a bounded code-owned condition, never a traceback or process output."""
    if isinstance(error, resources.PreparationOperationFailure):
        return 'errno=' + (str(error.errno) if error.errno is not None else 'unknown')
    if isinstance(error, subprocess.TimeoutExpired):
        return 'Configured command deadline exceeded'
    if isinstance(error, UnicodeError):
        return 'Text encoding validation failed'
    if isinstance(error, json.JSONDecodeError):
        return 'Child report is not valid JSON'
    if isinstance(error, OSError):
        condition = error.strerror or type(error).__name__
    elif isinstance(error, (KeyError, TypeError)):
        condition = type(error).__name__ + ' while validating bounded acceptance data'
    elif isinstance(error, (ValueError, RuntimeError)):
        condition = str(error)
    else:
        condition = type(error).__name__ + ' during bounded acceptance'

    condition = ' '.join(condition.replace('\x00', ' ').split())
    condition = re.sub(
        r"""(?i)(access[_ -]?token|refresh[_ -]?token|password|passwd|passphrase|token|secret|api[_ -]?key|authorization|credential)["']?\s*[:=]\s*(?:'[^']*'|"[^"]*"|[^\s,;]+)""",
        r'\1=[redacted]', condition,
    )
    condition = re.sub(r'(?i)\bBearer\s+[^\s,;]+', 'Bearer [redacted]', condition)
    condition = re.sub(r'(?i)(https?://)[^/@\s:]+:[^/@\s]+@', r'\1[redacted]@', condition)
    return (condition or type(error).__name__)[:240]


def _diagnostic(stage, error, *, check=None):
    preparation_failure = isinstance(error, resources.PreparationOperationFailure)
    if preparation_failure:
        stage = 'systemd_cgroup_preparation'
    if stage not in _FAILURE_STAGES:
        stage = 'systemd_unit'
    result = {
        'stage': stage,
        'exception': error.exception_name if preparation_failure else type(error).__name__,
        'condition': _safe_condition(error),
    }
    if preparation_failure:
        result.update(substage=error.substage, operation=error.operation, errno=error.errno)
    ruleset_diff = getattr(error, 'ruleset_diff', None)
    if _valid_ruleset_diagnostic(ruleset_diff):
        result.update(ruleset_diff)
    cleanup_failures = getattr(error, 'cleanup_failures', None)
    if type(cleanup_failures) is tuple:
        cleanup_failures = list(cleanup_failures)
    if _valid_cleanup_diagnostics(cleanup_failures):
        result['cleanup_failures'] = cleanup_failures
    if check is not None:
        result['check'] = check
    return result


def _emit_diagnostic(stage, error):
    _emit_diagnostic_record(_diagnostic(stage, error))


def _emit_diagnostic_record(record):
    text = json.dumps(record, sort_keys=True, separators=(',', ':'))
    print(_FAILURE_PREFIX + text, file=sys.stderr, flush=True)


def _diagnostics_from_output(text):
    """Read only our bounded, structured failure records; ignore all raw output."""
    records = []
    base_keys = {'stage', 'exception', 'condition'}
    preparation_keys = base_keys | {'substage', 'operation', 'errno'}
    ruleset_keys = base_keys | {'family', 'section', 'chain', 'rule_index', 'field', 'difference'}
    cleanup_keys = base_keys | {'cleanup_failures'}
    for line in text.splitlines():
        if not line.startswith(_FAILURE_PREFIX):
            continue
        try:
            value = route.strict_json(line[len(_FAILURE_PREFIX):])
        except (TypeError, ValueError, RecursionError):
            continue
        if (type(value) is not dict or set(value) not in (
                    base_keys, preparation_keys, ruleset_keys, cleanup_keys)
                or type(value['stage']) is not str or value['stage'] not in _FAILURE_STAGES
                or type(value['exception']) is not str
                or re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', value['exception']) is None
                or type(value['condition']) is not str
                or not value['condition'] or len(value['condition']) > 240
                or any(ord(char) < 32 for char in value['condition'])):
            continue
        if set(value) == preparation_keys:
            diagnostic_errno = value['errno']
            condition = 'errno=' + (str(diagnostic_errno) if type(diagnostic_errno) is int else 'unknown')
            if (value['stage'] != 'systemd_cgroup_preparation'
                    or not resources.preparation_operation_allowed(value['substage'], value['operation'])
                    or (diagnostic_errno is not None and
                        (type(diagnostic_errno) is not int or diagnostic_errno < 0))
                    or value['condition'] != condition):
                continue
        elif set(value) == ruleset_keys:
            diff = {key: value[key] for key in ruleset_keys - base_keys}
            if (value['stage'] != 'packet_check'
                    or value['exception'] != 'ProxyRulesetMismatch'
                    or value['condition'] != 'Independent proxy canonical readback failed'
                    or not _valid_ruleset_diagnostic(diff)):
                continue
        elif set(value) == cleanup_keys:
            if (value['stage'] != 'cleanup'
                    or value['exception'] != 'CleanupFailure'
                    or value['condition'] != 'Disposable lab cleanup failed; no report/receipt'
                    or not _valid_cleanup_diagnostics(value['cleanup_failures'])):
                continue
        records.append(value)
    # The outer bootstrap may report that namespace entry failed after the
    # private process already emitted the more specific cause.
    specific = [item for item in records if item['stage'] != 'namespace_entry']
    return (specific or records)[:3]


def _contract(check):
    if check not in receipts.CHECKS:
        raise ValueError('Unknown fixed packet check')
    return base if check in base.CHECKS else route


def _read_input():
    raw = sys.stdin.buffer.read(route.LIMIT + 1)
    if len(raw) > route.LIMIT:
        raise ValueError('Bounded private job input required')
    return route.strict_json(raw.decode('utf-8'))


def run_unit(config, check, run_id, unit, *, ops=None, enter=None, on_stage=None):
    """Transient MainPID only: resource proof precedes any namespace lab/daemon."""
    from scripts.gpu_host_acceptance import parse_config
    def mark(stage):
        if on_stage is not None:
            on_stage(stage)

    mark('configuration')
    config = parse_config(config)
    mark('check_contract')
    _contract(check)
    mark('run_id')
    if re.fullmatch('[0-9a-f]{32}', run_id) is None:
        raise ValueError('Fresh packet run ID required')
    mark('systemd_cgroup_preparation')
    plan = resources.JobPlan(unit, resources.ApprovedBudget.from_mapping(config['budget']))
    prepared = resources.prepare_owned_job(plan, ops=ops)
    mark('namespace_entry')
    return (enter or _enter_private)(config, check, run_id, plan, prepared)


def unit_main(check, run_id, unit):
    """Fixed systemd child bootstrap; receives configuration on a private pipe."""
    stage = 'unit_input'
    def mark(next_stage):
        nonlocal stage
        stage = next_stage

    try:
        config = _read_input()
        text = run_unit(config, check, run_id, unit, on_stage=mark)
        print(text)
        return 0
    except Exception as error:
        _emit_diagnostic(stage, error)
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
        child_diagnostics = []

        def observe_failure(output, status):
            child_diagnostics.extend(_diagnostics_from_output(output))

        try:
            return route.command(argv, input_text=json.dumps(payload, allow_nan=False),
                pass_fds=tuple(descriptors.values()), env=env,
                timeout=plan.budget.runtime_seconds, start_new_session=False,
                on_failure=observe_failure)
        except Exception:
            # Preserve only our structured, secret-screened records from the
            # private process; never forward its arbitrary stdout/stderr.
            for record in child_diagnostics:
                _emit_diagnostic_record(record)
            raise
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
        previous_stage = getattr(self, '_acceptance_stage', 'resource_verification')
        self._acceptance_stage = 'resource_verification'
        pids = [os.getpid()]
        if self.daemon is not None and self.daemon.poll() is None:
            pids.append(self.daemon.pid)
            if self.managed_containerd_pid is not None:
                pids.append(self.managed_containerd_pid)
        # After daemon exit, namespace exit and manager/cgroup absence are the
        # authoritative descendant teardown proof; stale PID numbers are not.
        resources.verify_prepared_job(self.job_plan, self.prepared_job,
            pids=tuple(pids), container_pids=container_pids, unit_properties_via_dbus=True)
        self._acceptance_stage = previous_stage

    def prepare_runtime(self):
        # Do not mount a new /run over the already-bounded job workspace.
        self.resource_check()

    def setup_docker(self):
        self._acceptance_stage = 'docker_setup'
        return super().setup_docker()

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
    stage = 'namespace_payload'
    lab = None
    try:
        payload = _read_input()
        if type(payload) is not dict or set(payload) != {'config', 'check', 'run_id', 'unit', 'prepared'}:
            raise ValueError('Invalid private job payload')
        stage = 'namespace_configuration'
        from scripts.gpu_host_acceptance import parse_config
        from scripts import ollama_route_linux as transport
        from scripts.proxy_acceptance_linux import ProxyLab
        config = parse_config(payload['config'])
        check, run_id = payload['check'], payload['run_id']
        stage = 'namespace_contract'
        contract = _contract(check)
        plan = resources.JobPlan(payload['unit'], resources.ApprovedBudget.from_mapping(config['budget']))
        prepared = _prepared(payload['prepared'])
        stage = 'namespace_descriptors'
        if len(fd_args) != 3 or not all(x.isdecimal() for x in fd_args):
            raise ValueError('Complete private namespace descriptor bundle required')
        args = SimpleNamespace(**{'parent_' + k + 'ns_fd': int(v)
            for k, v in zip(('net', 'mnt', 'pid'), fd_args)}, lab_dir=plan.workspace,
            endpoint=config['site']['ollama_endpoint_ip'], interface=config['site']['egress_interface'],
            image_archive=config['image_archive'], probe_image=config['probe_image'], run_id=run_id)
        # Constructors validate all namespace identities before any mutation.
        parent = ProxyLab if contract is base else transport.Lab
        cls = type('BoundedPacketLab', (BoundedLabMixin, parent), {})
        stage = 'namespace_validation'
        packet_config = receipts.site_binding(config['site'], receipts.machine_id_sha256())[
            'base' if contract is base else 'route']
        lab = cls(args, packet_config, check == contract.CHECKS[1])
        # Namespace cloning changes mount IDs, but not the verified bounded
        # backing objects. Rebind once using the inherited, already-typed FD.
        stage = 'namespace_rebind'
        prepared = resources.rebind_prepared_namespace(plan, prepared,
            parent_mnt_namespace=os.readlink('/proc/self/fd/' + str(args.parent_mntns_fd)))
        lab.job_plan, lab.prepared_job = plan, prepared
        lab.managed_containerd_pid = None
        report = None
        operation_failure = None
        try:
            stage = 'resource_verification'
            lab._acceptance_stage = stage
            lab.resource_check()
            stage = 'docker_setup' if check == contract.CHECKS[1] else 'network_setup'
            lab._acceptance_stage = stage
            lab.setup()
            stage = 'packet_check'
            lab._acceptance_stage = stage
            report = lab.exercise()
        except Exception as error:
            operation_failure = (getattr(lab, '_acceptance_stage', stage), error)
        try:
            stage = 'cleanup'
            lab._acceptance_stage = stage
            lab.cleanup()
        except Exception as cleanup_error:
            if operation_failure is not None:
                _emit_diagnostic(*operation_failure)
            _emit_diagnostic('cleanup', cleanup_error)
            print('FAIL: private bounded packet check failed', file=sys.stderr)
            return 1
        if operation_failure is not None:
            stage, error = operation_failure
            lab._acceptance_stage = stage
            raise error
        stage = 'report_validation'
        lab._acceptance_stage = stage
        report['cleanup'] = True
        contract.validate_report(report, packet_config, check, run_id)
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as error:
        if lab is not None:
            stage = getattr(lab, '_acceptance_stage', stage)
        _emit_diagnostic(stage, error)
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
        self.diagnostics = []
        self.active_check = None

    def run_check(self, check, binding, run_id):
        stage = 'systemd_preflight'
        self.active_check = check
        child_diagnostics = []
        exit_status = []

        def observe_failure(output, status):
            child_diagnostics.extend(_diagnostics_from_output(output))
            exit_status.append(status)

        try:
            stage = 'check_contract'
            contract = _contract(check)
            stage = 'systemd_preflight'
            plan = resources.JobPlan('acceptance-' + secrets.token_hex(16) + '.service',
                                    resources.ApprovedBudget.from_mapping(self.config['budget']))
            resources.assert_unit_absent(plan, ops=self.ops)
            self.plans.append(plan)
            bootstrap = ('import sys;sys.path.insert(0,sys.argv[1]);'
                         'from scripts.gpu_acceptance_job import unit_main;'
                         'raise SystemExit(unit_main(*sys.argv[2:]))')
            child = (sys.executable, '-c', bootstrap, str(ROOT), check, run_id, plan.unit)
            stage = 'systemd_launch'
            output = route.command(resources.launcher_argv(plan, child),
                input_text=json.dumps(self.config, allow_nan=False),
                timeout=plan.budget.runtime_seconds + plan.budget.stop_seconds + 30,
                env=dict(receipts.READ_ENV), on_failure=observe_failure)
            stage = 'report_readback'
            packet_config = binding['base' if contract is base else 'route']
            packet = contract.validate_report(route.strict_json(output), packet_config, check, run_id)
            if packet['caller_netns_inode'] != self.caller_inode:
                raise ValueError('Unit packet caller namespace drift')
            stage = 'cleanup_verification'
            self._absent(plan)
            self.finished.append(check)
            self.active_check = None
            return dict(check=check, binding=binding, run_id=run_id,
                        cleanup=True, passed=True, evidence=packet)
        except Exception as error:
            if child_diagnostics:
                for item in child_diagnostics:
                    diagnostic = dict(item, check=check)
                    if exit_status:
                        diagnostic['systemd_exit_status'] = exit_status[0]
                    self.diagnostics.append(diagnostic)
            else:
                diagnostic = _diagnostic(stage, error, check=check)
                if exit_status:
                    diagnostic['systemd_exit_status'] = exit_status[0]
                self.diagnostics.append(diagnostic)
            raise

    def _absent(self, plan):
        resources.assert_unit_absent(plan, ops=self.ops)
        if os.path.lexists('/sys/fs/cgroup' + plan.cgroup) or os.path.lexists(plan.workspace):
            raise RuntimeError('Owned unit resources remain; no receipt')

    def cleanup_verifier(self):
        # Fail closed rather than by-name stopping an unexpectedly replaced unit.
        # RuntimeMaxSec/TimeoutStopSec/KillMode bound even interrupted jobs.
        try:
            for plan in self.plans:
                self._absent(plan)
        except Exception as error:
            self.diagnostics.append(_diagnostic(
                'cleanup_verification', error, check=self.active_check,
            ))
            raise
        complete = self.finished == list(receipts.CHECKS)
        proof = dict(complete=complete, resources_absent=True, checks=list(self.finished))
        return proof
