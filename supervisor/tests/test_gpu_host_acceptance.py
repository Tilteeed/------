"""Connected CLI/config tests; synthetic job adapters are NOT Linux acceptance."""
import copy
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def profile() -> dict:
    return dict(schema_version=1,
        site=dict(agent_network_pool='10.80.0.0/16', frontend_network_pool='10.81.0.0/16',
                  ollama_network_pool='10.82.0.0/16', ollama_endpoint_ip='192.168.55.8',
                  egress_interface='synthetic0'),
        budget=dict(cpu_quota_percent=25, memory_bytes=268435456, swap_bytes=0,
                    tasks=64, runtime_seconds=60, stop_seconds=5, tmpfs_bytes=67108864,
                    tmpfs_inodes=1024, io=dict(device='/dev/vda', major=252, minor=0,
                        read_bps=1048576, write_bps=1048576, read_iops=100, write_iops=100)),
        probe_image='sha256:' + 'b' * 64, image_archive='/owned/probe.tar',
        production_docker_socket='/run/docker.sock', candidate_dir='/owned/new-candidate')


class ConfigAndCLITests(unittest.TestCase):
    def test_explicit_configuration_is_validated_without_host_operations(self):
        api = importlib.import_module('scripts.gpu_host_acceptance')
        original = profile()
        result = api.parse_config(original)
        self.assertEqual(result['site'], original['site'])
        self.assertEqual(original, profile())
        for malformed in ({}, dict(original, host_id_sha256='a' * 64),
                          dict(original, budget=None), dict(original, probe_image='latest'),
                          dict(original, candidate_dir='/'),
                          dict(original, production_docker_socket='tcp://remote:2375')):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                api.parse_config(malformed)
        invalid = copy.deepcopy(original)
        invalid['site']['ollama_endpoint_ip'] = '127.0.0.1'
        with self.assertRaises(ValueError):
            api.parse_config(invalid)

    def test_approved_cli_reaches_connected_orchestrator(self):
        api = importlib.import_module('scripts.gpu_host_acceptance')
        from unittest.mock import patch
        with patch.object(api.sys, 'platform', 'linux'), \
             patch.object(api.os, 'geteuid', return_value=0, create=True), \
             patch.object(api, 'read_config', return_value=profile()), \
             patch.object(api, 'execute_config', return_value={'status': 'complete'}) as execute:
            result = api.main(['--config', '/owned/site.json', '--execute',
                               '--approve-busy-host', '--allow-host-inspection'])
        self.assertEqual(result, 0)
        execute.assert_called_once_with(profile(), busy_host_approved=True, allow_host_inspection=True)

    def test_execute_refuses_platform_before_reading_any_profile(self):
        api = importlib.import_module('scripts.gpu_host_acceptance')
        from unittest.mock import patch
        with patch.object(api.sys, 'platform', 'win32'), patch.object(api, 'read_config') as reader:
            with self.assertRaises(SystemExit) as refused:
                api.main(['--config', 'missing', '--execute', '--approve-busy-host', '--allow-host-inspection'])
            self.assertEqual(refused.exception.code, 2)
            reader.assert_not_called()

    def test_real_cli_check_config_is_read_only_and_rejects_report_input(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-gpu-cli-') as directory:
            path = Path(directory) / 'profile.json'
            path.write_text(json.dumps(profile()), encoding='utf-8')
            child = subprocess.run([sys.executable, str(ROOT / 'scripts/gpu_host_acceptance.py'),
                                    '--config', str(path), '--check-config'],
                                   capture_output=True, text=True, timeout=10)
            self.assertEqual(child.returncode, 0, child.stderr)
            self.assertIn('no host operations', child.stdout)
            refused = subprocess.run([sys.executable, str(ROOT / 'scripts/gpu_host_acceptance.py'),
                                      '--config', str(path), '--report', str(path)],
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(refused.returncode, 2)


class ConnectedAcceptanceTests(unittest.TestCase):
    def test_real_report_validators_gate_both_candidate_writes(self):
        from unittest.mock import patch
        from supervisor.tests.test_gpu_acceptance_receipts import SyntheticStateSource, SyntheticCandidateStore
        from scripts import proxy_packet_acceptance as base
        from scripts import ollama_route_acceptance as route
        api = importlib.import_module('scripts.gpu_host_acceptance')

        class SyntheticJobs:
            def __init__(self):
                self.calls = []
                self.caller_inode = '11'
                self.corrupt = False

            def run_check(self, check, binding, run_id):
                self.calls.append(check)
                contract = base if check in base.CHECKS else route
                config = binding['base' if check in base.CHECKS else 'route']
                packet = contract.new_report(config, check, run_id, '11', '12')
                packet['cleanup'] = packet['policy_readback'] = packet['cold_neighbors'] = True
                if contract is route:
                    packet['topologies'] = [dict(route.topology_evidence(config, t),
                        policy_readback=True, cold_neighbors=True) for t in route.TOPOLOGIES]
                    probes = route.make_plan(config)[1]
                else:
                    probes = base.make_plan(config)[0]
                packet['probes'] = [dict(name=p['name'], spec=p, before=True,
                                        enforced=p['allow'], after=True) for p in probes]
                if self.corrupt:
                    packet['probes'][0]['before'] = False
                return dict(check=check, binding=binding, run_id=run_id,
                            cleanup=True, passed=True, evidence=packet)

            def cleanup_verifier(self):
                from scripts.gpu_acceptance_receipts import CHECKS
                return dict(complete=True, resources_absent=True, checks=list(CHECKS))

        for invalid in (False, True):
            jobs, source, store = SyntheticJobs(), SyntheticStateSource(), SyntheticCandidateStore()
            jobs.corrupt = invalid
            with self.subTest(invalid=invalid), patch('scripts.gpu_acceptance_receipts.machine_id_sha256', return_value='a' * 64):
                result = api.execute_config(profile(), jobs=jobs, source=source, store=store,
                                            busy_host_approved=True, allow_host_inspection=True)
            self.assertEqual(result['status'], 'incomplete' if invalid else 'complete')
            self.assertEqual(result['job_units'], [])
            if invalid:
                self.assertEqual(store.events, ['preflight'])
            else:
                self.assertEqual(len(jobs.calls), 4)
                self.assertEqual(store.events[-1], 'complete')


class JobBoundaryTests(unittest.TestCase):
    def test_preparation_diagnostic_exposes_only_fixed_step_and_errno(self):
        import contextlib
        import errno
        import io
        from unittest.mock import patch
        from supervisor.tests.test_acceptance_busy_host import fixture
        api = importlib.import_module('scripts.gpu_acceptance_job')
        _, plan, ops = fixture()
        ops.mknod = lambda path, major, minor: (_ for _ in ()).throw(
            PermissionError(errno.EACCES, 'Permission denied', '/private/secret/path'))
        with self.assertRaises(api.resources.PreparationOperationFailure) as caught:
            api.resources.prepare_owned_job(plan, ops=ops)

        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            api._emit_diagnostic('systemd_cgroup_preparation', caught.exception)
        line = output.getvalue()
        records = api._diagnostics_from_output(line)
        self.assertEqual(records, [{
            'stage': 'systemd_cgroup_preparation',
            'substage': 'device_creation',
            'operation': 'mknod_null',
            'exception': 'PermissionError',
            'errno': errno.EACCES,
            'condition': 'errno=13',
        }])
        self.assertNotIn('/private/secret/path', line)

        forged = dict(records[0], operation='../secret')
        self.assertEqual(api._diagnostics_from_output(
            api._FAILURE_PREFIX + json.dumps(forged)), [])

    def test_namespace_entry_rebinds_after_descriptor_validation_before_resources(self):
        """Synthetic transport ordering only; no packet/namespace execution."""
        import contextlib
        import io
        from dataclasses import asdict, replace
        from unittest.mock import patch
        from supervisor.tests.test_acceptance_busy_host import fixture
        api = importlib.import_module('scripts.gpu_acceptance_job')
        from scripts import proxy_packet_acceptance as contract
        _, plan, ops = fixture()
        plan = api.resources.JobPlan(plan.unit, api.resources.ApprovedBudget.from_mapping(asdict(plan.budget)))
        prepared = api.resources.prepare_owned_job(plan, ops=ops)
        child = replace(prepared, mount_namespace='mnt:[99001]')
        config = profile()
        config['budget'] = asdict(plan.budget)
        payload = dict(config=config, check=contract.CHECKS[0], run_id='d' * 32,
                       unit=plan.unit, prepared=asdict(prepared))
        for reject in (False, True):
            events = []
            class SyntheticLab:
                def __init__(self, args, packet_config, docker):
                    events.append('descriptor_validation')
                    self_args = (args.parent_netns_fd, args.parent_mntns_fd, args.parent_pidns_fd)
                    if self_args != (7, 8, 9) or reject:
                        raise RuntimeError('synthetic descriptor refusal')
                def setup(self):
                    events.append('setup')
                def exercise(self):
                    events.append('exercise')
                    return {'synthetic_transport_only': True}
                def cleanup(self):
                    events.append('cleanup')
            class SyntheticMixin:
                prepared_job: object
                def resource_check(lab):
                    events.append('resources')
                    self.assertIs(lab.prepared_job, child)
            def descriptor(path):
                events.append('parent_mount_descriptor')
                self.assertEqual(path, '/proc/self/fd/8')
                return prepared.mount_namespace
            def rebind(actual_plan, original, *, parent_mnt_namespace):
                events.append('rebind')
                self.assertEqual(actual_plan, plan)
                self.assertEqual(original, prepared)
                self.assertEqual(parent_mnt_namespace, prepared.mount_namespace)
                return child
            with self.subTest(reject=reject), \
                 patch.object(api, '_read_input', return_value=payload), \
                 patch.object(api, 'BoundedLabMixin', SyntheticMixin), \
                 patch('scripts.proxy_acceptance_linux.ProxyLab', SyntheticLab), \
                 patch.object(api.resources, 'rebind_prepared_namespace', side_effect=rebind), \
                 patch.object(api.receipts, 'machine_id_sha256', return_value='a' * 64), \
                 patch.object(api.os, 'readlink', side_effect=descriptor), \
                 patch('signal.signal'), patch.object(contract, 'validate_report'), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = api.namespace_main(['7', '8', '9'])
            self.assertEqual(status, 1 if reject else 0)
            self.assertEqual(events, ['descriptor_validation'] if reject else [
                'descriptor_validation', 'parent_mount_descriptor', 'rebind',
                'resources', 'setup', 'exercise', 'cleanup'])

    def test_finished_daemon_does_not_require_dead_containerd_pid_during_cleanup(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        api = importlib.import_module('scripts.gpu_acceptance_job')
        lab = object.__new__(api.BoundedLabMixin)
        lab.daemon = SimpleNamespace(poll=lambda: 0, pid=123)
        lab.managed_containerd_pid = 124
        lab.job_plan, lab.prepared_job = object(), object()
        with patch.object(api.resources, 'verify_prepared_job') as verify:
            lab.resource_check()
        self.assertEqual(verify.call_args.kwargs['pids'], (api.os.getpid(),))

    def test_resource_preparation_precedes_namespace_entry(self):
        from supervisor.tests.test_acceptance_busy_host import fixture
        api = importlib.import_module('scripts.gpu_acceptance_job')
        _, plan, ops = fixture()
        reached = []
        def synthetic_entry(config, check, run_id, actual_plan, prepared):
            reached.append(prepared.container_cgroup_parent)
            self.assertTrue(ops.writes)
            self.assertIn('--cgroup-parent=' + prepared.container_cgroup_parent, prepared.daemon_argv)
            raise RuntimeError('synthetic boundary reached')
        with self.assertRaisesRegex(RuntimeError, 'synthetic boundary reached'):
            api.run_unit(profile(), 'linux_proxy_isolated_check', 'd' * 32,
                         plan.unit, ops=ops, enter=synthetic_entry)
        self.assertEqual(reached, [plan.cgroup + '/containers'])


if __name__ == '__main__':
    unittest.main()
