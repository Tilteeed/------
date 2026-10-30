"""Synthetic command output only; Linux host inspection is tested separately on VM."""
import json
import sys
import subprocess
import tempfile
from pathlib import Path
from dataclasses import asdict, replace
from contextlib import redirect_stdout
import io
from typing import Any, cast
import unittest
from unittest.mock import patch
from supervisor.config import validate_profile


def profile():
    return validate_profile({
        'schema_version': 1, 'profile_version': 'unit-storage-v1', 'mode': 'final',
        'storage': {'backend': 'xfs_project_quota', 'mountpoint': '/mnt/unit-data',
                    'expected_uuid': '11111111-2222-4333-8444-555555555555'},
        'agent_limits': {'ram_bytes': 1024, 'cpu_millicores': 1000,
                         'pids_limit': 256, 'disk_bytes': 4096},
    })


def mount_output(**changes):
    mount = dict(target='/mnt/unit-data', source='/dev/unit1', fstype='xfs', fsroot='/',
                 uuid=profile().storage.expected_uuid, options='rw,relatime,prjquota')
    return json.dumps({'filesystems': [mount | changes]})


QUOTA_OUTPUT = '''Project quota state on /mnt/unit-data (/dev/unit1)
  Accounting: ON
  Enforcement: ON
  Inode: #131 (2 blocks, 2 extents)
Blocks grace time: [7 days]
'''


class StoragePreflightTests(unittest.TestCase):
    def test_matching_backend_is_ready_but_instance_quota_stays_unverified(self):
        from supervisor.storage import inspect_storage
        calls = []

        def run(argv):
            calls.append(argv)
            return QUOTA_OUTPUT if argv[0] == 'xfs_quota' else mount_output()

        with patch('supervisor.storage.sys.platform', 'linux'):
            report = inspect_storage(profile(), run=run, realpath=lambda path: path)
        self.assertTrue(report.backend_ready)
        self.assertFalse(report.disk_quota_verified)
        self.assertEqual(report.errors, ())
        find = ['findmnt', '--json', '--mountpoint', '/mnt/unit-data',
                '--output', 'TARGET,SOURCE,FSTYPE,UUID,OPTIONS,FSROOT']
        self.assertEqual(calls, [find, ['xfs_quota', '-x', '-c', 'state -p', '/mnt/unit-data'], find])

    def test_wrong_or_ambiguous_mount_metadata_stops_before_quota_probe(self):
        from supervisor.storage import inspect_storage
        invalid = [mount_output(extra='PRIVATE_UNUSED_FIELD'), mount_output(source='/dev/unit1[/other]'), mount_output(fsroot='/subtree'),
                   mount_output(options='ro,prjquota'), mount_output(options='rw,pqnoenforce'),
                   mount_output(options='rw,notprjquota'), mount_output(options='rw,rw,prjquota'),
                   mount_output(options='rw,prjquota,noquota'), mount_output(target='/'),
                   mount_output(fstype='ext4'), mount_output(uuid='00000000-0000-0000-0000-000000000000'),
                   mount_output(uuid=1), mount_output(source='/dev/../etc'),
                   json.dumps({'filesystems': []}), json.dumps({'filesystems': [{}, {}]}),
                   '{"filesystems": [], "filesystems": []}', 'not JSON']
        for blob in invalid:
            calls = []

            def run(argv):
                calls.append(argv)
                return QUOTA_OUTPUT if argv[0] == 'xfs_quota' else blob

            with self.subTest(blob=blob), patch('supervisor.storage.sys.platform', 'linux'):
                report = inspect_storage(profile(), run=run, realpath=lambda path: path)
                self.assertFalse(report.backend_ready)
                self.assertFalse(report.disk_quota_verified)
                self.assertTrue(report.errors)
                self.assertEqual(len(calls), 1)

    def test_quota_state_must_be_unique_enabled_and_for_this_mount(self):
        from supervisor.storage import inspect_storage
        invalid = [QUOTA_OUTPUT.replace('Accounting: ON', 'Accounting: OFF'),
                   QUOTA_OUTPUT.replace('Enforcement: ON', 'Enforcement: OFF'),
                   QUOTA_OUTPUT.replace('/mnt/unit-data', '/mnt/other'),
                   QUOTA_OUTPUT.replace('/dev/unit1', '/dev/other'),
                   QUOTA_OUTPUT.replace('Project quota', 'User quota'),
                   QUOTA_OUTPUT + '  Accounting: OFF\n', QUOTA_OUTPUT + QUOTA_OUTPUT,
                   'Accounting: ON\nEnforcement: ON\n', 'not state', '']
        for quota in invalid:
            calls = []

            def run(argv):
                calls.append(argv)
                return quota if argv[0] == 'xfs_quota' else mount_output()

            with self.subTest(quota=quota), patch('supervisor.storage.sys.platform', 'linux'):
                report = inspect_storage(profile(), run=run, realpath=lambda path: path)
                self.assertFalse(report.backend_ready)
                self.assertFalse(report.disk_quota_verified)
                self.assertEqual(len(calls), 2)

    def test_symlinked_or_changed_target_is_not_accepted(self):
        from supervisor.storage import inspect_storage
        calls = []

        def run(argv):
            calls.append(argv)
            return QUOTA_OUTPUT if argv[0] == 'xfs_quota' else mount_output()

        with patch('supervisor.storage.sys.platform', 'linux'):
            report = inspect_storage(profile(), run=run, realpath=lambda path: '/mnt/other')
        self.assertFalse(report.backend_ready)
        self.assertEqual(calls, [])
        paths = iter(['/mnt/unit-data', '/mnt/other'])
        with patch('supervisor.storage.sys.platform', 'linux'):
            report = inspect_storage(profile(), run=run, realpath=lambda path: next(paths))
        self.assertFalse(report.backend_ready)
        self.assertEqual(len(calls), 3)


    def test_command_failures_are_blocked_without_raw_diagnostics(self):
        from supervisor.storage import inspect_storage
        from supervisor.probes import ProbeFailure
        failures = (OSError('PRIVATE_DIAGNOSTIC'), ProbeFailure('PRIVATE_DIAGNOSTIC'),
                    subprocess.TimeoutExpired(['PRIVATE_DIAGNOSTIC'], 1))
        for stage in (1, 2, 3):
            for error in failures:
                calls = []

                def run(argv):
                    calls.append(argv)
                    if len(calls) == stage:
                        raise error
                    return QUOTA_OUTPUT if argv[0] == 'xfs_quota' else mount_output()

                with self.subTest(stage=stage, error=type(error).__name__), patch('supervisor.storage.sys.platform', 'linux'):
                    report = inspect_storage(profile(), run=run, realpath=lambda path: path)
                    self.assertFalse(report.backend_ready)
                    self.assertNotIn('PRIVATE_DIAGNOSTIC', repr(report))


    def test_changed_mount_is_rejected_after_quota_state(self):
        from supervisor.storage import inspect_storage
        outputs = iter([mount_output(), QUOTA_OUTPUT, mount_output(source='/dev/other')])
        with patch('supervisor.storage.sys.platform', 'linux'):
            result = inspect_storage(profile(), run=lambda argv: next(outputs), realpath=lambda path: path)
        self.assertFalse(result.backend_ready)
        self.assertEqual(result.errors, ('mount_changed',))

    def test_unsupported_or_invalid_profile_does_not_reach_commands(self):
        from supervisor.storage import inspect_storage

        def forbidden(argv):
            self.fail('No commands allowed before platform/profile checks')

        with patch('supervisor.storage.sys.platform', 'win32'):
            self.assertEqual(inspect_storage(profile(), run=forbidden).errors, ('unsupported_platform',))
        invalid = replace(profile(), storage=replace(profile().storage, mountpoint='/'))
        for value in (None, invalid):
            with patch('supervisor.storage.sys.platform', 'linux'):
                self.assertEqual(inspect_storage(value, run=forbidden).errors, ('invalid_profile',))
        with patch('supervisor.storage.sys.platform', 'linux'):
            def missing(_path):
                raise FileNotFoundError('PRIVATE_MISSING')
            self.assertEqual(inspect_storage(profile(), run=forbidden, realpath=missing).errors, ('probe_failed',))

    def test_valid_uuid_case_and_quota_option_alias_do_not_change_expected_identity(self):
        from supervisor.storage import inspect_storage
        data = profile()
        upper = replace(data, storage=replace(data.storage,
                        expected_uuid='AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE'))

        def run(argv):
            return QUOTA_OUTPUT if argv[0] == 'xfs_quota' else mount_output(
                uuid=upper.storage.expected_uuid.lower(), options='rw,pquota')

        with patch('supervisor.storage.sys.platform', 'linux'):
            self.assertTrue(inspect_storage(upper, run=run, realpath=lambda path: path).backend_ready)
        self.assertEqual(upper.storage.expected_uuid, 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE')


class ProbeRunnerTests(unittest.TestCase):
    def test_real_subprocess_output_is_bounded_not_unlimited_capture(self):
        from supervisor.probes import run_command, ProbeFailure
        self.assertEqual(run_command([sys.executable, '-c', "print('unit-ok')"]).splitlines(), ['unit-ok'])
        with self.assertRaises(ProbeFailure) as caught:
            run_command([sys.executable, '-c', "import sys; sys.stdout.buffer.write(b'x' * 70000)"])
        self.assertEqual(caught.exception.code, 'output_limit')

    def test_invalid_limits_never_spawn_a_process(self):
        from supervisor.probes import run_command
        cases = ({'timeout': True}, {'timeout': 0}, {'timeout': float('nan')},
                 {'timeout': 11}, {'max_output_bytes': True}, {'max_output_bytes': -1},
                 {'max_output_bytes': 65537}, {'max_output_bytes': 1.0})
        with patch('supervisor.probes.subprocess.Popen', side_effect=AssertionError('spawned invalid probe')):
            for values in cases:
                with self.subTest(values=values), self.assertRaises(ValueError):
                    run_command(['unused'], **cast(Any, values))

    def test_real_failure_timeout_and_binary_output_are_sanitized(self):
        from supervisor.probes import run_command, ProbeFailure
        cases = [([sys.executable, '-c', "import sys; sys.stderr.write('PRIVATE_ERROR'); sys.exit(7)"], {}, 'command_failed'),
                 ([sys.executable, '-c', 'import time; time.sleep(2)'], {'timeout': 0.1}, 'command_timeout'),
                 ([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(bytes([255]))'], {}, 'invalid_output'),
                 (['unit-probe-does-not-exist-e35ca6'], {}, 'command_unavailable')]
        for argv, values, code in cases:
            with self.subTest(code=code), self.assertRaises(ProbeFailure) as caught:
                run_command(argv, **values)
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn('PRIVATE_ERROR', str(caught.exception))


class StorageCliTests(unittest.TestCase):
    def test_real_cli_is_blocked_without_backend_and_has_no_fixture_or_mutation_flags(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'PRIVATE_PROFILE_FILENAME.json'
            path.write_text(json.dumps(asdict(profile())), encoding='utf-8')
            command = [sys.executable, '-X', 'utf8', '-m', 'supervisor.storage', '--check', str(path)]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 2)
            report = json.loads(result.stdout)
            self.assertFalse(report['backend_ready'])
            self.assertFalse(report['disk_quota_verified'])
            self.assertTrue(report['errors'])
            if sys.platform != 'linux':
                self.assertEqual(report['errors'], ['unsupported_platform'])
            path.write_text('{PRIVATE_CONFIG_CONTENT', encoding='utf-8')
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)['errors'], ['invalid_profile'])
            self.assertNotIn('PRIVATE_', result.stdout + result.stderr)
            for flag in ('--fixture', '--device', '--mount', '--enable'):
                result = subprocess.run(command + [flag], cwd=root, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')


    def test_cli_success_wire_format_is_only_backend_readiness(self):
        from supervisor.storage import _main, StorageReport
        # Formatting-only stub, not evidence of actual Linux/XFS readiness.
        stream = io.StringIO()
        with patch('supervisor.storage.load_profile', return_value=profile()), \
             patch('supervisor.storage.inspect_storage', return_value=StorageReport(True, ())), \
             redirect_stdout(stream):
            code = _main(['--check', 'unused-synthetic-profile'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue()), {
            'status': 'backend_ready', 'backend_ready': True,
            'disk_quota_verified': False, 'errors': [],
        })


if __name__ == '__main__':
    unittest.main()
