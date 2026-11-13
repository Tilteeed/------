"""Synthetic portable activation tests; never host or packet acceptance evidence."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import proxy_packet_acceptance as contract

from scripts import activate_agent_proxy as activation


class SyntheticActivationTests(unittest.TestCase):
    def argv(self):
        return ['--agent-pool', '10.240.0.0/13', '--frontend-pool', '10.248.0.0/13',
                '--probe-image', 'sha256:' + 'a' * 64,
                '--execute', '--confirm-disposable-host']

    def invoke(self, mutate=None, *, host_values=None, caller_values=None, extra=(), raw_json=None):
        """Synthetic external child/identity boundaries; real report validator."""
        config = contract.binding('10.240.0.0/13', '10.248.0.0/13', 'a' * 64)
        calls = []
        original_stat = activation.os.stat
        callers = iter(caller_values or [10] * 10)

        def stat(path, *args, **kwargs):
            if str(path) == '/proc/self/ns/net':
                return SimpleNamespace(st_ino=next(callers))
            return original_stat(path, *args, **kwargs)

        def child(label, argv):
            index = len(calls)
            calls.append(argv)
            self.assertIn('--execute', argv)
            self.assertIn('--confirm-disposable-host', argv)
            run_id = argv[argv.index('--run-id') + 1]
            report = contract.new_report(config, contract.CHECKS[index], run_id, '10', '20')
            report.update(cleanup=True, cold_neighbors=True, policy_readback=True)
            report['probes'] = [dict(name=p['name'], spec=p, before=True,
                                    enforced=p['allow'], after=True)
                                for p in contract.make_plan(config)[0]]
            if mutate:
                mutate(report, index)
            return report

        def transport(argv, *, timeout):
            assert raw_json is not None
            self.assertEqual(timeout, 660)
            return raw_json(child('synthetic transport', argv))

        external = (patch.object(activation, '_run_check', side_effect=child) if raw_json is None
                    else patch.object(activation, 'command', side_effect=transport))
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / 'synthetic-image.tar'
            archive.write_bytes(b'synthetic archive; never loaded')
            argv = self.argv() + ['--image-archive', str(archive), *extra]
            with (patch.object(activation.sys, 'platform', 'linux'),
                  patch.object(activation.os, 'geteuid', return_value=0, create=True),
                  patch.object(activation.os, 'stat', side_effect=stat),
                  patch.object(activation, 'validate_acceptance_state_path'),
                  patch.object(activation, 'machine_id_sha256', side_effect=host_values or ['a' * 64] * 10),
                  external,
                  patch.object(activation, 'write_firewall_acceptance_receipt', return_value='synthetic-receipt') as write,
                  contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
                result = activation.main(argv)
            return result, calls, write, str(archive)

    def test_complete_reports_use_fresh_bound_child_argv_before_receipt(self):
        result, calls, write, archive = self.invoke()
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 2)
        for index, argv in enumerate(calls):
            self.assertEqual(argv[:2], [activation.sys.executable,
                             str(activation.ROOT / 'scripts' / (contract.CHECKS[index] + '.py'))])
            self.assertEqual(argv[argv.index('--agent-pool') + 1], '10.240.0.0/13')
            self.assertEqual(argv[argv.index('--frontend-pool') + 1], '10.248.0.0/13')
            self.assertNotIn('--confirm-busy-host', argv)
            self.assertNotIn('--skip-checks', argv)
            self.assertNotIn('--report', argv)
        self.assertNotIn('--image-archive', calls[0])
        self.assertEqual(calls[1][calls[1].index('--image-archive') + 1], archive)
        self.assertEqual(calls[1][calls[1].index('--probe-image') + 1], 'sha256:' + 'a' * 64)
        ids = [argv[argv.index('--run-id') + 1] for argv in calls]
        self.assertNotEqual(*ids)
        for run_id in ids:
            self.assertRegex(run_id, r'^[0-9a-f]{32}$')
        write.assert_called_once_with('/var/lib/personal-agent-supervisor', '10.240.0.0/13',
                                      '10.248.0.0/13', expected_host_id_sha256='a' * 64)

    def test_invalid_child_evidence_never_writes_receipt(self):
        mutations = {
            'empty': lambda r: r.clear(),
            'wrong-run': lambda r: r.update(run_id='0' * 32),
            'wrong-check': lambda r: r.update(check='not-this-check'),
            'wrong-profile': lambda r: r.update(profile='agent_ollama_v1'),
            'wrong-host': lambda r: r['binding'].update(host_id_sha256='b' * 64),
            'wrong-pool': lambda r: r['binding'].update(agent_network_pool='10.0.0.0/13'),
            'wrong-policy': lambda r: r.update(policy_sha256='0' * 64),
            'missing-cleanup': lambda r: r.update(cleanup=False),
            'integer-cleanup': lambda r: r.update(cleanup=1),
            'missing-readback': lambda r: r.update(policy_readback=False),
            'missing-cold-path': lambda r: r.update(cold_neighbors=False),
            'missing-probe': lambda r: r['probes'].pop(),
            'bad-control': lambda r: r['probes'][0].update(before=False),
            'bad-enforcement': lambda r: r['probes'][0].update(enforced=False),
            'same-namespace': lambda r: r.update(router_netns_inode='10'),
        }
        for index in (0, 1):
            for name, mutation in mutations.items():
                with self.subTest(check=index, mutation=name):
                    result, calls, write, _ = self.invoke(
                        lambda r, i: mutation(r) if i == index else None)
                    self.assertEqual(result, 1)
                    self.assertEqual(len(calls), index + 1)
                    write.assert_not_called()

    def test_valid_but_foreign_caller_report_is_rejected(self):
        for index in (0, 1):
            with self.subTest(check=index):
                result, calls, write, _ = self.invoke(
                    lambda r, i: r.update(caller_netns_inode='11') if i == index else None)
                self.assertEqual(result, 1)
                self.assertEqual(len(calls), index + 1)
                write.assert_not_called()

    def test_caller_namespace_drift_is_rejected_before_receipt(self):
        for readings, expected_checks in (([10, 11], 1), ([10, 10, 11], 2), ([10, 10, 10, 11], 2)):
            with self.subTest(readings=readings):
                result, calls, write, _ = self.invoke(caller_values=readings)
                self.assertEqual(result, 1)
                self.assertEqual(len(calls), expected_checks)
                write.assert_not_called()

    def test_host_drift_is_rejected_before_next_check_or_receipt(self):
        a, b = 'a' * 64, 'b' * 64
        for readings, expected_checks in (([a, b], 1), ([a, a, b], 2), ([a, a, a, b], 2)):
            with self.subTest(readings=readings):
                result, calls, write, _ = self.invoke(host_values=readings)
                self.assertEqual(result, 1)
                self.assertEqual(len(calls), expected_checks)
                write.assert_not_called()

    def test_synthetic_child_json_is_consumed_instead_of_exit_status_only(self):
        result = activation._run_check('synthetic Python child',
                                       [activation.sys.executable, '-c', 'print(\'{"synthetic":true}\')'])
        self.assertEqual(result, {'synthetic': True})

    def test_synthetic_child_malformed_json_is_rejected(self):
        for output in ('', 'PASS', '{}\n{}', '{"x":1,"x":2}', '{"x":NaN}', '[' * 2000):
            with self.subTest(output=output[:30]):
                with self.assertRaises((RuntimeError, ValueError)):
                    activation._run_check('synthetic Python child',
                        [activation.sys.executable, '-c', 'print(' + repr(output) + ')'])

    def test_synthetic_child_output_is_bounded_and_failures_rejected(self):
        for script in ('import json; print(json.dumps({"synthetic": "x" * 262145}))',
                       'raise SystemExit(1)'):
            with self.subTest(script=script), self.assertRaises(RuntimeError):
                activation._run_check('synthetic Python child',
                                       [activation.sys.executable, '-c', script])

    def test_archive_must_be_an_existing_absolute_regular_file_before_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            for archive in ('relative.tar', '', str(Path(temp) / 'missing.tar'), temp):
                with self.subTest(archive=archive):
                    result, calls, write, _ = self.invoke(extra=['--image-archive', archive])
                    self.assertEqual(result, 1)
                    self.assertEqual(calls, [])
                    write.assert_not_called()

    def test_raw_child_reports_are_parsed_and_validated_before_receipt(self):
        result, calls, write, _ = self.invoke(raw_json=json.dumps)
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 2)
        write.assert_called_once()
        for output in ('', 'PASS', '{}', 'null', '[]', '{"x":1,"x":2}'):
            with self.subTest(output=output):
                result, calls, write, _ = self.invoke(raw_json=lambda r: output)
                self.assertEqual(result, 1)
                self.assertEqual(len(calls), 1)
                write.assert_not_called()

    def test_activation_refuses_busy_host_report_skip_or_missing_approval(self):
        full = self.argv() + ['--image-archive', '/synthetic-image.tar']
        cases = [
            (full, 'win32', 0), (full, 'linux', 1000),
            ([x for x in full if x != '--execute'], 'linux', 0),
            ([x for x in full if x != '--confirm-disposable-host'], 'linux', 0),
        ]
        for flag in ('--confirm-busy-host', '--report', '--skip-checks', '--run-id'):
            cases.append((full + [flag], 'linux', 0))
        cases.append((full + ['--probe-image', 'python:latest'], 'linux', 0))
        for argv, platform, euid in cases:
            with self.subTest(argv=argv, platform=platform, euid=euid):
                with (patch.object(activation.sys, 'platform', platform),
                      patch.object(activation.os, 'geteuid', return_value=euid, create=True),
                      patch.object(activation, '_run_check') as check,
                      patch.object(activation, 'write_firewall_acceptance_receipt') as write,
                      contextlib.redirect_stderr(io.StringIO()),
                      self.assertRaises(SystemExit) as error):
                    activation.main(argv)
                self.assertEqual(error.exception.code, 2)
                check.assert_not_called()
                write.assert_not_called()

    def test_explicit_archive_required_before_checks_or_receipt(self):
        with (patch.object(activation.sys, 'platform', 'linux'),
              patch.object(activation.os, 'geteuid', return_value=0, create=True),
              patch.object(activation, '_run_check') as check,
              patch.object(activation, 'write_firewall_acceptance_receipt') as write,
              contextlib.redirect_stderr(io.StringIO()),
              self.assertRaises(SystemExit) as error):
            activation.main(self.argv())
        self.assertEqual(error.exception.code, 2)
        check.assert_not_called()
        write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
