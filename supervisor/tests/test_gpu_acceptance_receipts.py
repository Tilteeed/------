"""Portable synthetic adapters only: never production/VM acceptance evidence."""
import copy
import importlib
import unittest
from unittest.mock import patch


class NftFingerprintTests(unittest.TestCase):
    def test_unknown_dynamic_nft_content_and_malformed_counters_remain_structural(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        for entry in (
            {'quota': {'family': 'inet', 'table': 'synthetic', 'name': 'q', 'bytes': 100, 'used': 10}},
            {'set': {'elem': [{'val': 'synthetic', 'expires': 20}]}},
            {'counter': {'family': 'inet', 'table': 'synthetic', 'name': 'future',
                         'packets': 1, 'bytes': 2, 'unknown': True}},
            {'rule': {'expr': [{'counter': {'packets': True, 'bytes': 2}}]}},
        ):
            with self.subTest(entry=entry):
                before = {'nftables': [entry]}
                after = copy.deepcopy(before)
                # Mutate every numeric runtime-looking field, including unknown
                # content. None is a recognized packet+byte counter schema.
                def mutate(value):
                    if isinstance(value, dict):
                        for key in value:
                            if type(value[key]) is int:
                                value[key] += 1
                            else:
                                mutate(value[key])
                    elif isinstance(value, list):
                        for item in value:
                            mutate(item)
                mutate(after)
                self.assertNotEqual(api.nft_fingerprint(before), api.nft_fingerprint(after))

    def test_unknown_named_counter_schema_is_not_normalized(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        for change in ({'family': 'future'}, {'handle': 'unknown'}, {'comment': {'bytes': 3}}):
            counter: dict = dict(family='inet', table='synthetic', name='synthetic', packets=1, bytes=2)
            counter.update(change)
            before = {'nftables': [{'counter': counter}]}
            after = copy.deepcopy(before)
            after['nftables'][0]['counter']['bytes'] = 999
            with self.subTest(change=change):
                self.assertNotEqual(api.nft_fingerprint(before), api.nft_fingerprint(after))

    def test_only_known_nft_counter_positions_are_transient(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        before = {'nftables': [
            {'rule': {'family': 'inet', 'table': 'synthetic', 'chain': 'c', 'handle': 7,
                      'expr': [{'counter': {'packets': 1, 'bytes': 2}},
                               {'quota': {'bytes': 4096, 'used': 3}},
                               {'unknown': {'counter': {'packets': 1, 'bytes': 2}}},
                               {'accept': None}]}},
            {'counter': {'family': 'inet', 'table': 'synthetic', 'name': 'named',
                         'handle': 8, 'packets': 10, 'bytes': 20}}]}
        after = copy.deepcopy(before)
        after['nftables'][0]['rule']['expr'][0]['counter'].update(packets=30, bytes=40)
        after['nftables'][1]['counter'].update(packets=50, bytes=60)
        self.assertEqual(api.nft_fingerprint(before), api.nft_fingerprint(after))
        for mutate in (
            lambda d: d['nftables'][0]['rule'].__setitem__('handle', 9),
            lambda d: d['nftables'][0]['rule']['expr'][1]['quota'].__setitem__('bytes', 8192),
            lambda d: d['nftables'][0]['rule']['expr'][2]['unknown']['counter'].__setitem__('bytes', 999),
            lambda d: d['nftables'][0]['rule']['expr'].reverse(),
            lambda d: d['nftables'][0]['rule']['expr'][0]['counter'].__setitem__('future', 1),
        ):
            changed = copy.deepcopy(before)
            mutate(changed)
            self.assertNotEqual(api.nft_fingerprint(before), api.nft_fingerprint(changed))
        self.assertEqual(before['nftables'][0]['rule']['expr'][0]['counter']['bytes'], 2)


class SyntheticReadRunner:
    """Labelled fake command transport; never calls a host executable."""
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[0] == '/usr/sbin/nft':
            return '{"nftables": []}'
        if argv[0] == '/usr/sbin/ip':
            return '[]'
        if argv[0] == '/usr/bin/systemctl':
            return 'MainPID=12\nExecMainStartTimestampMonotonic=100\nActiveEnterTimestampMonotonic=100\nNRestarts=0\nActiveState=active\nSubState=running\n'
        if 'inspect' in argv:
            if 'container' in argv:
                return '{"id":"' + 'a' * 64 + '","name":"synthetic","image":"synthetic","status":"running","pid":12,"started_at":"synthetic","restart_count":0,"networks":{}}'
            return '{"id":"' + 'b' * 64 + '","name":"synthetic","driver":"bridge","internal":false,"ipv6":false,"ipam":{},"containers":{}}'
        return ('a' if 'ps' in argv else 'b') * 64 + '\n'


class ProductionSourceTests(unittest.TestCase):
    def test_incomplete_or_unexpected_docker_projection_fails_closed(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        original = SyntheticReadRunner()
        for malformed in ('{}', '{"id":"foreign"}', '{"id":"' + 'a' * 64 + '","Env":["synthetic-secret"]}'):
            def synthetic_bad_projection(argv, **kwargs):
                return malformed if 'inspect' in argv else original(argv, **kwargs)
            source = api.ProductionStateSource(docker_socket='/var/run/docker.sock',
                                               runner=synthetic_bad_projection)
            with self.subTest(projection=malformed), self.assertRaises(ValueError):
                source.capture(allow_host_inspection=True, busy_host_approved=True)

    def test_socket_rejects_control_characters_and_context_like_inputs(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        for socket in ('/var/run/bad\x00.sock', '/var/run/bad\n.sock', 'unix:///var/run/docker.sock',
                       'default', '/var/run/../docker.sock', '//remote/docker.sock', '/'):
            with self.subTest(socket=repr(socket)), self.assertRaises(ValueError):
                api.ProductionStateSource(docker_socket=socket, runner=SyntheticReadRunner())

    def test_container_network_projection_never_captures_driver_secrets(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        runner = SyntheticReadRunner()
        source = api.ProductionStateSource(docker_socket='/var/run/docker.sock', runner=runner)
        source.capture(allow_host_inspection=True, busy_host_approved=True)
        fmt = next(argv[-2] for argv, _ in runner.calls if 'container' in argv)
        self.assertNotIn('json .NetworkSettings.Networks', fmt)
        self.assertNotIn('DriverOpts', fmt)
        self.assertIn('.NetworkID', fmt)

    def test_host_and_null_networks_have_known_configuration_absences(self):
        import json
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        for driver in ('host', 'null'):
            original = SyntheticReadRunner()
            def synthetic_native_network(argv, **kwargs):
                text = original(argv, **kwargs)
                if 'network' in argv and 'inspect' in argv:
                    value = json.loads(text)
                    value.update(driver=driver, ipam=None, containers=None)
                    return json.dumps(value)
                return text
            source = api.ProductionStateSource(docker_socket='/var/run/docker.sock', runner=synthetic_native_network)
            with self.subTest(driver=driver):
                self.assertEqual(len(source.capture(allow_host_inspection=True,
                                                    busy_host_approved=True)['networks']), 64)

    def test_gate_socket_and_allowlist_produce_digest_only_snapshot(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        runner = SyntheticReadRunner()
        source = api.ProductionStateSource(docker_socket='/var/run/docker.sock', runner=runner)
        with self.assertRaises(ValueError):
            source.capture()
        self.assertEqual(runner.calls, [])
        snapshot = source.capture(allow_host_inspection=True, busy_host_approved=True)
        self.assertEqual(set(snapshot), {'nft', 'routes', 'interfaces', 'containers', 'networks', 'services'})
        self.assertTrue(all(len(v) == 64 for v in snapshot.values()))
        for argv, kwargs in runner.calls:
            self.assertEqual(kwargs['env'], api.READ_ENV)
            self.assertEqual(kwargs['timeout'], 15)
            if argv[0] == '/usr/bin/docker':
                self.assertEqual(argv[1:5], ['--host', 'unix:///var/run/docker.sock', '--config', '/nonexistent'])
                if 'inspect' in argv:
                    self.assertIn('--format', argv)
                    self.assertNotIn('json .Config', argv[-2])
                    self.assertNotIn('.Env', argv[-2])
        with self.assertRaises(ValueError):
            api.ProductionStateSource(docker_socket='tcp://remote:2375', runner=runner)


class SyntheticStateSource:
    """Digest-only fixture, not an observation of a host."""
    def __init__(self):
        snapshot = {key: 'b' * 64 for key in ('nft', 'routes', 'interfaces', 'containers', 'networks', 'services')}
        self.values: list[dict] = [copy.deepcopy(snapshot), copy.deepcopy(snapshot)]

    def capture(self, **kwargs):
        return copy.deepcopy(self.values.pop(0))


class SyntheticCandidateStore:
    def __init__(self):
        self.events = []
        self.fail: str | None = None

    def preflight(self):
        self.events.append('preflight')

    def create(self):
        self.events.append('create')

    def write_base(self, site, host):
        self.events.append('write_base')
        if self.fail == 'write_base':
            raise OSError('synthetic private error not returned')

    def write_route(self, site, host):
        self.events.append('write_route')
        if self.fail == 'write_route':
            raise OSError('synthetic private error not returned')

    def read_base(self, site):
        self.events.append('read_base')
        return self.fail != 'read_base'

    def read_route(self, site):
        self.events.append('read_route')
        return self.fail != 'read_route'

    def complete(self):
        self.events.append('complete')

    def incomplete(self, phase):
        self.events.append('incomplete')


class CandidateOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('scripts.gpu_acceptance_receipts')
        self.site = dict(agent_network_pool='10.80.0.0/16', frontend_network_pool='10.81.0.0/16',
                         ollama_network_pool='10.82.0.0/16', ollama_endpoint_ip='192.168.55.8',
                         egress_interface='synthetic0')
        self.source = SyntheticStateSource()
        self.store = SyntheticCandidateStore()
        self.calls = []
        self.bad_check = None
        self.mutate = lambda report: None
        self.proof = {'complete': True, 'resources_absent': True, 'checks': list(self.api.CHECKS)}

    def runner(self, check, binding, run_id):
        self.calls.append(check)
        report = dict(check=check, binding=copy.deepcopy(binding), run_id=run_id,
                      cleanup=True, passed=check != self.bad_check, evidence={'synthetic': True})
        self.mutate(report)
        return report

    def execute(self, identities=None, validator=None, **kwargs):
        with patch.object(self.api, 'machine_id_sha256', side_effect=identities or ['a' * 64] * 2):
            return self.api.run_candidate_acceptance(
                self.site, source=self.source, store=self.store, check_runner=self.runner,
                report_validator=validator or (lambda report, binding, check, run_id: True),
                cleanup_verifier=lambda: self.proof,
                allow_host_inspection=True, busy_host_approved=True, **kwargs)

    def test_invalid_check_evidence_never_writes_candidates(self):
        mutations = [lambda r: r.pop('cleanup'),
                     lambda r: r.__setitem__('cleanup', False),
                     lambda r: r.__setitem__('cleanup', 1),
                     lambda r: r.__setitem__('passed', False),
                     lambda r: r.__setitem__('check', 'cached_vm_report'),
                     lambda r: r.__setitem__('run_id', 'old-run'),
                     lambda r: r['binding']['base'].__setitem__('host_id_sha256', 'f' * 64),
                     lambda r: r['binding']['route'].__setitem__('ollama_endpoint_ip', '192.168.55.9'),
                     lambda r: r['binding']['route'].__setitem__('policy_version', True)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp()
                self.mutate = mutate
                result = self.execute()
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(self.store.events, ['preflight'])
                self.assertEqual(len(self.calls), 1)
        for verdict in (False, None, 1, {'passed': True}):
            with self.subTest(validator_verdict=verdict):
                self.setUp()
                self.assertEqual(self.execute(validator=lambda *args: verdict)['status'], 'incomplete')
                self.assertEqual(self.store.events, ['preflight'])

    def test_cleanup_or_host_drift_never_writes_candidates(self):
        for proof in (None, {}, {'complete': True},
                      {'complete': True, 'resources_absent': False, 'checks': list(self.api.CHECKS)},
                      {'complete': 1, 'resources_absent': True, 'checks': list(self.api.CHECKS)},
                      {'complete': True, 'resources_absent': True, 'checks': list(self.api.CHECKS[:-1])}):
            with self.subTest(proof=proof):
                self.setUp()
                self.proof = proof
                self.assertEqual(self.execute()['status'], 'incomplete')
                self.assertEqual(self.store.events, ['preflight'])
        self.setUp()
        self.source.values[-1]['nft'] = 'c' * 64
        self.assertEqual(self.execute()['status'], 'incomplete')
        self.assertEqual(self.store.events, ['preflight'])
        self.setUp()
        self.assertEqual(self.execute(identities=['a' * 64, 'd' * 64])['status'], 'incomplete')
        self.assertEqual(self.store.events, ['preflight'])

    def test_readback_failure_preserves_incomplete_without_success_marker(self):
        for failure in ('read_base', 'read_route'):
            with self.subTest(failure=failure):
                self.setUp()
                self.store.fail = failure
                result = self.execute()
                self.assertEqual(result['status'], 'incomplete')
                self.assertIn('incomplete', self.store.events)
                self.assertNotIn('complete', self.store.events)

    def test_failed_fixed_check_or_write_never_reports_complete(self):
        for check in self.api.CHECKS:
            with self.subTest(check=check):
                self.setUp()
                self.bad_check = check
                self.assertEqual(self.execute()['status'], 'incomplete')
                self.assertEqual(self.store.events, ['preflight'])
        for failure in ('write_base', 'write_route'):
            with self.subTest(failure=failure):
                self.setUp()
                self.store.fail = failure
                result = self.execute()
                self.assertEqual(result['status'], 'incomplete')
                self.assertNotIn('complete', self.store.events)
                self.assertEqual(self.store.events[-1], 'incomplete')
                self.assertNotIn('synthetic private error', str(result))

    def test_callback_cannot_switch_site_after_validation(self):
        expected = copy.deepcopy(self.site)
        original = self.runner
        def switches_site(check, binding, run_id):
            report = original(check, binding, run_id)
            self.site['ollama_endpoint_ip'] = '192.168.55.9'
            return report
        self.runner = switches_site
        with patch.object(self.store, 'write_route', wraps=self.store.write_route) as write:
            self.assertEqual(self.execute()['status'], 'complete')
            self.assertEqual(write.call_args.args[0], expected)

    def test_permission_failure_runs_no_sources_checks_or_identity_read(self):
        for permission, approval in ((False, False), (True, False), (False, True), (1, True)):
            with self.subTest(permission=permission, approval=approval):
                self.setUp()
                with patch.object(self.api, 'machine_id_sha256') as local_identity:
                    result = self.api.run_candidate_acceptance(self.site, source=self.source,
                        store=self.store, check_runner=self.runner,
                        report_validator=lambda *args: True, cleanup_verifier=lambda: self.proof,
                        allow_host_inspection=permission, busy_host_approved=approval)
                    self.assertEqual(result['status'], 'incomplete')
                    local_identity.assert_not_called()
                    self.assertEqual(self.calls, [])
                    self.assertEqual(self.store.events, [])

    def test_check_exception_still_runs_cleanup_and_writes_nothing(self):
        def raises(*args):
            raise RuntimeError('synthetic failure with private content')
        with patch.object(self.api, 'machine_id_sha256', return_value='a' * 64), \
             patch.object(self, 'runner', side_effect=raises):
            cleanup = []
            result = self.api.run_candidate_acceptance(self.site, source=self.source,
                store=self.store, check_runner=self.runner, report_validator=lambda *args: True,
                cleanup_verifier=lambda: cleanup.append('verified'),
                allow_host_inspection=True, busy_host_approved=True)
        self.assertEqual(cleanup, ['verified'])
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(self.store.events, ['preflight'])
        self.assertNotIn('private content', str(result))

    def test_malformed_snapshot_cannot_leak_metadata_or_issue_candidates(self):
        for value in ({}, {'private': 'synthetic-private-inventory'}, {'nft': True}):
            with self.subTest(value=value):
                self.setUp()
                self.source.values = [value, value]
                result = self.execute()
                self.assertEqual(result['status'], 'incomplete')
                self.assertNotIn('synthetic-private-inventory', str(result))
                self.assertEqual(self.store.events, ['preflight'])

    def test_all_four_fixed_checks_cleanup_and_snapshot_precede_both_writes(self):
        result = self.execute()
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(self.calls, list(self.api.CHECKS))
        self.assertEqual(self.store.events, ['preflight', 'create', 'write_base', 'write_route',
                                             'read_base', 'read_route', 'complete'])
        self.assertNotIn('192.168.55.8', str(result))


class RootCandidateStoreTests(unittest.TestCase):
    def test_existing_receipt_writers_and_current_host_loaders_are_used(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        site = dict(agent_network_pool='10.80.0.0/16', frontend_network_pool='10.81.0.0/16',
                    ollama_network_pool='10.82.0.0/16', ollama_endpoint_ip='192.168.55.8',
                    egress_interface='synthetic0')
        store = api.RootCandidateStore('/synthetic/new-candidate')
        with patch.object(store, '_assert_owned') as owned, \
             patch.object(api, 'write_firewall_acceptance_receipt') as base_write, \
             patch.object(api, 'write_ollama_route_receipt') as route_write, \
             patch.object(api, 'load_firewall_acceptance_receipt', return_value=True) as base_load, \
             patch.object(api, 'load_ollama_route_receipt', return_value=True) as route_load:
            store.write_base(site, 'a' * 64)
            store.write_route(site, 'a' * 64)
            self.assertTrue(store.read_base(site))
            self.assertTrue(store.read_route(site))
            base_write.assert_called_once_with(store.path, '10.80.0.0/16', '10.81.0.0/16',
                                               expected_host_id_sha256='a' * 64)
            route_write.assert_called_once_with(store.path, '10.80.0.0/16', '10.81.0.0/16',
                    '10.82.0.0/16', '192.168.55.8', 'synthetic0', expected_host_id_sha256='a' * 64)
            base_load.assert_called_once_with(store.path, '10.80.0.0/16', '10.81.0.0/16')
            route_load.assert_called_once_with(store.path, '10.80.0.0/16', '10.81.0.0/16',
                    '10.82.0.0/16', '192.168.55.8', 'synthetic0')
            self.assertEqual(owned.call_count, 4)

    def test_new_candidate_keeps_incomplete_diagnostic_until_both_loaders_pass(self):
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        store = api.RootCandidateStore('/synthetic/new-candidate')
        with patch.object(store, '_assert_owned'), patch.object(store, '_record') as record:
            with self.assertRaises(ValueError):
                store.complete()
            record.assert_not_called()
            store.incomplete('write_route')
            record.assert_called_once_with('incomplete-write_route.json',
                                           {'status': 'incomplete', 'phase': 'write_route'})

    def test_existing_candidate_path_is_never_reused(self):
        import tempfile
        api = importlib.import_module('scripts.gpu_acceptance_receipts')
        with tempfile.TemporaryDirectory(prefix='synthetic-stage3-') as directory:
            with self.assertRaises(ValueError):
                api.RootCandidateStore(directory).preflight()


if __name__ == '__main__':
    unittest.main()
