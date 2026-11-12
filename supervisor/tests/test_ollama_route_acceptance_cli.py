"""Portable checks; these are NOT Linux/Docker packet evidence."""
import unittest
from unittest.mock import patch
from scripts import ollama_route_acceptance as route


class RouteAcceptanceTests(unittest.TestCase):
    def test_allowed_packets_are_checked_without_warmed_neighbor_cache(self):
        from scripts.ollama_route_linux import Lab
        from types import SimpleNamespace
        lab = object.__new__(Lab)
        lab.config = self.config()
        lab.args = SimpleNamespace(run_id='b'*32)
        lab.caller, lab.router, lab.docker = 10, 11, False
        _, lab.probes, _ = route.make_plan(lab.config)
        state = {'enabled': False, 'cold': False, 'flushes': 0}
        def policy(enabled):
            state['enabled'] = enabled
            state['cold'] = False
        def flush():
            self.assertTrue(state['enabled'])
            state['cold'] = True
            state['flushes'] += 1
        def transaction(spec):
            if state['enabled'] and spec['allow']:
                self.assertTrue(state['cold'], 'Positive controls must not prime allowed-path ARP/cache evidence')
                state['cold'] = False
            return spec['allow'] if state['enabled'] else True
        lab.set_policy, lab.flush_neighbors, lab.transaction = policy, flush, transaction
        report = lab.exercise()
        self.assertEqual(state['flushes'], sum(p['allow'] for p in lab.probes))
        self.assertIs(report['cold_neighbors'], True)

    def test_binding_rejects_overlapping_pool_before_running_checks(self):
        with self.assertRaises(ValueError):
            route.binding('10.240.0.0/13', '10.248.0.0/13',
                          '10.240.0.0/16', '192.168.40.10', 'ens18', 'a' * 64)

    def config(self):
        return route.binding('10.240.0.0/13', '10.248.0.0/13',
                             '172.20.0.0/16', '192.168.40.10', 'ens18', 'a' * 64)

    def test_report_rejects_timeout_without_positive_control(self):
        config = self.config()
        report = route.new_report(config, 'linux_ollama_route_check', 'b' * 32, '10', '11')
        report['cleanup'] = True
        report['probes'] = [{'name': p['name'], 'spec': p,
                             'before': False, 'enforced': not p['allow'], 'after': True}
                            for p in route.make_plan(config)[1]]
        with self.assertRaises(ValueError):
            route.validate_report(report, config, 'linux_ollama_route_check', 'b' * 32)

    def test_cli_refuses_without_opt_in_or_linux(self):
        from scripts import linux_ollama_route_check as cli
        with patch('sys.platform', 'win32'), self.assertRaises(SystemExit) as caught:
            cli.main(['--agent-pool', '10.240.0.0/13', '--frontend-pool', '10.248.0.0/13',
                      '--ollama-pool', '172.20.0.0/16', '--endpoint', '192.168.40.10',
                      '--interface', 'ens18'])
        self.assertEqual(caught.exception.code, 2)

    def test_plan_covers_real_transactions_and_both_isolated_pairs(self):
        policies, probes, addresses = route.make_plan(self.config())
        self.assertEqual(len(policies), 2)
        self.assertEqual(len(probes), 22)
        self.assertEqual(sum(p['allow'] for p in probes), 6)
        self.assertEqual(addresses['target'], '192.168.40.10')
        for p in policies:
            self.assertEqual(p.egress_interface, 'ens18')
        self.assertNotEqual(policies[0].subnet, policies[1].subnet)

    def test_activation_never_writes_on_failed_or_unvalidated_checks(self):
        from scripts import activate_ollama_route as activation
        from types import SimpleNamespace
        args = SimpleNamespace(agent_pool='10.240.0.0/13', frontend_pool='10.248.0.0/13',
            ollama_pool='172.20.0.0/16', endpoint='192.168.40.10', interface='ens18',
            state_dir='/var/lib/bezr-test', probe_image='sha256:' + 'c' * 64,
            image_archive='/owned/probe.tar')
        for output in ('{}', '{"cleanup":true}', 'not json'):
            with patch.object(activation, 'machine_id_sha256', return_value='a' * 64), \
                 patch.object(activation, 'caller_inode', return_value='10'), \
                 patch.object(activation, 'validate_acceptance_state_path'), \
                 patch.object(activation, 'command', return_value=output), \
                 patch.object(activation, 'write_ollama_route_receipt') as writer:
                with self.assertRaises((ValueError, RuntimeError)):
                    activation.activate(args)
                writer.assert_not_called()
        with patch.object(activation, 'machine_id_sha256', return_value='a' * 64), \
             patch.object(activation, 'caller_inode', return_value='10'), \
                 patch.object(activation, 'validate_acceptance_state_path'), \
             patch.object(activation, 'command', side_effect=RuntimeError('nonzero')), \
             patch.object(activation, 'write_ollama_route_receipt') as writer:
            with self.assertRaises(RuntimeError):
                activation.activate(args)
            writer.assert_not_called()

    def test_adapter_batch_uses_production_argv_and_bounded_runner(self):
        from scripts import ollama_route_linux as linux
        from types import SimpleNamespace
        with patch.object(linux.os, 'fstat', return_value=SimpleNamespace(st_ino=10)), \
             patch.object(linux.os, 'readlink', return_value='net:[10]'), \
             patch.object(linux, 'inode', return_value=11), \
             patch.object(linux.Lab, 'run', return_value='') as runner:
            lab = linux.Lab(SimpleNamespace(parent_netns_fd=8), self.config(), False)
            lab.adapter.batch_runner(['nft', '-f', '-'], 'EXACT_BATCH\n')
            runner.assert_called_once_with(['nft', '-f', '-'], input_text='EXACT_BATCH\n')

    def test_sidecars_use_actual_agent_pool_and_preserve_allowed_pairs(self):
        import ipaddress
        _, probes, addresses = route.make_plan(self.config())
        for index in (1, 2):
            self.assertIn(ipaddress.IPv4Address(addresses[f'side{index}']),
                          ipaddress.IPv4Network(self.config()['agent_network_pool']))
            by_name = {p['name']: p for p in probes}
            self.assertTrue(by_name[f'gateway{index}_own_sidecar']['allow'])
            self.assertTrue(by_name[f'sidecar{index}_own_web']['allow'])

    def synthetic_report(self, check=route.CHECKS[0], run_id='b' * 32):
        # Synthetic contract fixture ONLY, never written as a receipt/evidence.
        config = self.config()
        report = route.new_report(config, check, run_id, '10', '11')
        report['cleanup'] = report['policy_readback'] = report['cold_neighbors'] = True
        report['probes'] = [{'name': spec['name'], 'spec': spec, 'before': True,
                             'enforced': spec['allow'], 'after': True}
                            for spec in route.make_plan(config)[1]]
        return report

    def test_structured_report_rejects_boolean_integer_substitution(self):
        report = self.synthetic_report()
        report['binding']['schema_version'] = True
        with self.assertRaises(ValueError):
            route.validate_report(report, self.config(), route.CHECKS[0], 'b' * 32)

    def test_report_binds_every_field_and_requires_both_controls(self):
        import copy
        good = self.synthetic_report()
        route.validate_report(good, self.config(), route.CHECKS[0], 'b' * 32)
        mutations = [lambda r: r.update(cleanup=False), lambda r: r.update(policy_readback=False),
            lambda r: r.update(cold_neighbors=False),
            lambda r: r.update(router_netns_inode='10'), lambda r: r.update(policy_sha256='0' * 64),
            lambda r: r.update(run_id='c' * 32), lambda r: r.update(check=route.CHECKS[1]),
            lambda r: r['binding'].update(egress_interface='ens19'),
            lambda r: r['binding'].update(host_id_sha256='c' * 64),
            lambda r: r['binding'].update(ollama_endpoint_ip='192.168.40.11'),
            lambda r: r['binding'].update(frontend_network_pool='10.0.0.0/16'),
            lambda r: r['probes'].pop(), lambda r: r['probes'].__setitem__(1, r['probes'][0]),
            lambda r: r['probes'][0].update(before=False), lambda r: r['probes'][0].update(after=False),
            lambda r: r['probes'][0].update(enforced=False),
            lambda r: r['probes'][0]['spec'].update(port=11435)]
        for mutate in mutations:
            report = copy.deepcopy(good)
            mutate(report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                route.validate_report(report, self.config(), route.CHECKS[0], 'b' * 32)

    def test_activation_checks_both_exact_commands_and_never_writes_on_second_failure(self):
        from scripts import activate_ollama_route as activation
        from types import SimpleNamespace
        from contextlib import ExitStack
        import json
        args = SimpleNamespace(agent_pool='10.240.0.0/13', frontend_pool='10.248.0.0/13',
            ollama_pool='172.20.0.0/16', endpoint='192.168.40.10', interface='ens18',
            state_dir='/synthetic/never-written', probe_image='sha256:' + 'c' * 64,
            image_archive='/owned/probe.tar')
        for scenario in ('pass', 'second_nonzero', 'second_badcleanup', 'second_wrongendpoint', 'host_drift'):
            calls = []
            def run(argv, **kwargs):
                calls.append(argv)
                check = route.CHECKS[len(calls) - 1]
                if len(calls) == 2 and scenario == 'second_nonzero':
                    raise RuntimeError('synthetic nonzero')
                run_id = argv[argv.index('--run-id') + 1]
                report = self.synthetic_report(check, run_id)
                if len(calls) == 2 and scenario == 'second_badcleanup':
                    report['cleanup'] = False
                if len(calls) == 2 and scenario == 'second_wrongendpoint':
                    report['binding']['ollama_endpoint_ip'] = '192.168.40.11'
                return json.dumps(report)
            with self.subTest(scenario=scenario), ExitStack() as stack:
                host = stack.enter_context(patch.object(activation, 'machine_id_sha256', return_value='a' * 64))
                if scenario == 'host_drift':
                    host.side_effect = ['a' * 64, 'a' * 64, 'd' * 64]
                stack.enter_context(patch.object(activation, 'caller_inode', return_value='10'))
                stack.enter_context(patch.object(activation, 'validate_acceptance_state_path'))
                stack.enter_context(patch.object(activation, 'command', side_effect=run))
                writer = stack.enter_context(patch.object(activation, 'write_ollama_route_receipt'))
                loader = stack.enter_context(patch.object(activation, 'load_ollama_route_receipt', return_value=True))
                if scenario == 'pass':
                    activation.activate(args)
                    writer.assert_called_once_with(args.state_dir, args.agent_pool, args.frontend_pool,
                        args.ollama_pool, args.endpoint, args.interface, expected_host_id_sha256='a' * 64)
                    loader.assert_called_once()
                else:
                    with self.assertRaises((RuntimeError, ValueError)):
                        activation.activate(args)
                    writer.assert_not_called()
                self.assertEqual(len(calls), 2)
                for index, argv in enumerate(calls):
                    self.assertTrue(argv[1].endswith(route.CHECKS[index] + '.py'))
                    self.assertIn('--execute', argv)
                    self.assertIn('--confirm-disposable-host', argv)
                    self.assertEqual(argv[argv.index('--endpoint') + 1], args.endpoint)
                    self.assertEqual(argv[argv.index('--interface') + 1], args.interface)
                self.assertEqual(calls[1][-4:], ['--probe-image', args.probe_image, '--image-archive', args.image_archive])

    def test_portable_command_runner_bounds_output_and_timeout(self):
        import sys
        import subprocess
        self.assertEqual(route.command([sys.executable, '-c', 'print("portable")']).strip(), 'portable')
        with patch.object(route, 'LIMIT', 8), self.assertRaises(RuntimeError):
            route.command([sys.executable, '-c', 'print("x" * 1000)'])
        with self.assertRaises(subprocess.TimeoutExpired):
            route.command([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=.1)

    def test_no_report_file_skip_or_existing_receipt_cli_inputs(self):
        import contextlib
        import io
        from scripts import activate_ollama_route as activation
        base = ['--agent-pool', '10.240.0.0/13', '--frontend-pool', '10.248.0.0/13',
                '--ollama-pool', '172.20.0.0/16', '--endpoint', '192.168.40.10',
                '--interface', 'ens18', '--probe-image', 'sha256:' + 'c' * 64,
                '--image-archive', '/owned/probe.tar']
        for forbidden in ('--skip-checks', '--report-file=x', '--existing-receipt=x'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                activation.main([*base, forbidden])
            self.assertEqual(caught.exception.code, 2)

    def test_cleanup_refuses_nonempty_private_daemon_readback(self):
        from scripts import ollama_route_linux as linux
        from unittest.mock import Mock
        lab = linux.Lab.__new__(linux.Lab)
        lab.guard = Mock()
        lab.set_policy = Mock()
        lab.daemon = Mock()
        lab.daemon.poll.return_value = None
        lab.containers = lab.networks = lab.processes = lab.links = []
        lab.temp = None
        lab.adapter = Mock()
        lab.adapter.read.return_value = None
        lab.proxy_adapter = Mock()
        lab.proxy_adapter.read.return_value = None
        lab.specs = route.network_specs(self.config())
        lab.run = Mock(return_value='[{"ifname":"lo"}]')
        lab.dc = Mock(return_value='leftover-owned-container\n')
        with self.assertRaises(RuntimeError):
            lab.cleanup()

    def test_namespace_guard_blocks_mutation_in_callers_namespace(self):
        from scripts import ollama_route_linux as linux
        lab = linux.Lab.__new__(linux.Lab)
        lab.caller = lab.router = 10
        with patch.object(linux, 'inode', return_value=10), \
             patch.object(linux, 'command') as execute:
            with self.assertRaises(RuntimeError):
                lab.run(['ip', 'link', 'add', 'MUST_NOT_RUN', 'type', 'dummy'])
            execute.assert_not_called()

    def test_nested_daemon_argv_is_private_and_disables_host_integration(self):
        from pathlib import Path
        from scripts import ollama_route_linux as linux
        base = Path('/synthetic/bezr-ollama-private')
        argv = linux.daemon_argv(base, 'b' * 32)
        self.assertEqual(argv[0], 'dockerd')
        for flag, value in (('--host', 'unix://' + str(base / 'docker.sock')),
                            ('--data-root', str(base / 'data')), ('--exec-root', str(base / 'exec')),
                            ('--pidfile', str(base / 'dockerd.pid')),
                            ('--config-file', str(base / 'daemon.json'))):
            self.assertEqual(argv[argv.index(flag) + 1], value)
        for flag in ('--iptables=false', '--ip6tables=false', '--ip-forward=false',
                     '--bridge', '--userland-proxy=false'):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index('--bridge') + 1], 'none')

    def test_network_readback_accepts_only_empty_default_ipam_options(self):
        import copy
        from scripts.ollama_route_linux import verify_network_readback
        payload = route.network_specs(self.config())[0][1]
        identity = 'd' * 64
        observed = {**copy.deepcopy(payload), 'Id': identity}
        for options in (None, {}):
            observed['IPAM']['Options'] = options
            verify_network_readback(observed, identity, payload)
        for mutate in (
                lambda n: n['IPAM'].update(Options={'subnet': 'foreign'}),
                lambda n: n['IPAM'].update(Unexpected=True),
                lambda n: n.update(Id='e'*64),
                lambda n: n['IPAM']['Config'][0].update(Gateway='172.20.0.99'),
                lambda n: n.update(Labels={}),
                lambda n: n.update(Options={})):
            bad = copy.deepcopy(observed)
            mutate(bad)
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                verify_network_readback(bad, identity, payload)

    def test_argv_contains_every_canonical_network_option(self):
        payload = {'Name': 'pa-ollama-test', 'Driver': 'bridge', 'Internal': False,
                   'Attachable': False, 'EnableIPv6': False,
                   'IPAM': {'Driver': 'default', 'Config': [
                       {'Subnet': '172.20.0.0/29', 'Gateway': '172.20.0.1'}]},
                   'Options': {'com.docker.network.bridge.name': 'bzotest',
                               'com.docker.network.bridge.enable_icc': 'false'},
                   'Labels': {'owner': 'test'}}
        self.assertEqual(route.network_argv(payload), [
            'network', 'create', '--driver', 'bridge', '--ipam-driver', 'default',
            '--subnet', '172.20.0.0/29', '--gateway', '172.20.0.1',
            '--opt', 'com.docker.network.bridge.enable_icc=false',
            '--opt', 'com.docker.network.bridge.name=bzotest',
            '--label', 'owner=test', 'pa-ollama-test'])


if __name__ == '__main__':
    unittest.main()
