"""Portable contracts; no Docker/kernel/host acceptance is performed here."""
import unittest


class ProxyPrivateContractTests(unittest.TestCase):
    def test_proxy_ruleset_difference_reports_safe_family_section_chain_and_path(self):
        from copy import deepcopy
        from scripts.proxy_acceptance_linux import (
            ProxyLab, ProxyRulesetMismatch, first_ruleset_difference,
        )
        from scripts.proxy_packet_acceptance import binding
        from scripts.ollama_route_acceptance import proxy_policy
        expected = proxy_policy(binding('10.240.0.0/13', '10.248.0.0/13', 'a' * 64))

        actual = deepcopy(expected)
        actual['tables']['bridge']['rules'][0]['expr'][0]['match']['right'] = '192.0.2.99'
        self.assertEqual(first_ruleset_difference(expected, actual), {
            'family': 'bridge', 'section': 'rules', 'chain': 'forward', 'rule_index': 0,
            'field': 'rules[0].expr[0].match.right', 'difference': 'value_mismatch',
        })
        self.assertNotIn('192.0.2.99', repr(first_ruleset_difference(expected, actual)))
        absent = first_ruleset_difference(expected, None)
        self.assertEqual((absent['family'], absent['section'], absent['difference']),
                         ('inet', 'table', 'missing_field'))

        class Adapter:
            def __init__(self, value=None):
                self.value = value
            def read(self):
                return self.value
            def replace(self, value):
                pass

        lab = object.__new__(ProxyLab)
        lab.guard = lambda: None
        lab.adapter = Adapter()
        lab.proxy_adapter = Adapter(actual)
        lab.proxy_rules = expected
        with self.assertRaises(ProxyRulesetMismatch) as caught:
            lab.set_policy(True)
        self.assertEqual(caught.exception.ruleset_diff, {
            'family': 'bridge', 'section': 'rules', 'chain': 'forward', 'rule_index': 0,
            'field': 'rules[0].expr[0].match.right', 'difference': 'value_mismatch',
        })

        cases = (
            ('missing_field', lambda rules: rules['tables']['inet']['table'].pop('comment'),
             'table.comment'),
            ('extra_field', lambda rules: rules['tables']['inet']['table'].__setitem__(
                'private/path', 'must-not-be-reported'), 'table.other'),
            ('type_mismatch', lambda rules: rules['tables']['inet']['chains'][0].__setitem__(
                'prio', str(rules['tables']['inet']['chains'][0]['prio'])), 'chains[0].prio'),
            ('order_mismatch', lambda rules: rules['tables']['bridge']['rules'].__setitem__(
                slice(0, 2), reversed(rules['tables']['bridge']['rules'][:2])), 'rules[0]'),
        )
        for difference, mutate, field in cases:
            with self.subTest(difference=difference):
                changed = deepcopy(expected)
                mutate(changed)
                observed = first_ruleset_difference(expected, changed)
                self.assertEqual(observed['difference'], difference)
                self.assertEqual(observed['field'], field)
                self.assertNotIn('private/path', repr(observed))

        changed = deepcopy(expected)
        rules = changed['tables']['bridge']['rules']
        rules.insert(1, deepcopy(rules[0]))
        observed = first_ruleset_difference(expected, changed)
        self.assertEqual(observed['difference'], 'extra_field')
        self.assertEqual(observed['rule_index'], 1)
        self.assertEqual(observed['field'], 'rules[1]')

    def test_base_matrix_has_only_proxy_networks_and_both_allowed_pair_directions(self):
        from scripts.proxy_packet_acceptance import binding, make_plan, network_specs
        config = binding('10.240.0.0/13', '10.248.0.0/13', 'a' * 64)
        probes, addresses = make_plan(config)
        allowed = {(p['source'], p['destination']) for p in probes if p['allow']}
        for index in (1, 2):
            self.assertIn((f'gw{index}', addresses[f'side{index}']), allowed)
            self.assertIn((f'side{index}', addresses[f'gw{index}']), allowed)
            self.assertIn((f'web{index}', addresses[f'side_front{index}']), allowed)
            self.assertIn((f'side{index}', addresses[f'web{index}']), allowed)
        self.assertEqual(len(allowed), 8)
        networks = network_specs(config)
        self.assertEqual(len(networks), 4)
        self.assertTrue(all(not payload['Name'].startswith('pa-ollama-') for _, payload, _ in networks))
        self.assertTrue(any(not p['allow'] and p['destination'] == addresses['target'] for p in probes))
    def test_reports_require_complete_independent_proxy_evidence(self):
        from copy import deepcopy
        from scripts.proxy_packet_acceptance import binding, make_plan, new_report, validate_report
        config = binding('10.240.0.0/13', '10.248.0.0/13', 'a' * 64)
        report = new_report(config, 'linux_proxy_isolated_check', 'b' * 32, '10', '20')
        with self.assertRaises(ValueError):
            validate_report(report, config, 'linux_proxy_isolated_check', 'b' * 32)
        # Explicitly synthetic report to exercise the validator, not packet evidence.
        report.update(cleanup=True, cold_neighbors=True, policy_readback=True)
        report['probes'] = [dict(name=p['name'], spec=p, before=True,
                                enforced=p['allow'], after=True) for p in make_plan(config)[0]]
        validate_report(report, config, 'linux_proxy_isolated_check', 'b' * 32)
        for mutate in (
            lambda r: r.update(cleanup=1),
            lambda r: r.update(profile='agent_ollama_v1'),
            lambda r: r['probes'].pop(),
            lambda r: r['binding'].update(host_id_sha256='c' * 64),
            lambda r: r['probes'][0].update(after=False),
        ):
            bad = deepcopy(report)
            mutate(bad)
            with self.assertRaises(ValueError):
                validate_report(bad, config, 'linux_proxy_isolated_check', 'b' * 32)
    def test_connected_proxy_lab_never_installs_or_removes_ollama_table(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from scripts import ollama_route_linux as route
        from scripts.proxy_acceptance_linux import ProxyLab
        from scripts.proxy_packet_acceptance import binding
        class Adapter:
            def __init__(self):
                self.value, self.events = None, []
            def replace(self, value):
                self.events.append('replace')
                self.value = value
            def remove(self):
                self.events.append('remove')
                self.value = None
            def read(self):
                return self.value
        # Synthetic namespace proof and adapters; actual ProxyLab policy path.
        proof = {'net': 20, 'mnt': 30, 'pid': 40}
        config = binding('10.240.0.0/13', '10.248.0.0/13', 'a' * 64)
        with (patch.object(route, 'validate_lab_boundary', return_value=(proof, {'net': 10})),
              patch.object(route, 'current_namespaces', return_value=proof),
              patch.object(route.os, 'getpid', return_value=1)):
            lab = ProxyLab(SimpleNamespace(run_id='b' * 32), config, False)
            lab.adapter, lab.proxy_adapter = Adapter(), Adapter()
            lab.set_policy(True)
            self.assertEqual(lab.proxy_adapter.events, ['replace'])
            self.assertEqual(lab.adapter.events, [])
            lab.set_policy(False)
            self.assertEqual(lab.proxy_adapter.events, ['replace', 'remove'])
            self.assertEqual(lab.adapter.events, [])
            self.assertEqual(lab.cleanup_policy_removals(),
                             (('remove_proxy_policy', lab.proxy_adapter),))
            lab.adapter.value = {'foreign': 'unexpected'}
            with self.assertRaises(RuntimeError):
                lab.set_policy(True)
    def test_proxy_exercise_emits_base_report_and_cold_allows(self):
        from types import SimpleNamespace
        from scripts.proxy_acceptance_linux import ProxyLab
        from scripts import proxy_packet_acceptance as contract
        lab = object.__new__(ProxyLab)
        lab.config = lab.proxy_binding = contract.binding('10.240.0.0/13', '10.248.0.0/13', 'a' * 64)
        lab.args = SimpleNamespace(run_id='b' * 32)
        lab.caller, lab.router, lab.docker = 10, 20, False
        lab.probes = contract.make_plan(lab.proxy_binding)[0]
        state, cold = {'enabled': False}, []
        # Synthetic transport only; exercise/contract below are the real base path.
        lab.set_policy = lambda enabled: state.update(enabled=enabled)
        lab.transaction = lambda spec: spec['allow'] if state['enabled'] else True
        lab.flush_neighbors = lambda: cold.append(True)
        report = lab.exercise()
        self.assertEqual(report.get('profile'), 'agent_proxy_v1')
        self.assertEqual(len(cold), sum(p['allow'] for p in lab.probes))
        self.assertIs(report['cleanup'], False)
        report['cleanup'] = True  # Synthetic teardown acknowledgement for validator only.
        contract.validate_report(report, lab.proxy_binding, contract.CHECKS[0], lab.args.run_id)
    def test_public_proxy_cli_rejects_internal_descriptor_flags_before_launch(self):
        import contextlib
        import io
        from unittest.mock import patch
        from scripts import proxy_acceptance_linux as private
        with patch.object(private.transport, 'command') as launch:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                private.main(['--agent-pool', '10.240.0.0/13', '--frontend-pool', '10.248.0.0/13',
                              '--execute', '--confirm-disposable-host', '--parent-netns-fd', '3'])
            self.assertEqual(error.exception.code, 2)
            launch.assert_not_called()
    def test_existing_base_entrypoints_delegate_to_private_lab(self):
        from unittest.mock import patch
        from scripts import linux_proxy_isolated_check, linux_docker_proxy_acceptance
        argv = ['--agent-pool', '10.240.0.0/13', '--frontend-pool', '10.248.0.0/13',
                '--execute', '--confirm-disposable-host']
        for entry, docker in ((linux_proxy_isolated_check, False), (linux_docker_proxy_acceptance, True)):
            with self.subTest(docker=docker), patch.object(entry, 'private_main', create=True, return_value=0) as run:
                self.assertEqual(entry.main(argv), 0)
                run.assert_called_once_with(argv, docker=docker)


if __name__ == '__main__':
    unittest.main()
