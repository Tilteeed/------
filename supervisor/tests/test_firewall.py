"""Synthetic adapter tests; never execute nft or privileged operations."""
import copy
import json
import unittest

from supervisor.firewall import (
    EndpointPair, FirewallError, FirewallManager, NetworkPolicy, NftablesAdapter,
    expected_ruleset, validate_networks,
)


class FakeAdapter:
    def __init__(self, state=None, *, corrupt_readback=False):
        self.state = copy.deepcopy(state)
        self.writes = []
        self.corrupt_readback = corrupt_readback

    def read(self):
        return copy.deepcopy(self.state)

    def replace(self, ruleset):
        self.writes.append(copy.deepcopy(ruleset))
        self.state = copy.deepcopy(ruleset)
        if self.corrupt_readback:
            drop_rule = next(rule for rule in self.state['tables']['inet']['rules']
                             if rule['expr'][-1] == {'drop': None})
            drop_rule['expr'][-1] = {'accept': None}

    def remove(self):
        self.writes.append(None)
        self.state = None


def network(hex_digit='a', subnet='192.0.2.0/29'):
    ident = hex_digit * 32
    import ipaddress
    net = ipaddress.ip_network(subnet)
    front_net = ipaddress.ip_network((int(net.network_address) + net.num_addresses, 29))
    return NetworkPolicy(
        ident, str(net), str(front_net), 'bza' + ident[:12], 'bzf' + ident[:12],
        EndpointPair(str(net.network_address + 2), str(net.network_address + 3)),
        EndpointPair(str(front_net.network_address + 2), str(front_net.network_address + 3)))


class NftablesAdapterTests(unittest.TestCase):
    def test_nft_json_readback_matches_and_detects_rule_drift(self):
        expected = expected_ruleset((network(),))
        drift = {'enabled': False}
        def runner(argv):
            family = argv[-1] if argv[-2] == 'tables' else argv[-2]
            table = expected['tables'][family]
            if argv[-2] == 'tables':
                return json.dumps({'nftables': [{'table': {
                    **table['table'], 'handle': 20 if family == 'inet' else 21}}]})
            objects = [{'table': {**table['table'], 'handle': 20 if family == 'inet' else 21}}]
            objects.extend({'chain': {**chain, 'handle': i + 30}}
                           for i, chain in enumerate(table['chains']))
            rules = sorted(copy.deepcopy(table['rules']),
                           key=lambda item: item['chain'], reverse=True)
            if drift['enabled'] and family == 'inet' and rules:
                rules[0]['expr'][-1] = {'accept': None}
            objects.extend({'rule': {**rule, 'handle': i + 100}}
                           for i, rule in enumerate(rules))
            return json.dumps({'nftables': objects})
        adapter = NftablesAdapter(nft_binary='nft-test', runner=runner,
                                  batch_runner=lambda *_args: None)
        self.assertEqual(adapter.read(), expected)
        drift['enabled'] = True
        self.assertNotEqual(adapter.read(), expected)

    def test_batch_is_atomic_scoped_to_bezr_tables_and_never_flushes_host_rules(self):
        invocations = []
        batches = []
        def runner(argv):
            invocations.append(tuple(argv))
            return '{"nftables":[]}'
        def batch_runner(argv, batch):
            batches.append((tuple(argv), batch))
        adapter = NftablesAdapter(nft_binary='nft-test', runner=runner,
                                  batch_runner=batch_runner)
        adapter.replace(expected_ruleset((network(),)))
        self.assertEqual(len(batches), 1)
        command, batch = batches[0]
        self.assertEqual(command, ('nft-test', '-f', '-'))
        self.assertIn('inet agent_proxy_v1', batch)
        self.assertIn('bridge agent_proxy_v1', batch)
        self.assertNotIn('flush ruleset', batch.lower())
        self.assertNotIn('flush table', batch.lower())
        self.assertGreaterEqual(len(invocations), 2)

    def test_unowned_table_name_is_never_replaced(self):
        batches = []
        def runner(argv):
            if argv[-2:] == ['tables', 'inet']:
                return ('{"nftables":[{"table":{"family":"inet","name":"agent_proxy_v1",'
                        '"handle":17,"comment":"not-bezr"}}]}')
            if argv[-3:] == ['table', 'inet', 'agent_proxy_v1']:
                return ('{"nftables":[{"table":{"family":"inet","name":"agent_proxy_v1",'
                        '"handle":17,"comment":"not-bezr"}}]}')
            return '{"nftables":[]}'
        adapter = NftablesAdapter(
            nft_binary='nft-test', runner=runner,
            batch_runner=lambda argv, batch: batches.append((argv, batch)))
        with self.assertRaises(FirewallError):
            adapter.replace(expected_ruleset((network(),)))
        self.assertEqual(batches, [])

    def test_partial_tables_are_not_a_ready_ruleset(self):
        def runner(argv):
            if argv[-2:] == ('tables', 'inet') or argv[-2:] == ['tables', 'inet']:
                return ('{"nftables":[{"table":{"family":"inet","name":"agent_proxy_v1",'
                        '"handle":17,"comment":"BEZR managed firewall agent_proxy_v1 v1"}}]}')
            if argv[-2:] == ('tables', 'bridge') or argv[-2:] == ['tables', 'bridge']:
                return '{"nftables":[]}'
            return '{"nftables":[]}'
        adapter = NftablesAdapter(nft_binary='nft-test', runner=runner,
                                  batch_runner=lambda *_args: None)
        self.assertFalse(FirewallManager(adapter, semantics_validated=True).ready((network(),)))

    def test_unvalidated_firewall_cannot_apply_policy(self):
        adapter = FakeAdapter()
        manager = FirewallManager(adapter, semantics_validated=False)
        with self.assertRaises(FirewallError):
            manager.apply((network(),))
        self.assertEqual(adapter.writes, [])


class FirewallPolicyTests(unittest.TestCase):
    def test_expected_policy_separates_host_routed_and_bridge_hooks(self):
        policy = network()
        expected = expected_ruleset((policy,))
        self.assertEqual(set(expected['tables']), {'inet', 'bridge'})
        inet = expected['tables']['inet']
        self.assertEqual(inet['table']['name'], 'agent_proxy_v1')
        inet_chains = {chain['name']: chain for chain in inet['chains']}
        self.assertEqual(set(inet_chains), {'input', 'output', 'forward'})
        self.assertTrue(all(chain['policy'] == 'accept' and chain['prio'] == -10
                            for chain in inet_chains.values()))
        self.assertTrue(any('input agent source' in rule['comment']
                            and rule['expr'][-1] == {'drop': None}
                            for rule in inet['rules']))
        inet_forward_accepts = [rule for rule in inet['rules']
                                if rule['chain'] == 'forward'
                                and rule['expr'][-1] == {'accept': None}]
        self.assertTrue(inet_forward_accepts)
        for rule in inet_forward_accepts:
            meta_keys = {match['match']['left']['meta']['key']
                         for match in rule['expr'][:-1]
                         if 'meta' in match.get('match', {}).get('left', {})}
            self.assertEqual(meta_keys, {'iifname', 'oifname'})
        bridge = expected['tables']['bridge']
        bridge_chains = {chain['name']: chain for chain in bridge['chains']}
        self.assertTrue(all(chain['policy'] == 'accept' and chain['prio'] == -210
                            for chain in bridge_chains.values()))
        self.assertTrue(any('same-bridge arp' in rule['comment'] for rule in bridge['rules']))
        self.assertTrue(any('bridge agent' in rule['comment']
                            and rule['expr'][-1] == {'accept': None}
                            for rule in bridge['rules']))
        self.assertTrue(any(rule['expr'][-1] == {'drop': None}
                            and 'bridge ingress' in rule['comment']
                            for rule in bridge['rules']))

    def test_policy_lists_distinct_static_pairs_for_frontend_and_agent(self):
        ident = 'c' * 32
        policy = NetworkPolicy(
            instance_id=ident, agent_subnet='10.240.0.0/29',
            frontend_subnet='10.248.0.0/29',
            agent_bridge='bza' + ident[:12], frontend_bridge='bzf' + ident[:12],
            agent_pair=EndpointPair('10.240.0.2', '10.240.0.3'),
            frontend_pair=EndpointPair('10.248.0.2', '10.248.0.3'))
        rules = expected_ruleset((policy,))
        agent_rules = [rule for rule in rules['tables']['bridge']['rules']
                       if 'bridge agent' in rule['comment']]
        front_rules = [rule for rule in rules['tables']['bridge']['rules']
                       if 'bridge frontend' in rule['comment']]
        self.assertEqual(len(agent_rules), 2)
        self.assertEqual(len(front_rules), 2)
        self.assertTrue(all('10.240.0.' in str(rule['expr']) for rule in agent_rules))
        self.assertTrue(all('10.248.0.' in str(rule['expr']) for rule in front_rules))


    def test_network_policy_rejects_non_contract_static_endpoint_pair(self):
        ident = 'd' * 32
        with self.assertRaises(ValueError):
            NetworkPolicy(
                instance_id=ident, agent_subnet='10.240.0.0/29',
                frontend_subnet='10.248.0.0/29',
                agent_bridge='bza' + ident[:12], frontend_bridge='bzf' + ident[:12],
                agent_pair=EndpointPair('10.240.0.2', '10.240.0.4'),
                frontend_pair=EndpointPair('10.248.0.2', '10.248.0.3'))

    def test_readiness_fails_closed_until_enabled_and_exact_table_present(self):
        n = network()
        expected = expected_ruleset((n,))
        adapter = FakeAdapter(expected)
        self.assertFalse(FirewallManager(adapter).ready((n,)))
        manager = FirewallManager(adapter, semantics_validated=True)
        self.assertTrue(manager.ready((n,)))
        if adapter.state is None:
            self.fail('Fake adapter state unexpectedly absent')
        drop_rule = next(rule for rule in adapter.state['tables']['inet']['rules']
                         if rule['expr'][-1] == {'drop': None})
        drop_rule['expr'][-1] = {'accept': None}
        self.assertFalse(manager.ready((n,)))
        self.assertFalse(manager.ready(()))

    def test_drift_in_table_chain_or_pair_never_reports_ready(self):
        n = network()
        expected = expected_ruleset((n,))
        manager = FirewallManager(FakeAdapter(expected), semantics_validated=True)
        for mutate in (
            lambda state: state['tables']['inet']['table'].update(name='other'),
            lambda state: state['tables']['inet']['chains'].pop(),
            lambda state: state['tables']['inet']['rules'].clear(),
        ):
            adapter = FakeAdapter(expected)
            manager = FirewallManager(adapter, semantics_validated=True)
            mutate(adapter.state)
            self.assertFalse(manager.ready((n,)))

    def test_network_contract_requires_explicit_disjoint_site_specific_slash29s(self):
        a = network('a')
        b = network('b', '198.51.100.0/29')
        self.assertEqual(len(validate_networks((a, b))), 2)
        with self.assertRaises(ValueError):
            validate_networks(())
        with self.assertRaises(ValueError):
            validate_networks((a, network('b', '192.0.2.0/29')))
        bad = NetworkPolicy
        with self.assertRaises(ValueError):
            bad('c' * 32, '192.0.2.0/28', '198.51.100.0/29',
                'bza' + 'c' * 12, 'bzf' + 'c' * 12,
                EndpointPair('192.0.2.2', '192.0.2.3'),
                EndpointPair('198.51.100.2', '198.51.100.3'))

    def test_partial_registration_replaces_whole_table_and_verifies_readback(self):
        a, b = network('a'), network('b', '198.51.100.0/29')
        adapter = FakeAdapter(expected_ruleset((a,)))
        manager = FirewallManager(adapter, semantics_validated=True)
        result = manager.register(b, (a,))
        self.assertEqual(result, expected_ruleset((a, b)))
        self.assertEqual(adapter.state, result)
        self.assertEqual(len(adapter.writes), 1)
        broken = FakeAdapter(corrupt_readback=True)
        with self.assertRaises(FirewallError):
            FirewallManager(broken, semantics_validated=True).register(a)

    def test_cleanup_removes_one_network_or_removes_empty_table_with_readback(self):
        a, b = network('a'), network('b', '198.51.100.0/29')
        adapter = FakeAdapter(expected_ruleset((a, b)))
        manager = FirewallManager(adapter, semantics_validated=True)
        result = manager.unregister(a.instance_id, (a, b))
        self.assertEqual(result, expected_ruleset((b,)))
        self.assertEqual(adapter.state, result)
        manager.unregister(b.instance_id, (b,))
        self.assertIsNone(adapter.state)
        self.assertEqual(adapter.writes[-1], None)

    def test_cleanup_readback_failure_is_reported(self):
        class Stubborn(FakeAdapter):
            def remove(self):
                self.writes.append(None)
                self.state = {'unexpected': True}
        with self.assertRaises(FirewallError):
            FirewallManager(Stubborn(), semantics_validated=True).unregister('a' * 32, (network(),))


if __name__ == '__main__':
    unittest.main()
