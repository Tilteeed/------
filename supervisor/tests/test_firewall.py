"""Synthetic adapter tests; never execute nft or privileged operations."""
import copy
import unittest

from supervisor.firewall import (
    EndpointPair, FirewallError, FirewallManager, NetworkPolicy,
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
            self.state['tables']['inet']['chains']['output']['rules'][0]['verdict'] = 'accept'

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


class FirewallPolicyTests(unittest.TestCase):
    def test_expected_policy_separates_host_and_routed_filters_from_bridge_forwarding(self):
        policy = network()
        expected = expected_ruleset((policy,))
        self.assertEqual(set(expected['tables']), {'inet', 'bridge'})
        inet = expected['tables']['inet']
        self.assertEqual(inet['chains']['input']['policy'], 'accept')
        self.assertEqual(inet['chains']['output']['policy'], 'accept')
        self.assertEqual(inet['chains']['forward']['policy'], 'accept')
        self.assertEqual(inet['chains']['forward']['rules'][0]['match'], 'exact-allowed-endpoint-pair')
        self.assertEqual(inet['chains']['forward']['rules'][-1]['verdict'], 'drop')
        bridge = expected['tables']['bridge']
        self.assertEqual(bridge['chains']['forward']['policy'], 'accept')
        self.assertEqual(bridge['chains']['forward']['rules'][0]['match'],
                         'exact-endpoint-pair-on-same-managed-bridge')
        self.assertNotIn('allowed_bridge_pairs', bridge['sets'])
        self.assertTrue(all(chain['policy'] == 'accept'
                            for chain in bridge['chains'].values()))

    def test_policy_models_separate_agent_and_frontend_networks_and_pairs(self):
        ident = 'c' * 32
        policy = NetworkPolicy(
            instance_id=ident, agent_subnet='10.240.0.0/29',
            frontend_subnet='10.248.0.0/29',
            agent_bridge='bza' + ident[:12], frontend_bridge='bzf' + ident[:12],
            agent_pair=EndpointPair('10.240.0.2', '10.240.0.3'),
            frontend_pair=EndpointPair('10.248.0.2', '10.248.0.3'))
        rules = expected_ruleset((policy,))
        self.assertEqual(rules['tables']['inet']['sets']['managed_subnets4'],
                         ['10.240.0.0/29', '10.248.0.0/29'])
        self.assertEqual(rules['tables']['inet']['sets']['allowed_endpoint_pairs4'], [
            ['10.240.0.2', '10.240.0.3'], ['10.240.0.3', '10.240.0.2'],
            ['10.248.0.2', '10.248.0.3'], ['10.248.0.3', '10.248.0.2']])
        self.assertEqual(rules['tables']['bridge']['sets']['allowed_bridge_endpoint_pairs'], [
            ['bza' + ident[:12], '10.240.0.2', '10.240.0.3'],
            ['bza' + ident[:12], '10.240.0.3', '10.240.0.2'],
            ['bzf' + ident[:12], '10.248.0.2', '10.248.0.3'],
            ['bzf' + ident[:12], '10.248.0.3', '10.248.0.2']])

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
        adapter.state['tables']['inet']['chains']['input']['rules'][0]['verdict'] = 'accept'
        self.assertFalse(manager.ready((n,)))
        self.assertFalse(manager.ready(()))

    def test_drift_in_table_chain_or_pair_never_reports_ready(self):
        n = network()
        expected = expected_ruleset((n,))
        manager = FirewallManager(FakeAdapter(expected), semantics_validated=True)
        for mutate in (
            lambda s: s['tables']['inet'].update(name='other'),
            lambda s: s['tables']['inet']['chains'].pop('forward'),
            lambda s: s['tables']['inet']['sets']['allowed_endpoint_pairs4'].clear(),
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
            FirewallManager(broken).register(a)

    def test_cleanup_removes_one_network_or_removes_empty_table_with_readback(self):
        a, b = network('a'), network('b', '198.51.100.0/29')
        adapter = FakeAdapter(expected_ruleset((a, b)))
        manager = FirewallManager(adapter)
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
            FirewallManager(Stubborn()).unregister('a' * 32, (network(),))


if __name__ == '__main__':
    unittest.main()
