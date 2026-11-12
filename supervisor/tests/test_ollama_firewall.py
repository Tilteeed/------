import ipaddress
import unittest


class FakeAdapter:
    def __init__(self, state=None):
        self.state = state
        self.writes = []

    def read(self) -> object:
        return self.state

    def replace(self, ruleset: object) -> None:
        self.writes.append(ruleset)
        self.state = ruleset

    def remove(self) -> None:
        self.writes.append(None)
        self.state = None


def route(instance_id='a' * 32, subnet='10.98.0.0/29',
          ollama_ip='172.16.5.20', egress_interface='ens18'):
    from supervisor.ollama_firewall import OllamaRoutePolicy
    network = ipaddress.IPv4Network(subnet, strict=True)
    return OllamaRoutePolicy(
        instance_id=instance_id,
        subnet=subnet,
        gateway=str(network.network_address + 1),
        gateway_ip=str(network.network_address + 2),
        ollama_ip=ollama_ip,
        egress_interface=egress_interface,
    )


class OllamaFirewallPolicyTests(unittest.TestCase):
    def test_route_policy_rejects_non_rfc1918_target_and_inconsistent_network_identity(self):
        from supervisor.ollama_firewall import OllamaRoutePolicy

        for kwargs in (
            {'ollama_ip': '8.8.8.8'},
            {'ollama_ip': '127.0.0.1'},
            {'ollama_ip': '169.254.1.1'},
            {'gateway': '10.98.0.3'},
            {'gateway_ip': '10.98.0.3'},
            {'subnet': '10.98.0.0/28'},
            {'egress_interface': 'ens18;flush ruleset'},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                values = {
                    'instance_id': 'a' * 32,
                    'subnet': '10.98.0.0/29',
                    'gateway': '10.98.0.1',
                    'gateway_ip': '10.98.0.2',
                    'ollama_ip': '172.16.5.20',
                    'egress_interface': 'ens18',
                }
                values.update(kwargs)
                OllamaRoutePolicy(**values)

    def test_rules_allow_only_selected_instance_endpoint_and_tcp_port(self):
        from supervisor.ollama_firewall import expected_ollama_ruleset

        first = route()
        second = route(instance_id='b' * 32, subnet='10.98.0.8/29',
                       ollama_ip='192.168.40.12', egress_interface='enp3s0')
        ruleset = expected_ollama_ruleset((first, second))
        inet_rules = ruleset['tables']['inet']['rules']
        bridge_rules = ruleset['tables']['bridge']['rules']

        self.assertIn('172.16.5.20', str(inet_rules))
        self.assertIn('192.168.40.12', str(inet_rules))
        self.assertIn('ens18', str(inet_rules))
        self.assertIn('enp3s0', str(inet_rules))
        self.assertIn('11434', str(inet_rules))
        self.assertNotIn('8.8.8.8', str(inet_rules))
        self.assertTrue(any('ollama outbound' in item['comment'] for item in inet_rules))
        self.assertTrue(any('ollama established return' in item['comment'] for item in inet_rules))
        self.assertTrue(any('bridge input deny' in item['comment'] for item in bridge_rules))
        self.assertTrue(any('bridge egress deny' in item['comment'] for item in bridge_rules))

    def test_canonical_manifest_matches_adapter_chain_order_without_reordering_a_chain(self):
        # Synthetic nft JSON shape, not a kernel capture or live acceptance.
        import json
        from supervisor.firewall import NftablesAdapter
        from supervisor.ollama_firewall import TABLE_NAME, TABLE_COMMENT, expected_ollama_ruleset
        adapter = NftablesAdapter(table_name=TABLE_NAME, table_comment=TABLE_COMMENT)
        desired = expected_ollama_ruleset((route(), route('b'*32, '10.98.0.8/29')))
        for family, table in desired['tables'].items():
            raw = {'nftables': [{'table': {**table['table'], 'handle': 1}},
                *({'chain': {**chain, 'handle': index + 2}}
                  for index, chain in enumerate(table['chains'])),
                *({'rule': {**rule, 'handle': index + 20}}
                  for index, rule in enumerate(table['rules']))]}
            normalized, handle = adapter._normalise_table(json.dumps(raw), family)
            self.assertEqual(handle, 1)
            self.assertEqual(normalized['tables'][family], table)
            for chain in table['chains']:
                rules = [r for r in table['rules'] if r['chain'] == chain['name']]
                denied = False
                for rule in rules:
                    if 'drop' in rule['expr'][-1]:
                        denied = True
                    elif 'accept' in rule['expr'][-1]:
                        self.assertFalse(denied, 'Stable chain grouping must preserve allow-before-deny')

    def test_ollama_ruleset_uses_separate_owned_table_and_renders_tcp_scope(self):
        from supervisor.firewall import NftablesAdapter
        from supervisor.ollama_firewall import (
            TABLE_COMMENT, TABLE_NAME, expected_ollama_ruleset,
        )

        adapter = NftablesAdapter(
            nft_binary='nft-test', table_name=TABLE_NAME, table_comment=TABLE_COMMENT)
        rendered = adapter._render_batch(
            expected_ollama_ruleset((route(),)), {'inet': None, 'bridge': None})

        self.assertIn('create table inet agent_ollama_v1', rendered)
        self.assertIn('tcp dport == 11434', rendered)
        self.assertIn('tcp sport == 11434', rendered)
        self.assertIn('ct state == established', rendered)
        self.assertIn('meta oifname == ens18', rendered)

    def test_network_settings_require_a_disjoint_private_pool_and_exact_interface(self):
        from supervisor.ollama_firewall import validate_ollama_route_inputs

        self.assertEqual(
            validate_ollama_route_inputs(
                '172.20.0.0/16', 'ens18', '10.99.0.10',
                protected_pools=('10.240.0.0/13', '10.248.0.0/13')),
            ('172.20.0.0/16', 'ens18'),
        )
        for pool, interface, endpoint, protected in (
            ('10.240.0.0/13', 'ens18', '10.99.0.10', ('10.240.0.0/13', '10.248.0.0/13')),
            ('172.20.0.0/16', 'ens18', '172.20.0.10', ()),
            ('192.0.2.0/24', 'ens18', '10.99.0.10', ()),
            ('172.20.0.0/25', 'ens18', '10.99.0.10', ()),
            ('172.20.0.0/16', 'ens18;flush', '10.99.0.10', ()),
        ):
            with self.subTest(pool=pool, interface=interface), self.assertRaises(ValueError):
                validate_ollama_route_inputs(
                    pool, interface, endpoint, protected_pools=protected)

    def test_acceptance_receipt_binds_host_endpoint_interface_and_all_pools(self):
        from supervisor.ollama_firewall import (
            build_ollama_route_receipt, ollama_route_receipt_matches,
        )

        receipt = build_ollama_route_receipt(
            'a' * 64, '10.240.0.0/13', '10.248.0.0/13',
            '172.20.0.0/16', '10.99.0.10', 'ens18', accepted_at_unix=123)
        self.assertTrue(ollama_route_receipt_matches(
            receipt, 'a' * 64, '10.240.0.0/13', '10.248.0.0/13',
            '172.20.0.0/16', '10.99.0.10', 'ens18'))
        self.assertFalse(ollama_route_receipt_matches(
            receipt, 'a' * 64, '10.240.0.0/13', '10.248.0.0/13',
            '172.20.0.0/16', '10.99.0.11', 'ens18'))
        self.assertFalse(ollama_route_receipt_matches(
            receipt, 'a' * 64, '10.240.0.0/13', '10.248.0.0/13',
            '172.20.0.0/16', '10.99.0.10', 'ens19'))

    def test_written_receipt_is_valid_json(self):
        import json
        import tempfile
        from unittest.mock import patch
        from supervisor import ollama_firewall as firewall

        payload = bytearray()
        with tempfile.TemporaryDirectory() as state_dir:
            with patch.object(firewall, 'machine_id_sha256', return_value='a' * 64), \
                 patch.object(firewall, '_open_state_directory', return_value=100), \
                 patch.object(firewall.os, 'open', return_value=101), \
                 patch.object(firewall.os, 'fchown', create=True), \
                 patch.object(firewall.os, 'fchmod', create=True), \
                 patch.object(firewall.os, 'write', side_effect=lambda fd, data: payload.extend(data) or len(data)), \
                 patch.object(firewall.os, 'fsync'), \
                 patch.object(firewall.os, 'close'), \
                 patch.object(firewall.os, 'replace'):
                receipt = firewall.write_ollama_route_receipt(
                    state_dir, '10.240.0.0/13', '10.248.0.0/13',
                    '172.20.0.0/16', '10.99.0.10', 'ens18')

        self.assertEqual(json.loads(payload.decode('utf-8')), receipt)
        self.assertTrue(payload.endswith(b'\n'))

    def test_route_firewall_removes_the_owned_table_after_last_route_is_purged(self):
        from supervisor.ollama_firewall import (
            OllamaFirewallManager, expected_ollama_ruleset,
        )

        policy = route()
        adapter = FakeAdapter(expected_ollama_ruleset((policy,)))
        firewall = OllamaFirewallManager(adapter, semantics_validated=True)

        firewall.apply(())

        self.assertEqual(adapter.writes, [None])
        self.assertIsNone(adapter.state)
        self.assertTrue(firewall.ready(()))

    def test_route_firewall_requires_its_own_acceptance_gate(self):
        from supervisor.ollama_firewall import (
            OllamaFirewallError, OllamaFirewallManager, expected_ollama_ruleset,
        )

        policy = route()
        adapter = FakeAdapter(expected_ollama_ruleset((policy,)))
        blocked = OllamaFirewallManager(adapter, semantics_validated=False)
        self.assertFalse(blocked.ready((policy,)))
        with self.assertRaises(OllamaFirewallError):
            blocked.apply((policy,))
        self.assertEqual(adapter.writes, [])

        accepted_adapter = FakeAdapter()
        accepted = OllamaFirewallManager(accepted_adapter, semantics_validated=True)
        accepted.apply((policy,))
        self.assertTrue(accepted.ready((policy,)))
        self.assertEqual(len(accepted_adapter.writes), 1)


if __name__ == '__main__':
    unittest.main()
