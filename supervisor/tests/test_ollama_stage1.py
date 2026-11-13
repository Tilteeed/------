"""Portable Stage 1 regressions. Synthetic packets are NOT kernel evidence."""
import copy
import unittest
from supervisor.tests.test_ollama_firewall import route
from supervisor.firewall import NftablesAdapter
from supervisor.ollama_firewall import expected_ollama_ruleset


def verdict(rules, chain, packet):
    """Explicit small matcher: unknown/missing packet fields never match."""
    for rule in rules:
        if rule['chain'] != chain:
            continue
        for expr in rule['expr']:
            if 'match' in expr:
                match = expr['match']
                left = match['left']
                if 'meta' in left:
                    key = ('meta', left['meta']['key'])
                else:
                    key = (left['payload']['protocol'], left['payload']['field'])
                if key not in packet or packet[key] != match['right']:
                    break
            else:
                return next(iter(expr))
    return 'accept'


class ColdARPTests(unittest.TestCase):
    def test_arp_readback_drift_cannot_open_manager_gate(self):
        from supervisor.tests.test_ollama_firewall import FakeAdapter
        from supervisor.ollama_firewall import OllamaFirewallManager, OllamaFirewallError
        policy = route()
        desired = expected_ollama_ruleset((policy,))
        arp_index = next(i for i, rule in enumerate(desired['tables']['bridge']['rules'])
                         if 'bridge arp input request' in rule['comment'])
        for expression in range(5):
            adapter = FakeAdapter(copy.deepcopy(desired))
            manager = OllamaFirewallManager(adapter, semantics_validated=True)
            self.assertTrue(manager.ready((policy,)))
            adapter.state['tables']['bridge']['rules'][arp_index]['expr'].pop(expression)
            self.assertFalse(manager.ready((policy,)))
        class DroppedARPField(FakeAdapter):
            def replace(self, ruleset):
                self.state = copy.deepcopy(ruleset)
                self.state['tables']['bridge']['rules'][arp_index]['expr'].pop(1)
        with self.assertRaises(OllamaFirewallError):
            OllamaFirewallManager(DroppedARPField(), semantics_validated=True).apply((policy,))

    def test_production_adapter_renders_and_strictly_reads_arp(self):
        import json
        from supervisor.ollama_firewall import TABLE_NAME
        adapter = NftablesAdapter(table_name=TABLE_NAME)
        desired = expected_ollama_ruleset((route(),))
        batch = adapter._render_batch(desired, {'inet': None, 'bridge': None})
        self.assertIn('ether type == arp arp saddr ip == 10.98.0.2 arp daddr ip == 10.98.0.1 arp operation == request', batch)
        for family, table in desired['tables'].items():
            # Explicit synthetic JSON round-trip; no inferred live nft output.
            raw = {'nftables': [
                {'table': {**table['table'], 'handle': 1}},
                *({'chain': {**chain, 'handle': index + 2}}
                  for index, chain in enumerate(table['chains'])),
                *({'rule': {**rule, 'handle': index + 100}}
                  for index, rule in enumerate(table['rules'])),
            ]}
            observed, _ = adapter._normalise_table(json.dumps(raw), family)
            self.assertEqual(observed['tables'][family], table)
        for field, right in (('saddr ip', '10.98.0.0/29'), ('saddr ip', 'not-ip'),
                             ('daddr ip', '::1'), ('operation', 'rrequest'),
                             ('operation', 1), ('saddr ether', '00:00:00:00:00:00')):
            with self.subTest(field=field, right=right), self.assertRaises(ValueError):
                adapter._render_expr({'match': {'left': {'payload': {'protocol': 'arp', 'field': field}},
                                               'op': '==', 'right': right}})

    def test_only_gateway_bridge_gateway_arp_request_reply_are_allowed(self):
        first, second = route(), route('b'*32, '10.98.0.8/29')
        rules = expected_ollama_ruleset((first, second))['tables']['bridge']['rules']
        for policy in (first, second):
            for chain, interface, source, target in (
                ('input', 'ibrname', policy.gateway_ip, policy.gateway),
                ('output', 'obrname', policy.gateway, policy.gateway_ip),
            ):
                for operation in ('request', 'reply'):
                    packet = {('meta', interface): policy.bridge, ('ether', 'type'): 'arp',
                              ('arp', 'saddr ip'): source, ('arp', 'daddr ip'): target,
                              ('arp', 'operation'): operation}
                    with self.subTest(chain=chain, operation=operation, instance=policy.instance_id):
                        self.assertEqual(verdict(rules, chain, packet), 'accept')
                    for key, bad in ((('meta', interface), second.bridge if policy is first else first.bridge),
                                     (('arp', 'saddr ip'), '10.98.0.3'),
                                     (('arp', 'daddr ip'), second.gateway if policy is first else first.gateway),
                                     (('arp', 'operation'), 'rrequest'),
                                     (('ether', 'type'), 'ip')):
                        self.assertEqual(verdict(rules, chain, {**packet, key: bad}), 'drop')
                    # No ARP forward exemption, even for an otherwise valid pair.
                    forwarded = {**packet, ('meta', 'ibrname'): policy.bridge,
                                 ('meta', 'obrname'): policy.bridge}
                    self.assertEqual(verdict(rules, 'forward', forwarded), 'drop')
        arp = [r for r in rules if any(e.get('match', {}).get('left') ==
               {'payload': {'protocol': 'arp', 'field': 'operation'}} for e in r['expr'])]
        self.assertEqual(len(arp), 8)
        # Every ARP allow is fully pinned, with no subnet/blanket exemption.
        for rule in arp:
            self.assertEqual(len(rule['expr']), 6)


class TopologyLabTests(unittest.TestCase):
    def lab(self):
        from scripts.ollama_route_linux import Lab
        from scripts.ollama_route_acceptance import binding
        from types import SimpleNamespace
        from unittest.mock import Mock
        lab = object.__new__(Lab)
        lab.config = binding('10.240.0.0/13', '10.248.0.0/13', '172.20.0.0/16',
                             '192.168.40.10', 'ens18', 'a'*64)
        lab.args = SimpleNamespace(endpoint='192.168.40.10', interface='ens18', run_id='b'*32)
        lab.guard = Mock()
        lab.ns = lambda role, argv: [role, *argv]
        lab.topology = 'routed'
        lab.endpoint_on_router = False
        return lab

    def test_lab_moves_endpoint_to_router_and_verifies_live_placement(self):
        import json
        lab = self.lab()
        calls = []
        endpoint = lab.args.endpoint
        state = {'local': False, 'remote': True}
        def run(argv, **kwargs):
            calls.append(argv)
            if argv == ['ip', 'route', 'delete', endpoint+'/32', 'via', '169.254.254.2', 'dev', 'ens18']:
                return ''
            if argv == ['target', 'ip', 'address', 'delete', endpoint+'/32', 'dev', 'bzrtarget']:
                state['remote'] = False
                return ''
            if argv == ['ip', 'address', 'add', endpoint+'/32', 'dev', 'lo']:
                state['local'] = True
                return ''
            if argv in (['ip', '-j', '-4', 'address', 'show'], ['target', 'ip', '-j', '-4', 'address', 'show']):
                local = argv[0] != 'target'
                present = state['local'] if local else state['remote']
                return json.dumps([dict(ifname='lo' if local else 'bzrtarget',
                    addr_info=[dict(family='inet', local=endpoint, prefixlen=32)] if present else [])])
            if argv == ['ip', '-j', '-4', 'route', 'get', endpoint]:
                return json.dumps([dict(dst=endpoint, dev='lo', type='local')] if state['local'] else
                                  [dict(dst=endpoint, dev='ens18', gateway='169.254.254.2')])
            self.fail('Unexpected command: '+repr(argv))
        lab.run = run
        routed = lab.set_topology('routed')
        local = lab.set_topology('host-local')
        self.assertEqual(routed['endpoint_namespace'], 'target')
        self.assertEqual(local['endpoint_namespace'], 'router')
        self.assertEqual(local['route_type'], 'local')
        self.assertFalse(state['remote'])
        self.assertTrue(state['local'])
        self.assertTrue(lab.endpoint_on_router)
        lab.guard.assert_called()
        self.assertFalse(any('neigh' in argv for argv in calls))

    def test_unsolicited_host_local_probe_runs_in_router_not_remote_namespace(self):
        from unittest.mock import Mock
        from scripts.ollama_route_linux import CLIENT
        import sys
        for docker in (False, True):
            lab = self.lab()
            lab.docker = docker
            lab.topology = 'host-local'
            lab.dc = Mock(return_value='HTTP_OK')
            lab.run = Mock(return_value='HTTP_OK')
            spec = dict(source='target', destination='172.20.0.2', port=11434, topology='host-local')
            self.assertTrue(lab.transaction(spec))
            argv = lab.run.call_args.args[0]
            self.assertEqual(argv, [sys.executable, '-c', CLIENT, '172.20.0.2', '11434',
                                    'b'*32, '192.168.40.10'])
            lab.dc.assert_not_called()
            lab.topology = 'routed'
            spec['topology'] = 'routed'
            self.assertTrue(lab.transaction(spec))
            self.assertEqual(lab.run.call_args.args[0][0], 'target')

    def test_cleanup_removes_router_endpoint_and_rejects_address_leftover(self):
        import json
        from unittest.mock import Mock
        for leftover in (False, True):
            lab = self.lab()
            lab.endpoint_on_router = True
            lab.daemon = None
            lab.containers = lab.networks = lab.processes = lab.links = []
            lab.temp = None
            lab.set_policy = Mock()
            lab.adapter = Mock()
            lab.proxy_adapter = Mock()
            lab.adapter.read.return_value = lab.proxy_adapter.read.return_value = None
            calls = []
            def run(argv, **kwargs):
                calls.append(argv)
                if argv == ['ip', 'address', 'delete', lab.args.endpoint+'/32', 'dev', 'lo']:
                    return ''
                if argv == ['ip', '-j', '-4', 'address', 'show', 'dev', 'lo']:
                    return json.dumps([dict(ifname='lo', addr_info=[dict(local=lab.args.endpoint)] if leftover else [])])
                if argv == ['ip', '-j', 'link', 'show']:
                    return '[{"ifname":"lo"}]'
                self.fail('Unexpected cleanup command '+repr(argv))
            lab.run = run
            if leftover:
                with self.assertRaises(RuntimeError):
                    lab.cleanup()
            else:
                lab.cleanup()
            self.assertIn(['ip', 'address', 'delete', lab.args.endpoint+'/32', 'dev', 'lo'], calls)

    def test_topology_readback_rejects_a_routed_endpoint_mislabeled_local(self):
        import json
        lab = self.lab()
        lab.topology = 'host-local'
        lab.run = lambda *args, **kwargs: json.dumps([])
        with self.assertRaisesRegex(RuntimeError, 'topology'):
            lab.set_topology('host-local')


if __name__ == '__main__':
    unittest.main()
