import unittest

from supervisor.network_routes import (
    HostRouteInventoryError, parse_ipv4_networks, read_host_ipv4_networks,
)


class HostRouteInventoryTests(unittest.TestCase):
    def test_parser_collects_route_and_interface_prefixes_but_ignores_default(self):
        routes = [
            {'dst': 'default', 'gateway': '192.0.2.1', 'dev': 'eth0'},
            {'dst': '10.20.0.0/16', 'dev': 'vboxnet0'},
            {'dst': '10.8.0.0/24', 'dev': 'tun0'},
            {'dst': '192.168.56.0/24', 'dev': 'vboxnet1'},
            {'dst': '172.29.4.8', 'type': 'local', 'dev': 'lo'},
        ]
        addresses = [
            {'ifname': 'lo', 'addr_info': [
                {'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8}]},
            {'ifname': 'eth0', 'addr_info': [
                {'family': 'inet', 'local': '192.168.1.9', 'prefixlen': 24}]},
            {'ifname': 'tun0', 'addr_info': [
                {'family': 'inet', 'local': '10.8.0.3', 'prefixlen': 24}]},
        ]
        self.assertEqual(parse_ipv4_networks(routes, addresses), (
            '10.8.0.0/24', '10.20.0.0/16', '127.0.0.0/8',
            '172.29.4.8/32', '192.168.1.0/24', '192.168.56.0/24',
        ))

    def test_parser_rejects_malformed_or_oversized_inventory(self):
        with self.assertRaises(HostRouteInventoryError):
            parse_ipv4_networks([{'dst': 'not-a-cidr'}], [])
        with self.assertRaises(HostRouteInventoryError):
            parse_ipv4_networks([{'dst': '10.0.0.0/8'}] * 4097, [])

    def test_read_uses_fixed_read_only_iproute_commands(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            if 'route' in argv:
                return '[{"dst":"10.90.0.0/16"}]'
            return '[{"ifname":"test0","addr_info":[{"family":"inet","local":"10.1.2.3","prefixlen":24}]}]'
        self.assertEqual(read_host_ipv4_networks(runner), ('10.1.2.0/24', '10.90.0.0/16'))
        self.assertEqual([call[0] for call in calls], [
            ['ip', '-j', '-4', 'route', 'show', 'table', 'all'],
            ['ip', '-j', '-4', 'address', 'show'],
        ])
        self.assertTrue(all(call[1]['timeout'] <= 10 and call[1]['max_output_bytes'] <= 65536
                            for call in calls))


if __name__ == '__main__':
    unittest.main()
