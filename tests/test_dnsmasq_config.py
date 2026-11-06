import subprocess
import unittest
from unittest.mock import patch

from ops.lab_dnsmasq import render_dnsmasq_config, validate_interface_address


class DnsmasqConfigTests(unittest.TestCase):
    def test_renders_parameterized_wildcard_with_lab_interface_and_upstreams(self):
        rendered = render_dnsmasq_config(
            domain='agents.example.test',
            proxy_ip='192.0.2.20',
            listen_address='192.0.2.53',
            interface='enp0s8',
            upstream_servers=('192.0.2.1', '2001:db8::53'),
        )

        self.assertIn('interface=enp0s8', rendered)
        self.assertIn('listen-address=192.0.2.53', rendered)
        self.assertIn('bind-interfaces', rendered)
        self.assertIn('except-interface=lo', rendered)
        self.assertNotIn('local-service', rendered)
        self.assertIn('no-dhcp-interface=enp0s8', rendered)
        self.assertIn('address=/agents.example.test/192.0.2.20', rendered)
        self.assertIn('no-resolv', rendered)
        self.assertIn('server=192.0.2.1', rendered)
        self.assertIn('server=2001:db8::53', rendered)
        self.assertNotIn('192.168.56.102', rendered)
        self.assertNotIn('agents.bezr.test', rendered)

    def test_rejects_domain_directives_and_malformed_dns_labels(self):
        for domain in ('agents.example.test\nserver=8.8.8.8', 'agents..example',
                       '-agents.example', 'agents.example-', 'agents.example.test.'):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                render_dnsmasq_config(
                    domain=domain, proxy_ip='192.0.2.20',
                    listen_address='192.0.2.53', interface='enp0s8',
                    upstream_servers=('192.0.2.1',),
                )

    def test_rejects_non_routable_addresses_and_unsafe_interface(self):
        invalid_cases = (
            {'proxy_ip': '0.0.0.0'},
            {'proxy_ip': '127.0.0.1'},
            {'proxy_ip': '255.255.255.255'},
            {'listen_address': '224.0.0.1'},
            {'interface': 'enp0s8\nlisten-address=0.0.0.0'},
        )
        for changes in invalid_cases:
            kwargs = {
                'domain': 'agents.example.test',
                'proxy_ip': '192.0.2.20',
                'listen_address': '192.0.2.53',
                'interface': 'enp0s8',
                'upstream_servers': ('192.0.2.1',),
            }
            kwargs.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                render_dnsmasq_config(**kwargs)

    def test_requires_explicit_upstream_and_rejects_invalid_entries(self):
        base = {
            'domain': 'agents.example.test',
            'proxy_ip': '192.0.2.20',
            'listen_address': '192.0.2.53',
            'interface': 'enp0s8',
        }
        for servers in ((), ('192.0.2.1\naddress=/evil.test/1.2.3.4',),
                        ('127.0.0.1',), ('0.0.0.0',)):
            with self.subTest(servers=servers), self.assertRaises(ValueError):
                render_dnsmasq_config(**base, upstream_servers=servers)


    @patch('ops.lab_dnsmasq.subprocess.run')
    def test_verifies_listen_address_is_on_the_selected_interface(self, run):
        run.return_value = type('Result', (), {
            'stdout': '2: enp0s8 inet 192.0.2.53/24 brd 192.0.2.255 scope global enp0s8',
        })()
        validate_interface_address('enp0s8', '192.0.2.53')
        run.assert_called_once_with(
            ['ip', '-o', '-4', 'address', 'show', 'dev', 'enp0s8'],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='ascii', timeout=5)

        run.reset_mock()
        run.return_value = type('Result', (), {
            'stdout': '2: enp0s8 inet 192.0.2.54/24 scope global enp0s8',
        })()
        with self.assertRaises(ValueError):
            validate_interface_address('enp0s8', '192.0.2.53')

    @patch('ops.lab_dnsmasq.subprocess.run')
    def test_fails_closed_if_interface_inspection_is_unavailable(self, run):
        run.side_effect = subprocess.CalledProcessError(1, ['ip'])

        with self.assertRaises(ValueError):
            validate_interface_address('enp0s8', '192.0.2.53')


if __name__ == '__main__':
    unittest.main()
