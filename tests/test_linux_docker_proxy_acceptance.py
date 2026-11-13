"""Unit tests for the disposable Docker acceptance harness."""
import unittest
from scripts.ollama_route_acceptance import network_argv
from scripts.ollama_route_linux import verify_network_readback


class DockerAcceptanceNetworkTests(unittest.TestCase):
    def test_network_create_passes_all_payload_options_and_labels(self):
        name = 'pa-agent-' + 'a' * 32
        options = {
            'com.docker.network.bridge.name': 'bza' + 'a' * 12,
            'com.docker.network.bridge.enable_ip_masquerade': 'false',
            'com.docker.network.bridge.enable_icc': 'true',
        }
        labels = {'io.bezr.managed': 'true', 'io.bezr.instance': 'a' * 32}
        ipam = {'Subnet': '10.246.0.0/29', 'Gateway': '10.246.0.1'}
        payload = {
            'Name': name,
            'Options': options,
            'Labels': labels,
            'Driver': 'bridge', 'Internal': True, 'EnableIPv6': False, 'Attachable': False,
            'IPAM': {'Driver': 'default', 'Config': [ipam]},
        }
        observed = dict(payload, Id='network-id')
        # Exercise the actual private-daemon builder/readback, not the removed
        # caller-Docker mutation helper. This remains synthetic evidence.
        argv = network_argv(payload)
        verify_network_readback(observed, 'network-id', payload)
        options_sent = [argv[index + 1] for index, arg in enumerate(argv[:-1])
                        if arg == '--opt']
        labels_sent = [argv[index + 1] for index, arg in enumerate(argv[:-1])
                       if arg == '--label']
        self.assertEqual(options_sent,
                         [f'{key}={value}' for key, value in sorted(options.items())])
        self.assertEqual(labels_sent,
                         [f'{key}={value}' for key, value in sorted(labels.items())])
        self.assertEqual(argv[-1], name)
        self.assertIn('--internal', argv)
        self.assertEqual(argv[argv.index('--subnet') + 1], ipam['Subnet'])
        self.assertEqual(argv[argv.index('--gateway') + 1], ipam['Gateway'])


if __name__ == '__main__':
    unittest.main()
