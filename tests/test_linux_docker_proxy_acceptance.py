"""Unit tests for the disposable Docker acceptance harness."""
import unittest
from unittest.mock import patch

from scripts import linux_docker_proxy_acceptance as acceptance


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
            'IPAM': {'Config': [ipam]},
        }
        observed = {
            'Id': 'network-id', 'Name': name, 'Driver': 'bridge',
            'Internal': True, 'EnableIPv6': False, 'Options': options,
            'Labels': labels, 'IPAM': {'Config': [ipam]},
        }
        resources = {'networks': []}
        with patch.object(acceptance, '_run', return_value='network-id') as run, \
                patch.object(acceptance, '_docker_json', return_value=[observed]):
            result = acceptance._network_create(payload, resources)

        argv = run.call_args.args[0]
        options_sent = [argv[index + 1] for index, arg in enumerate(argv[:-1])
                        if arg == '--opt']
        labels_sent = [argv[index + 1] for index, arg in enumerate(argv[:-1])
                       if arg == '--label']
        self.assertEqual(options_sent,
                         [f'{key}={value}' for key, value in sorted(options.items())])
        self.assertEqual(labels_sent,
                         [f'{key}={value}' for key, value in sorted(labels.items())])
        self.assertEqual(result, ('network-id', name))
        self.assertEqual(resources['networks'], ['network-id'])


if __name__ == '__main__':
    unittest.main()
