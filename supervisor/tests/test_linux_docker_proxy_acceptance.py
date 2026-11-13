"""Synthetic portable regressions for shared argv and public disposable gates.

The removed host-daemon _network_create helper must not be restored for tests.
No Docker, namespace, firewall or host acceptance is performed here.
"""
import contextlib
from copy import deepcopy
import io
import itertools
import unittest
from unittest.mock import patch

from scripts import linux_docker_proxy_acceptance as acceptance
from scripts import proxy_acceptance_linux as private
from scripts.ollama_route_acceptance import network_argv
from scripts.ollama_route_linux import verify_network_readback


class SyntheticDockerAcceptanceNetworkTests(unittest.TestCase):
    def payload(self):
        return {
            'Name': 'pa-agent-' + 'a' * 32, 'Driver': 'bridge',
            'Internal': True, 'Attachable': False, 'EnableIPv6': False,
            'Options': {
                'com.docker.network.bridge.name': 'bza' + 'a' * 12,
                'com.docker.network.bridge.enable_ip_masquerade': 'false',
                'com.docker.network.bridge.enable_icc': 'true',
            },
            'Labels': {'io.bezr.managed': 'true', 'io.bezr.instance': 'a' * 32},
            'IPAM': {'Driver': 'default', 'Config': [
                {'Subnet': '10.246.0.0/29', 'Gateway': '10.246.0.1'}]},
        }

    def test_network_create_passes_all_payload_options_and_labels(self):
        payload = self.payload()
        untouched = deepcopy(payload)
        argv = network_argv(payload)
        self.assertEqual(argv[:10], ['network', 'create', '--driver', 'bridge',
                                    '--ipam-driver', 'default', '--subnet', '10.246.0.0/29',
                                    '--gateway', '10.246.0.1'])
        for flag, key in (('--opt', 'Options'), ('--label', 'Labels')):
            sent = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == flag]
            self.assertEqual(sent, [f'{k}={v}' for k, v in sorted(payload[key].items())])
        self.assertEqual(argv[-1], payload['Name'])
        self.assertEqual(payload, untouched)
        self.assertIn('--internal', argv)
        self.assertNotIn('--attachable', argv)
        self.assertNotIn('--ipv6', argv)

    def test_network_boolean_flags_preserve_every_payload_combination(self):
        for values in itertools.product((False, True), repeat=3):
            with self.subTest(values=values):
                payload = self.payload()
                keys = ('Internal', 'Attachable', 'EnableIPv6')
                payload.update(zip(keys, values))
                argv = network_argv(payload)
                for key, flag in zip(keys, ('--internal', '--attachable', '--ipv6')):
                    self.assertEqual(argv.count(flag), int(payload[key]))

    def test_private_network_readback_keeps_identity_options_and_labels_strict(self):
        payload = self.payload()
        observed = dict(deepcopy(payload), Id='synthetic-network-id')
        verify_network_readback(observed, 'synthetic-network-id', payload)
        for key in ('Id', 'Name', 'Driver', 'Options', 'Labels', 'IPAM', 'Internal'):
            with self.subTest(key=key):
                bad = deepcopy(observed)
                bad[key] = 'drift'
                with self.assertRaises(RuntimeError):
                    verify_network_readback(bad, 'synthetic-network-id', payload)

    def test_public_wrapper_refuses_missing_disposable_approval_before_launch(self):
        base = ['--agent-pool', '10.240.0.0/13', '--frontend-pool', '10.248.0.0/13',
                '--probe-image', 'sha256:' + 'a' * 64, '--image-archive', '/synthetic.tar']
        for flags in ([], ['--execute'], ['--confirm-disposable-host'],
                      ['--execute', '--confirm-busy-host']):
            with self.subTest(flags=flags):
                self.refused(base + flags)

    def test_public_wrapper_refuses_missing_archive_or_report_skip_internal_flags(self):
        base = ['--agent-pool', '10.240.0.0/13', '--frontend-pool', '10.248.0.0/13',
                '--probe-image', 'sha256:' + 'a' * 64, '--execute', '--confirm-disposable-host']
        self.refused(base)
        for flags in (['--report', '/synthetic.json'], ['--skip-checks'],
                      ['--parent-netns-fd', '3'], ['--confirm-busy-host']):
            with self.subTest(flags=flags):
                self.refused(base + ['--image-archive', '/synthetic.tar', *flags])

    def refused(self, argv):
        with (patch.object(private.sys, 'platform', 'linux'),
              patch.object(private.os, 'geteuid', return_value=0, create=True),
              patch.object(private.transport, 'prerequisites') as prerequisites,
              patch.object(private.transport, 'command') as command,
              contextlib.redirect_stderr(io.StringIO()),
              self.assertRaises(SystemExit) as error):
            acceptance.main(argv)
        self.assertEqual(error.exception.code, 2)
        prerequisites.assert_not_called()
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
