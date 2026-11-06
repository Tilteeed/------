import unittest
from urllib.parse import quote

from supervisor.docker_engine import DockerEngine, DockerEngineError


class ControlPlaneProxyTrustTests(unittest.TestCase):
    def setUp(self):
        self.engine = DockerEngine('sha256:' + 'a' * 64)
        self.container_id = 'b' * 64
        self.image_id = 'sha256:' + 'c' * 64
        self.network_id = 'd' * 64
        self.gateway = '172.30.0.1'
        self.project = 'personal-agent-platform'
        self.domain = 'agents.example.test'
        self.container = {
            'Id': self.container_id,
            'Image': self.image_id,
            'State': {'Running': True, 'Status': 'running'},
            'Config': {
                'Labels': {
                    self.engine.CONTROL_PLANE_LABEL: 'true',
                    'com.docker.compose.project': self.project,
                },
                'Env': [
                    'AGENT_CONTROL_UI_DOMAIN=' + self.domain,
                    'FORWARDED_ALLOW_IPS=127.0.0.1,' + self.gateway,
                ],
            },
            'NetworkSettings': {'Networks': {
                self.project + '_web': {
                    'NetworkID': self.network_id,
                    'Gateway': self.gateway,
                    'IPAddress': '172.30.0.2',
                },
            }},
        }
        self.network = {
            'Id': self.network_id,
            'Name': self.project + '_web',
            'Driver': 'bridge',
            'Internal': False,
            'EnableIPv6': False,
            'Labels': {
                'com.docker.compose.project': self.project,
                'com.docker.compose.network': 'web',
            },
            'IPAM': {'Config': [{'Subnet': '172.30.0.0/24', 'Gateway': self.gateway}]},
        }
        self.image = {'Id': self.image_id, 'Config': {'Env': []}}

    def _request(self, method, path, *args, **kwargs):
        if path.startswith('/containers/json?'):
            return [{'Id': self.container_id}]
        if path == '/containers/' + self.container_id + '/json':
            return self.container
        if path == '/networks/' + self.network_id:
            return self.network
        if path == '/images/' + quote(self.image_id, safe='') + '/json':
            return self.image
        raise AssertionError('Unexpected Docker API path')

    def test_finds_web_only_when_actual_compose_gateway_is_trusted(self):
        self.engine._request = self._request

        found = self.engine._find_control_plane_web(self.domain)

        self.assertEqual(found['container_id'], self.container_id)
        self.assertEqual(found['image_id'], self.image_id)
        self.assertEqual(found['docker_gateway'], self.gateway)
        self.engine._verify_control_plane_forwarded_trust(found)

    def test_rejects_forwarded_allowlist_without_actual_gateway(self):
        self.container['Config']['Env'][1] = 'FORWARDED_ALLOW_IPS=127.0.0.1'
        self.engine._request = self._request
        found = self.engine._find_control_plane_web(self.domain)

        with self.assertRaises(DockerEngineError):
            self.engine._verify_control_plane_forwarded_trust(found)

    def test_rejects_wildcard_cidr_and_duplicate_forwarded_trust_entries(self):
        for allowlist in ('*', '0.0.0.0/0', '255.255.255.255,' + self.gateway,
                          self.gateway + ',' + self.gateway,
                          self.gateway + ',', self.gateway + ', 127.0.0.1',
                          self.gateway + ',,127.0.0.1',
                          self.gateway + ',2001:0DB8::1'):
            with self.subTest(allowlist=allowlist):
                self.container['Config']['Env'][1] = 'FORWARDED_ALLOW_IPS=' + allowlist
                self.engine._request = self._request
                found = self.engine._find_control_plane_web(self.domain)
                with self.assertRaises(DockerEngineError):
                    self.engine._verify_control_plane_forwarded_trust(found)

    def test_rejects_repeated_forwarded_allowlist_environment_entries(self):
        self.container['Config']['Env'].append('FORWARDED_ALLOW_IPS=' + self.gateway)
        self.engine._request = self._request
        found = self.engine._find_control_plane_web(self.domain)

        with self.assertRaises(DockerEngineError):
            self.engine._verify_control_plane_forwarded_trust(found)

    def test_preserves_old_sidecar_image_identity_for_isolation_checks_after_web_update(self):
        old_image_id = 'sha256:' + 'f' * 64
        old_image = {'Id': old_image_id, 'Config': {'Env': ['PATH=/usr/local/bin']}}
        new_web = {'image_id': self.image_id, 'image_info': self.image}
        calls = []

        def request(method, path, *args, **kwargs):
            calls.append((method, path))
            if method == 'GET' and path == '/images/' + quote(old_image_id, safe='') + '/json':
                return old_image
            raise AssertionError((method, path))

        self.engine._request = request
        self.assertIs(self.engine._proxy_sidecar_image_info(old_image_id, new_web), old_image)
        self.assertEqual(calls, [('GET', '/images/' + quote(old_image_id, safe='') + '/json')])

    def test_rejects_image_metadata_that_does_not_match_pinned_sidecar_id(self):
        old_image_id = 'sha256:' + 'f' * 64
        self.engine._request = lambda *args, **kwargs: {'Id': self.image_id, 'Config': {}}

        with self.assertRaises(DockerEngineError):
            self.engine._proxy_sidecar_image_info(
                old_image_id, {'image_id': self.image_id, 'image_info': self.image})

    def test_rejects_network_gateway_drift_or_ambiguous_compose_web_network(self):
        self.engine._request = self._request
        self.network['IPAM']['Config'][0]['Gateway'] = '172.30.0.254'
        with self.assertRaises(DockerEngineError):
            self.engine._find_control_plane_web(self.domain)

        self.network['IPAM']['Config'][0]['Gateway'] = self.gateway
        second_id = 'e' * 64
        second_endpoint = {
            'NetworkID': second_id,
            'Gateway': self.gateway,
            'IPAddress': '172.30.0.3',
        }
        self.container['NetworkSettings']['Networks'][self.project + '_web2'] = second_endpoint
        original_request = self.engine._request

        def request_with_second_network(method, path, *args, **kwargs):
            if path == '/networks/' + second_id:
                return {
                    'Id': second_id, 'Name': self.project + '_web2', 'Driver': 'bridge',
                    'Labels': {
                        'com.docker.compose.project': self.project,
                        'com.docker.compose.network': 'web',
                    },
                    'IPAM': {'Config': [{'Subnet': '172.30.0.0/24', 'Gateway': self.gateway}]},
                }
            return original_request(method, path, *args, **kwargs)

        self.engine._request = request_with_second_network
        with self.assertRaises(DockerEngineError):
            self.engine._find_control_plane_web(self.domain)


if __name__ == '__main__':
    unittest.main()
