"""Synthetic Docker API checks for the versioned per-agent network profile."""
import copy
import json
import unittest
from typing import Any

from supervisor.config import AgentLimits
from supervisor.docker_engine import DockerEngine


class DockerEngineNetworkTests(unittest.TestCase):
    def test_legacy_none_spec_remains_verifiable_without_implicit_migration(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = 'e' * 32
        container_id = 'f' * 64
        token = 'legacy-gateway-token'
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        image_id = 'sha256:' + 'a' * 64
        image_info = {'Id': image_id,
                      'Config': {'Env': [], 'Entrypoint': [], 'WorkingDir': ''}}
        engine._image_info = lambda: image_info
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=1)
        payload = engine._payload(instance_id, spec, token, image_info)
        expected = engine._projection(payload, payload['HostConfig'],
                                      engine._expected_mounts(payload), image_id)
        payload['Labels'].update({engine.SPEC_LABEL: engine._json(spec),
                                  engine.CONFIG_LABEL: engine._hash(expected)})
        config = {key: copy.deepcopy(payload.get(key)) for key in (
            'Image', 'User', 'Cmd', 'Env', 'Entrypoint', 'WorkingDir',
            'Healthcheck', 'StopTimeout', 'Labels', 'Tty', 'OpenStdin', 'StdinOnce')}
        host = copy.deepcopy(payload['HostConfig'])
        mounts = [{
            'Type': mount['Type'], 'Source': mount['Source'],
            'Destination': mount['Target'], 'RW': not mount['ReadOnly'],
            'Propagation': mount['BindOptions']['Propagation'],
        } for mount in host['Mounts']]
        observed = {
            'Id': container_id, 'Image': image_id, 'Config': config,
            'HostConfig': host, 'Mounts': mounts,
            'NetworkSettings': {'Ports': {}, 'Networks': {'none': {}}},
        }
        self.assertEqual(engine._verify(instance_id, observed, expected_spec=spec,
                                        expected_token=token), container_id)

    def test_create_uses_owned_internal_network_without_published_ports(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = 'b' * 32
        container_id = 'c' * 64
        network_id = 'd' * 64
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        calls = []
        state: dict[str, Any] = {'network_payload': None, 'container_payload': None}
        image_id = 'sha256:' + 'a' * 64

        def network_inspect():
            payload = state['network_payload']
            assert payload is not None
            spec = payload.get('Labels') or {}
            containers = {}
            if state['container_payload'] is not None:
                containers[container_id] = {'Name': 'pa-' + instance_id, 'EndpointID': 'e' * 64}
            return {
                'Id': network_id,
                'Name': payload.get('Name', 'pa-net-' + instance_id),
                'Driver': 'bridge',
                'Internal': True,
                'Attachable': False,
                'Ingress': False,
                'EnableIPv6': False,
                'Labels': spec,
                'Containers': containers,
            }

        def container_inspect():
            payload = state['container_payload']
            assert payload is not None
            host = copy.deepcopy(payload['HostConfig'])
            mounts = [{
                'Type': mount['Type'], 'Source': mount['Source'],
                'Destination': mount['Target'], 'RW': not mount['ReadOnly'],
                'Propagation': mount['BindOptions']['Propagation'],
            } for mount in host['Mounts']]
            config = {key: copy.deepcopy(payload.get(key)) for key in (
                'Image', 'User', 'Cmd', 'Env', 'Entrypoint', 'WorkingDir',
                'Healthcheck', 'StopTimeout', 'Labels', 'Tty', 'OpenStdin', 'StdinOnce')}
            network_name = host['NetworkMode']
            return {
                'Id': container_id,
                'Image': image_id,
                'Config': config,
                'HostConfig': host,
                'Mounts': mounts,
                'State': {'Status': 'created'},
                'NetworkSettings': {
                    'Ports': {},
                    'Networks': {network_name: {
                        'NetworkID': network_id, 'IPAddress': '172.31.0.2',
                        'Gateway': '172.31.0.1',
                    }},
                },
            }

        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path, copy.deepcopy(payload)))
            if method == 'GET' and path == '/info':
                return {'OSType': 'linux', 'MemoryLimit': True, 'SwapLimit': True,
                        'CpuCfsPeriod': True, 'CpuCfsQuota': True, 'PidsLimit': True,
                        'SecurityOptions': ['name=seccomp']}
            if method == 'GET' and path.startswith('/images/'):
                return {'Id': image_id, 'Config': {'Env': [], 'Entrypoint': [], 'WorkingDir': ''}}
            if method == 'GET' and path.startswith('/networks?filters='):
                if state['network_payload'] is None:
                    return []
                return [{'Id': network_id, 'Name': state['network_payload']['Name']}]
            if method == 'POST' and path == '/networks/create':
                state['network_payload'] = copy.deepcopy(payload)
                return {'Id': network_id}
            if method == 'GET' and path == '/networks/' + network_id:
                return network_inspect()
            if method == 'GET' and path.startswith('/containers/json?'):
                return ([{'Id': container_id}] if state['container_payload'] is not None else [])
            if method == 'POST' and path.startswith('/containers/create?'):
                state['container_payload'] = copy.deepcopy(payload)
                return {'Id': container_id}
            if method == 'DELETE' and path == f'/containers/{container_id}?force=true&v=false':
                state['container_payload'] = None
                return None
            if method == 'DELETE' and path == '/networks/' + network_id:
                state['network_payload'] = None
                return None
            if method == 'GET' and path == '/containers/' + container_id + '/json':
                return container_inspect()
            raise AssertionError(f'Unexpected fake Docker request: {method} {path}')

        engine._request = request
        result = engine.create(instance_id, '/srv/agent-data/' + instance_id, limits,
                               'gateway-test-token', network_profile='agent_internal_v1')
        self.assertEqual(result, container_id)

        network_calls = [item for item in calls if item[1] == '/networks/create']
        self.assertEqual(len(network_calls), 1)
        network = network_calls[0][2]
        self.assertEqual(network['Name'], 'pa-net-' + instance_id)
        self.assertNotIn('CheckDuplicate', network)
        self.assertEqual(network['Driver'], 'bridge')
        self.assertIs(network['Internal'], True)
        self.assertIs(network['Attachable'], False)
        self.assertIs(network['EnableIPv6'], False)
        self.assertEqual(network['Labels'][DockerEngine.INSTANCE_LABEL], instance_id)
        self.assertEqual(state['container_payload']['HostConfig']['NetworkMode'], network['Name'])
        self.assertEqual(state['container_payload']['HostConfig']['PortBindings'], {})
        self.assertIs(state['container_payload']['HostConfig']['PublishAllPorts'], False)
        self.assertEqual(set(container_inspect()['NetworkSettings']['Networks']), {network['Name']})
        self.assertEqual(engine.inspect(instance_id)['network_profile'], 'agent_internal_v1')
        engine.remove(instance_id)
        delete_container_index = next(i for i, call in enumerate(calls)
                                      if call[0] == 'DELETE' and call[1].startswith('/containers/'))
        delete_network_index = next(i for i, call in enumerate(calls)
                                    if call[0] == 'DELETE' and call[1] == '/networks/' + network_id)
        self.assertLess(delete_container_index, delete_network_index)
        self.assertIsNone(state['container_payload'])
        self.assertIsNone(state['network_payload'])


if __name__ == '__main__':
    unittest.main()
