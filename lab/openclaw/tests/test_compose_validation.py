"""Unit fixtures represent Compose JSON, not output from a running Docker daemon."""
import copy
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def valid_spec():
    environment = {
        'OPENCLAW_GATEWAY_TOKEN': 'unit-test-placeholder',
        'OPENCLAW_STATE_DIR': '/home/node/.openclaw',
        'OPENCLAW_CONFIG_PATH': '/home/node/.openclaw/openclaw.json',
        'OPENCLAW_WORKSPACE_DIR': '/home/node/.openclaw/workspace',
    }
    mounts = [
        {'type': 'volume', 'source': name, 'target': target}
        for name, target in (
            ('state', '/home/node/.openclaw'),
            ('workspace', '/home/node/.openclaw/workspace'),
            ('auth_secrets', '/home/node/.config/openclaw'),
        )
    ]
    common = {
        'image': 'openclaw-stage2:7c12438929e5',
        'environment': environment,
        'volumes': mounts,
        'security_opt': ['no-new-privileges:true'],
        'cap_drop': ['NET_ADMIN', 'NET_RAW'],
    }
    gateway = copy.deepcopy(common)
    gateway.update({
        'command': ['node', 'dist/index.js', 'gateway', '--bind', 'lan', '--port', '18789'],
        'ports': [{'host_ip': '127.0.0.1', 'target': 18789, 'published': '18789', 'protocol': 'tcp'}],
        'mem_limit': 2147483648, 'cpus': 1.0, 'pids_limit': 256,
        'healthcheck': {'test': ['CMD', 'node', 'dist/docker-healthcheck.js']},
    })
    cli = copy.deepcopy(common)
    cli.update({'network_mode': 'service:gateway', 'entrypoint': ['node', 'dist/index.js']})
    return {'services': {'gateway': gateway, 'cli': cli},
            'volumes': {name: {} for name in ('state', 'workspace', 'auth_secrets')}}


class ComposeValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('stage2_validation', HERE / 'validate_compose.py')
        if spec is None or spec.loader is None:
            raise RuntimeError('Cannot load Stage 2 validation')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_accepts_normalized_spec_and_custom_loopback_port(self):
        spec = valid_spec()
        self.module.validate_spec(spec)
        spec['services']['gateway']['ports'][0]['published'] = '18888'
        self.module.validate_spec(spec)

    def test_gateway_entrypoint_must_be_absent_or_null(self):
        spec = valid_spec()
        self.module.validate_spec(spec)
        spec['services']['gateway']['entrypoint'] = None
        self.module.validate_spec(spec)
        for entrypoint in ([], '', False, ['sh']):
            with self.subTest(entrypoint=entrypoint):
                spec['services']['gateway']['entrypoint'] = entrypoint
                with self.assertRaises(ValueError):
                    self.module.validate_spec(spec)

    def test_default_network_name_must_belong_to_project(self):
        spec = valid_spec()
        for network in ({}, {'name': 'personal-agent-stage2_default'}):
            with self.subTest(network=network):
                spec['networks'] = {'default': network}
                self.module.validate_spec(spec)
        spec['networks'] = {'default': {'name': 'foreign-network'}}
        with self.assertRaisesRegex(ValueError, 'Foreign network name'):
            self.module.validate_spec(spec)

    def test_rejects_public_ports_and_host_network(self):
        for service, key, value in (
            ('gateway', 'ports', [{'host_ip': '0.0.0.0', 'target': 18789, 'published': '18789'}]),
            ('gateway', 'ports', [{'target': 18789, 'published': '18789'}]),
            ('gateway', 'network_mode', 'host'),
            ('cli', 'network_mode', 'host'),
            ('cli', 'ports', [{'host_ip': '127.0.0.1', 'target': 18789, 'published': '18790'}]),
        ):
            with self.subTest(service=service, key=key, value=value):
                spec = valid_spec()
                spec['services'][service][key] = value
                with self.assertRaises(ValueError):
                    self.module.validate_spec(spec)

    def test_rejects_privileges_bind_mounts_and_capability_additions(self):
        for service in ('gateway', 'cli'):
            for key, value in (
                ('privileged', True), ('pid', 'host'), ('ipc', 'host'),
                ('cap_add', ['SYS_ADMIN']), ('security_opt', []), ('cap_drop', []),
                ('devices', ['/dev/kvm']),
                ('volumes', [{'type': 'bind', 'source': '/var/run/docker.sock', 'target': '/socket'}]),
            ):
                with self.subTest(service=service, key=key):
                    spec = valid_spec()
                    spec['services'][service][key] = value
                    with self.assertRaises(ValueError):
                        self.module.validate_spec(spec)

    def test_rejects_wrong_image_shared_mounts_and_external_storage(self):
        mutations = [
            lambda s: s['services']['gateway'].update(image='unrelated:latest'),
            lambda s: s['services']['cli']['volumes'][0].update(source='workspace'),
            lambda s: s['volumes']['state'].update(external=True),
            lambda s: s['volumes']['state'].update(driver_opts={'device': '/'}),
            lambda s: s['volumes']['state'].update(name='foreign-volume'),
            lambda s: s.update(networks={'default': {'driver': 'host'}}),
            lambda s: s['services']['gateway'].update(entrypoint=['sh']),
            lambda s: s['services'].update(extra={'image': 'unrelated:latest'}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                spec = valid_spec()
                mutate(spec)
                with self.assertRaises(ValueError):
                    self.module.validate_spec(spec)

    def test_rejects_missing_auth_and_resource_limits_without_echoing_secret(self):
        mutations = [
            lambda s: s['services']['gateway']['environment'].pop('OPENCLAW_GATEWAY_TOKEN'),
            lambda s: s['services']['cli']['environment'].update(OPENCLAW_GATEWAY_TOKEN='different-placeholder'),
            lambda s: s['services']['gateway'].update(mem_limit=0),
            lambda s: s['services']['gateway'].update(cpus=0),
            lambda s: s['services']['gateway'].update(pids_limit=-1),
            lambda s: s['services']['gateway'].update(healthcheck={'disable': True}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                spec = valid_spec()
                mutate(spec)
                with self.assertRaises(ValueError) as error:
                    self.module.validate_spec(spec)
                self.assertNotIn('unit-test-placeholder', str(error.exception))

    def test_rejects_wrong_json_shapes(self):
        for spec in (None, [], {}, {'services': []}, {'services': {'gateway': [], 'cli': {}}}):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                self.module.validate_spec(spec)


if __name__ == '__main__':
    unittest.main()
