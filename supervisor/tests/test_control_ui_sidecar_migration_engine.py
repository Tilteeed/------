import json
import unittest

from supervisor.docker_engine import DockerEngine, DockerEngineError
from supervisor.runtime_store import RuntimeStore


class ReadyFirewall:
    def ready(self, _policies):
        return True


class PlannedEngine(DockerEngine):
    def __init__(self, instance_id, gateway, sidecar, web, plan, image_ids):
        super().__init__('sha256:' + 'f' * 64,
                         agent_network_pool='10.240.0.0/24',
                         frontend_network_pool='10.241.0.0/24',
                         firewall=ReadyFirewall())
        self.instance_id = instance_id
        self.gateway = gateway
        self.sidecar = sidecar
        self.web = web
        self.plan = plan
        self.sidecar: dict | None = sidecar
        self.verified_memberships = []
        self.network_checks = []
        self.api_calls = []
        self.next_sidecar_id = '8' * 64
        self.reject_frontend_if_absent = False
        self.created_calls = 0

    def _list_proxy_sidecars(self):
        return {self.instance_id: self.sidecar} if self.sidecar is not None else {}

    def _find_control_plane_web(self, control_ui_domain):
        return self.web

    def _verify_control_plane_forwarded_trust(self, web):
        return None

    def _find(self, instance_id):
        return self.gateway

    def _verify(self, instance_id, observed, expected_spec=None, expected_token=None):
        return self.gateway['Id']

    def _proxy_network_id(self, instance_id, role, expected):
        return 'a' * 64 if role == 'agent' else 'b' * 64

    def _proxy_sidecar_image_info(self, sidecar_image_id, web):
        return {'Id': sidecar_image_id, 'Config': {'Env': []}}

    def _verify_proxy_sidecar(self, instance_id, observed, expected, plan, network_ids):
        if (type(observed) is not dict or observed.get('Image') != expected.get('Image')
                or observed.get('Config', {}).get('Labels') != expected.get('Labels')):
            raise AssertionError('synthetic Sidecar identity mismatch')
        return observed['Id']

    def _verify_proxy_network_membership(self, instance_id, role, network_id,
                                         expected_plan, expected_container_ids, *,
                                         expected_ips, allow_unstarted=False):
        self.verified_memberships.append((role, network_id, set(expected_container_ids)))
        return {'Id': network_id}

    def _verify_migration_frontend_membership(self, instance_id, network_id, plan,
                                              web_id, sidecar_id=None):
        return True

    def _proxy_firewall_policy(self, instance_id, plan):
        return super()._proxy_firewall_policy(instance_id, plan)

    def proxy_network_policies(self):
        return (self._proxy_firewall_policy(self.instance_id, self.plan),)

    def _find_proxy_sidecar(self, instance_id):
        return self.sidecar

    def _verify_migration_networks(self, item, *, sidecar_id=None, web_attached=True,
                                   allow_unstarted=False):
        self.network_checks.append((sidecar_id, web_attached, allow_unstarted))
        if self.reject_frontend_if_absent and sidecar_id is None:
            raise DockerEngineError('synthetic unexpected frontend participant')

    def _ensure_container_network(self, container_id, network_id, network_name, ipv4):
        if container_id == self.web['container_id']:
            return {'Id': container_id}
        if self.sidecar is None:
            return {}
        return self.sidecar

    def _request(self, method, path, payload=None, *, ok=(200,)):
        self.api_calls.append((method, path))
        if method == 'POST' and path.endswith('/stop?t=10'):
            if self.sidecar is not None:
                self.sidecar['State'] = {'Status': 'exited', 'Health': {'Status': 'healthy'}}
        elif method == 'POST' and path.endswith('/start'):
            if self.sidecar is not None:
                self.sidecar['State'] = {'Status': 'running', 'Health': {'Status': 'healthy'}}
        return {}

    def _delete_container(self, container_id):
        if self.sidecar is None or self.sidecar.get('Id') != container_id:
            raise AssertionError('attempted deletion of an unknown synthetic container')
        self.sidecar = None

    def _create_proxy_sidecar(self, instance_id, payload, plan, network_ids):
        self.created_calls += 1
        labels = payload['Labels']
        self.sidecar = {
            'Id': self.next_sidecar_id, 'Image': payload['Image'],
            'Name': '/pa-proxy-' + instance_id,
            'Config': {'Labels': labels},
            'State': {'Status': 'created', 'Health': {'Status': 'starting'}},
        }
        return self.next_sidecar_id

    def _wait_proxy_sidecar_healthy(self, instance_id, expected, plan, network_ids,
                                    expected_id, timeout=60):
        if (self.sidecar is None or self.sidecar.get('Id') != expected_id
                or (self.sidecar.get('State') or {}).get('Status') != 'running'
                or (self.sidecar.get('State', {}).get('Health') or {}).get('Status') != 'healthy'):
            raise AssertionError('synthetic Sidecar did not become healthy')
        return self.sidecar

    def control_ui_target(self, instance_id, owner_id):
        if self.sidecar is None:
            return None
        return {'identity': {
            'gateway_id': self.gateway['Id'], 'sidecar_id': self.sidecar['Id'],
            'agent_network_id': 'a' * 64, 'frontend_network_id': 'b' * 64,
        }}

    def _build_payload(self, instance_id, *, owner_id, control_ui_origin,
                       gateway_ip, listen_ip, image_id, host_path, plan, image_info=None):
        spec = {
            'version': 1, 'image_id': image_id, 'owner_id': owner_id,
            'control_ui_origin': control_ui_origin, 'gateway_ip': gateway_ip,
            'listen_ip': listen_ip, 'host_path': host_path,
            'agent': plan['agent'], 'frontend': plan['frontend'],
        }
        return {'Image': image_id, 'Labels': {
            self.SIDECAR_SPEC_LABEL: self._json(spec),
            self.SIDECAR_CONFIG_LABEL: self._hash(spec),
        }}

    def _verify_membership(self, instance_id, role, network_id, plan, container_ids,
                           *, expected_ips, allow_unstarted=False):
        self.verified_memberships.append((role, network_id, set(container_ids), expected_ips))


class DockerEngineMigrationPlanTests(unittest.TestCase):
    def _fixtures(self):
        instance_id = '1' * 32
        old_image = 'sha256:' + '2' * 64
        new_image = 'sha256:' + '3' * 64
        network_plan = DockerEngine._proxy_network_plan(
            instance_id, agent_network_pool='10.240.0.0/24',
            frontend_network_pool='10.241.0.0/24')
        gateway_id, sidecar_id, web_id = '4' * 64, '5' * 64, '6' * 64
        gateway_spec = {
            'version': 3, 'image': 'openclaw:test', 'host_path': '/srv/agents/' + instance_id,
            'limits': {'ram_bytes': 1024, 'cpu_millicores': 100, 'disk_bytes': 2048},
            'proxy_network': network_plan['agent'], 'owner_id': 'alice',
            'control_ui_origin': 'https://' + instance_id + '.agents.example.test',
        }
        sidecar_spec = {
            'version': 1, 'image_id': old_image, 'owner_id': 'alice',
            'control_ui_origin': gateway_spec['control_ui_origin'],
            'gateway_ip': network_plan['agent']['gateway_ip'],
            'listen_ip': network_plan['frontend']['sidecar_ip'],
            'host_path': gateway_spec['host_path'],
            'agent': network_plan['agent'], 'frontend': network_plan['frontend'],
        }
        gateway = {
            'Id': gateway_id, 'Image': 'sha256:' + '7' * 64,
            'Name': '/pa-' + instance_id,
            'Config': {'Labels': {DockerEngine.SPEC_LABEL: DockerEngine._json(gateway_spec),
                                  DockerEngine.MANAGED_LABEL: 'true',
                                  DockerEngine.INSTANCE_LABEL: instance_id,
                                  DockerEngine.CONFIG_LABEL: '9' * 64}},
            'HostConfig': {'NetworkMode': network_plan['agent']['name']},
            'Mounts': [],
            'NetworkSettings': {'Networks': {network_plan['agent']['name']: {}}},
            'State': {'Status': 'running', 'Health': {'Status': 'healthy'}},
        }
        sidecar = {
            'Id': sidecar_id, 'Image': old_image,
            'Name': '/pa-proxy-' + instance_id,
            'Config': {'Labels': {
                DockerEngine.INSTANCE_LABEL: instance_id,
                DockerEngine.SIDECAR_ROLE_LABEL: DockerEngine.SIDECAR_ROLE,
                DockerEngine.SIDECAR_SPEC_LABEL: DockerEngine._json(sidecar_spec),
                DockerEngine.SIDECAR_CONFIG_LABEL: DockerEngine._hash(sidecar_spec),
            }},
            'State': {'Status': 'running', 'Health': {'Status': 'healthy'}},
        }
        web = {
            'container_id': web_id, 'image_id': new_image,
            'image_info': {'Id': new_image, 'Config': {'Env': []}},
            'networks': {'web': {}}, 'docker_gateway': '172.20.0.1',
            'forwarded_allow_values': ('172.20.0.1',),
            'state': {'Running': True, 'Status': 'running'},
        }
        engine = PlannedEngine(instance_id, gateway, sidecar, web, network_plan,
                               {old_image, new_image})
        instance = {
            'id': instance_id, 'actor': 'alice', 'active': 1,
            'network_profile': RuntimeStore.NETWORK_PROFILE_PROXY,
            'container_id': gateway_id,
            'storage': json.dumps({'host_path': gateway_spec['host_path'], 'project_id': 42}),
        }
        return engine, instance, old_image, new_image, gateway_id, sidecar_id, network_plan

    def test_plan_pins_old_and_new_images_and_preserves_gateway_and_network_identity(self):
        engine, instance, old_image, new_image, gateway_id, sidecar_id, plan = self._fixtures()

        package = engine.plan_control_ui_sidecar_migration(
            [instance], 'agents.example.test')

        self.assertEqual(package['public']['webui']['container_id'], '6' * 64)
        self.assertEqual(package['public']['webui']['image_id'], new_image)
        self.assertEqual(package['public']['items'][0]['old_image_id'], old_image)
        self.assertEqual(package['public']['items'][0]['target_image_id'], new_image)
        self.assertEqual(package['public']['items'][0]['gateway_id'], gateway_id)
        self.assertEqual(package['public']['items'][0]['old_sidecar_id'], sidecar_id)
        prepared = package['prepared'][0]
        self.assertEqual(prepared['gateway_id'], gateway_id)
        self.assertEqual(prepared['network_ids'], {'agent': 'a' * 64, 'frontend': 'b' * 64})
        self.assertEqual(prepared['network_plan'], plan)
        self.assertEqual(package['public']['blockers'], [])
        self.assertEqual({item[0] for item in engine.verified_memberships}, {'agent'})
        self.assertEqual(engine.api_calls, [])

    def test_rollback_accepts_old_identity_when_target_spec_is_identical(self):
        engine, instance, _old_image, _new_image, _gateway_id, old_sidecar_id, _plan = self._fixtures()
        package = engine.plan_control_ui_sidecar_migration([instance], 'agents.example.test')
        item = dict(package['prepared'][0])
        item['target_image_id'] = item['old_image_id']
        engine.web['image_id'] = item['old_image_id']
        engine.web['image_info'] = {'Id': item['old_image_id'], 'Config': {'Env': []}}
        item['target_sidecar_spec'] = dict(item['old_sidecar_spec'])
        item['target_sidecar_config_sha256'] = item['old_sidecar_config_sha256']
        item['stage'] = 'new_running'
        checkpoints = []

        result = engine.rollback_control_ui_sidecar(
            item, lambda stage, **values: checkpoints.append((stage, values)))

        self.assertEqual(result['sidecar_id'], old_sidecar_id)
        self.assertEqual(engine.created_calls, 0)
        self.assertEqual(engine.api_calls, [])
        self.assertEqual(checkpoints[-1][0], 'rolled_back')

    def test_rollback_reuses_existing_stopped_old_sidecar(self):
        engine, instance, _old_image, _new_image, _gateway_id, old_sidecar_id, _plan = self._fixtures()
        package = engine.plan_control_ui_sidecar_migration([instance], 'agents.example.test')
        item = dict(package['prepared'][0])
        item['stage'] = 'old_stopped'
        if engine.sidecar is None:
            self.fail('original Sidecar fixture is absent')
        sidecar = engine.sidecar
        sidecar['State'] = {'Status': 'exited', 'Health': {'Status': 'healthy'}}
        checkpoints = []

        result = engine.rollback_control_ui_sidecar(
            item, lambda stage, **values: checkpoints.append((stage, values)))

        self.assertEqual(result['sidecar_id'], old_sidecar_id)
        self.assertEqual(sidecar['Id'], old_sidecar_id)
        self.assertEqual(engine.created_calls, 0)
        self.assertEqual(engine.api_calls, [
            ('POST', '/containers/' + old_sidecar_id + '/start')])
        self.assertEqual(checkpoints[-1][0], 'rolled_back')

    def test_migration_rejects_target_spec_reusing_the_old_container_id(self):
        engine, instance, _old_image, new_image, _gateway_id, old_sidecar_id, _plan = self._fixtures()
        package = engine.plan_control_ui_sidecar_migration([instance], 'agents.example.test')
        item = dict(package['prepared'][0])
        target_spec = item['target_sidecar_spec']
        if engine.sidecar is None:
            self.fail('original Sidecar fixture is absent')
        sidecar = engine.sidecar
        sidecar['Image'] = new_image
        sidecar['Config']['Labels'][DockerEngine.SIDECAR_SPEC_LABEL] = (
            DockerEngine._json(target_spec))
        sidecar['Config']['Labels'][DockerEngine.SIDECAR_CONFIG_LABEL] = (
            DockerEngine._hash(target_spec))
        item.update({'stage': 'new_running', 'new_sidecar_id': old_sidecar_id})

        with self.assertRaises(DockerEngineError):
            engine.migrate_control_ui_sidecar(item, lambda *_args, **_kwargs: None)

        self.assertEqual(sidecar['Id'], old_sidecar_id)
        self.assertEqual(engine.created_calls, 0)
        self.assertEqual(engine.api_calls, [])

    def test_rollback_checks_frontend_membership_before_recreating_sidecar(self):
        engine, instance, _old_image, _new_image, _gateway_id, _sidecar_id, _plan = self._fixtures()
        package = engine.plan_control_ui_sidecar_migration([instance], 'agents.example.test')
        item = dict(package['prepared'][0])
        item.update({'stage': 'old_removed', 'result': None})
        engine.sidecar = None
        engine.reject_frontend_if_absent = True

        with self.assertRaises(DockerEngineError):
            engine.rollback_control_ui_sidecar(item, lambda *_args, **_kwargs: None)

        self.assertEqual(engine.created_calls, 0)
        self.assertEqual(engine.api_calls, [])

    def test_migration_replaces_only_sidecar_and_keeps_gateway_and_network_plan(self):
        engine, instance, _old_image, new_image, gateway_id, old_sidecar_id, _plan = self._fixtures()
        package = engine.plan_control_ui_sidecar_migration([instance], 'agents.example.test')
        item = dict(package['prepared'][0])
        item.update({'stage': 'planned', 'result': None})
        checkpoints = []

        def record_checkpoint(stage, **values):
            checkpoints.append((stage, values))
            item.update({'stage': stage, **values})

        result = engine.migrate_control_ui_sidecar(item, record_checkpoint)

        self.assertEqual(result['gateway_id'], gateway_id)
        self.assertEqual(result['sidecar_id'], engine.next_sidecar_id)
        self.assertIsNotNone(engine.sidecar)
        if engine.sidecar is None:
            self.fail('migrated Sidecar is absent')
        self.assertEqual(engine.sidecar['Image'], new_image)
        self.assertNotEqual(engine.sidecar['Id'], old_sidecar_id)
        self.assertEqual(engine.gateway['Id'], gateway_id)
        self.assertIn(('POST', '/containers/' + old_sidecar_id + '/stop?t=10'), engine.api_calls)
        self.assertNotIn(('POST', '/containers/' + gateway_id + '/start'), engine.api_calls)
        self.assertEqual(checkpoints[-1][0], 'complete')


if __name__ == '__main__':
    unittest.main()
