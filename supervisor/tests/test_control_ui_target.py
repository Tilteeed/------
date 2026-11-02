import threading
import unittest

from supervisor.service import RuntimeService


class FakeStore:
    def __init__(self, instance):
        self.instance = instance
    def current(self, owner_id):
        return self.instance if self.instance and self.instance['actor'] == owner_id else None


class FakeEngine:
    def __init__(self, target):
        self.target = target
        self.target_calls = []
        self.abort_calls = []
    def abort_control_ui_prepare(self, instance_id):
        self.abort_calls.append(instance_id)
    def control_ui_target(self, instance_id, owner_id):
        self.target_calls.append((instance_id, owner_id))
        return self.target


class ControlUiTargetTests(unittest.TestCase):
    def make_service(self, *, state='running', gateway='ready', profile='agent_proxy_v1',
                     proxy_state='ready', target=None, current=True):
        instance_id = 'a' * 32
        instance = {'id': instance_id, 'actor': 'owner-1'} if current else None
        identity = {
            'gateway_id': '1' * 64, 'sidecar_id': '2' * 64,
            'agent_network_id': '3' * 64, 'frontend_network_id': '4' * 64,
        }
        target_value = dict(target) if target is not None else {
            'ip': '172.30.1.2', 'port': 18790, 'proxy_token': 'X' * 43,
        }
        target_value.setdefault('identity', identity)
        engine = FakeEngine(target_value)
        service = RuntimeService.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.store = FakeStore(instance)
        service.engine = engine
        service._inspect = lambda _instance_id: {
            'state': state, 'gateway': gateway,
            'network_profile': profile, 'proxy_state': proxy_state,
            'container_id': target_value['identity']['gateway_id'],
            'proxy_identity': target_value['identity'],
        }
        return service, engine, instance_id

    def test_proxy_prepare_enriches_only_trusted_network_identity(self):
        service, engine, instance_id = self.make_service()
        service.control_ui_domain = 'agents.example.test'
        service.agent_network_pool = '172.30.0.0/16'
        calls = []
        def prepare(requested_instance, owner_id, domain, host_path):
            calls.append((requested_instance, owner_id, domain, host_path))
            return {
                'sidecar_ip': '172.30.1.2',
                'agent_subnet': '172.30.1.0/29',
                'control_ui_origin': 'https://' + instance_id + '.agents.example.test',
            }
        service.engine.prepare_control_ui = prepare
        instance = {
            'id': instance_id, 'actor': 'owner-1', 'network_profile': 'agent_proxy_v1',
            'gateway_token': 'S' * 43,
        }
        enriched = service._prepare_control_ui_instance(
            instance, host_path='/srv/agent-data/' + instance_id)
        self.assertEqual(enriched['sidecar_ip'], '172.30.1.2')
        self.assertEqual(enriched['agent_subnet'], '172.30.1.0/29')
        self.assertEqual(enriched['control_ui_origin'], 'https://' + instance_id + '.agents.example.test')
        self.assertEqual(calls, [(instance_id, 'owner-1', 'agents.example.test',
                                  '/srv/agent-data/' + instance_id)])
        self.assertNotIn('sidecar_ip', instance)

    def test_proxy_prepare_is_not_invoked_for_start_or_restart(self):
        for action in ('start', 'restart'):
            with self.subTest(action=action):
                service, _engine, instance_id = self.make_service()
                calls = []
                service.control_ui_domain = 'agents.example.test'
                service.engine.prepare_control_ui = lambda *_args: calls.append(action)
                instance = {'id': instance_id, 'actor': 'owner-1',
                            'network_profile': 'agent_proxy_v1'}
                self.assertIs(service._prepare_control_ui_instance(instance, action=action), instance)
                self.assertEqual(calls, [])

    def test_proxy_prepare_rejects_sidecar_ip_not_matching_verified_agent_subnet(self):
        service, _engine, instance_id = self.make_service()
        service.control_ui_domain = 'agents.example.test'
        service.agent_network_pool = '172.30.0.0/16'
        service.engine.prepare_control_ui = lambda *_args: {
            'sidecar_ip': '172.30.1.3',
            'agent_subnet': '172.30.1.0/29',
            'control_ui_origin': 'https://' + instance_id + '.agents.example.test',
        }
        with self.assertRaises(Exception):
            service._prepare_control_ui_instance({
                'id': instance_id, 'actor': 'owner-1',
                'network_profile': 'agent_proxy_v1',
            }, host_path='/srv/agent-data/' + instance_id)

    def test_proxy_prepare_fails_closed_without_matching_supervisor_network_result(self):
        for result in (
            {'sidecar_ip': '127.0.0.1', 'agent_subnet': '172.30.1.0/29',
             'control_ui_origin': 'https://' + 'a' * 32 + '.agents.example.test'},
            {'sidecar_ip': '172.30.1.2', 'agent_subnet': '172.30.1.0/29',
             'control_ui_origin': 'https://' + 'b' * 32 + '.agents.example.test'},
            {'sidecar_ip': '172.30.1.2', 'agent_subnet': '172.30.1.0/29',
             'control_ui_origin': 'https://' + 'a' * 32 + '.other.test'},
        ):
            with self.subTest(result=result):
                service, _engine, instance_id = self.make_service()
                service.control_ui_domain = 'agents.example.test'
                service.engine.prepare_control_ui = lambda _owner, _id, _domain, _path, result=result: result
                with self.assertRaises(Exception):
                    service._prepare_control_ui_instance({
                        'id': instance_id, 'actor': 'owner-1',
                        'network_profile': 'agent_proxy_v1', 'gateway_token': 'S' * 43,
                    }, host_path='/srv/agent-data/' + instance_id)

    def test_proxy_prepare_cleanup_is_scoped_to_proxy_instances(self):
        service, engine, instance_id = self.make_service()
        proxy = {'id': instance_id, 'network_profile': 'agent_proxy_v1'}
        legacy = {'id': 'b' * 32, 'network_profile': 'legacy_none'}
        service._abort_control_ui_prepare(instance_id, proxy)
        service._abort_control_ui_prepare(legacy['id'], legacy)
        self.assertEqual(engine.abort_calls, [instance_id])

    def test_proxy_create_passes_only_trusted_proxy_identity_not_gateway_token(self):
        calls = []
        class Engine:
            def create(self, instance_id, host_path, limits, token, **kwargs):
                calls.append((instance_id, host_path, limits, token, kwargs))
        service = RuntimeService.__new__(RuntimeService)
        service.engine = Engine()
        service.agent_network_pool = '172.30.0.0/16'
        instance_id = 'a' * 32
        instance = {'id': instance_id, 'actor': 'owner-1',
                    'network_profile': 'agent_proxy_v1', 'gateway_token': 'DO_NOT_FORWARD'}
        evidence = {'host_path': '/srv/agents/' + instance_id}
        limits = object()
        service._create_engine_instance(instance, evidence, limits, {
            'sidecar_ip': '172.30.1.2',
            'agent_subnet': '172.30.1.0/29',
            'control_ui_origin': 'https://' + instance_id + '.agents.example.test',
        })
        self.assertEqual(calls, [(instance_id, evidence['host_path'], limits, None, {
            'network_profile': 'agent_proxy_v1', 'owner_id': 'owner-1',
            'sidecar_ip': '172.30.1.2',
            'control_ui_origin': 'https://' + instance_id + '.agents.example.test',
        })])

    def test_proxy_remove_retains_ipam_for_restore_but_purge_releases_it(self):
        calls = []
        class Engine:
            def remove(self, instance_id, **kwargs):
                calls.append((instance_id, kwargs))
        service = RuntimeService.__new__(RuntimeService)
        service.engine = Engine()
        instance = {'id': 'a' * 32, 'network_profile': 'agent_proxy_v1'}
        service._remove_engine_instance(instance, action='remove')
        service._remove_engine_instance(instance, action='purge')
        self.assertEqual(calls, [
            ('a' * 32, {'retain_networks': True}),
            ('a' * 32, {'retain_networks': False}),
        ])

    def test_control_ui_target_requires_current_owner_instance_and_ready_proxy(self):
        service, engine, instance_id = self.make_service(proxy_state='starting')
        result = service.control_ui_target({'actor_id': 'owner-1', 'instance_id': instance_id})
        self.assertEqual(result, {'ready': False, 'target': None})
        self.assertEqual(engine.target_calls, [])

        service, engine, instance_id = self.make_service()
        result = service.control_ui_target({'actor_id': 'owner-2', 'instance_id': instance_id})
        self.assertEqual(result, {'ready': False, 'target': None})
        self.assertEqual(engine.target_calls, [])

    def test_control_ui_target_rejects_runtime_identity_change_during_resolution(self):
        instance_id = 'a' * 32
        identity = {
            'gateway_id': '1' * 64, 'sidecar_id': '2' * 64,
            'agent_network_id': '3' * 64, 'frontend_network_id': '4' * 64,
        }
        service, _engine, _instance_id = self.make_service(target={
            'ip': '172.30.1.2', 'port': 18790, 'proxy_token': 'X' * 43,
            'identity': identity,
        })
        observations = iter((
            {'state': 'running', 'gateway': 'ready', 'network_profile': 'agent_proxy_v1',
             'proxy_state': 'ready', 'container_id': identity['gateway_id'],
             'proxy_identity': identity},
            {'state': 'running', 'gateway': 'ready', 'network_profile': 'agent_proxy_v1',
             'proxy_state': 'ready', 'container_id': '5' * 64,
             'proxy_identity': {**identity, 'gateway_id': '5' * 64}},
        ))
        service.__dict__['_inspect'] = lambda instance_id: next(observations)
        result = service.control_ui_target({'actor_id': 'owner-1', 'instance_id': instance_id})
        self.assertEqual(result, {'ready': False, 'target': None})

    def test_control_ui_target_returns_only_verified_sidecar_target(self):
        service, engine, instance_id = self.make_service()
        result = service.control_ui_target({'actor_id': 'owner-1', 'instance_id': instance_id})
        self.assertEqual(result, {
            'ready': True,
            'target': {'ip': '172.30.1.2', 'port': 18790, 'proxy_token': 'X' * 43},
        })
        self.assertEqual(engine.target_calls, [(instance_id, 'owner-1')])

    def test_control_ui_target_rejects_unsafe_engine_target(self):
        for target in (
            {'ip': '127.0.0.1', 'port': 18790, 'proxy_token': 'X' * 43},
            {'ip': '172.30.1.2', 'port': 80, 'proxy_token': 'X' * 43},
            {'ip': '172.30.1.2', 'port': 18790, 'proxy_token': 'short'},
            {'ip': '172.30.1.2/24', 'port': 18790, 'proxy_token': 'X' * 43},
        ):
            with self.subTest(target=target):
                service, engine, instance_id = self.make_service(target=target)
                result = service.control_ui_target({'actor_id': 'owner-1', 'instance_id': instance_id})
                self.assertEqual(result, {'ready': False, 'target': None})


if __name__ == '__main__':
    unittest.main()
