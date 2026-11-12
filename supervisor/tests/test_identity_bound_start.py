"""Synthetic transport checks, not Docker/Linux firewall acceptance evidence."""
import copy
import json
import unittest
from unittest.mock import Mock
from typing import Any, Callable
from urllib.parse import parse_qs

from supervisor.config import AgentLimits
from supervisor.docker_engine import DockerEngine, DockerEngineError
from supervisor.firewall import FirewallManager, expected_ruleset
from supervisor.ollama_firewall import OllamaFirewallManager, expected_ollama_ruleset
from supervisor.network_routes import HostIPv4Inventory, IPv4Route, IPv4InterfaceAddress


class ProxyFixture:
    instance = '1' * 32
    gateway_id, sidecar_id, web_id = '2' * 64, '3' * 64, '4' * 64

    def __init__(self, *, ollama=False):
        options = {}
        if ollama:
            options = {'ollama_config': {
                'base_url': 'http://10.99.0.10:11434', 'default_model_id': 'qwen3.5:9b',
                'context_tokens': 8192, 'max_tokens': 512, 'think': False},
                'ollama_network_pool': '172.20.0.0/16', 'ollama_egress_interface': 'eth0'}
        self.engine: Any = DockerEngine('sha256:' + 'a' * 64,
            agent_network_pool='10.244.0.0/24', frontend_network_pool='10.245.0.0/24', **options)
        e = self.engine
        self.plan = plan = e._proxy_network_plan(self.instance,
            agent_network_pool=e.agent_network_pool, frontend_network_pool=e.frontend_network_pool)
        self.network_ids = {'agent': '5' * 64, 'frontend': '6' * 64}
        self.image_info = {'Id': e.image, 'Config': {'Env': []}}
        self.spec = e._spec('/srv/agent-data/' + self.instance,
            AgentLimits(ram_bytes=2**30, cpu_millicores=1000, pids_limit=256, disk_bytes=10*1024**3),
            version=3, instance_id=self.instance, proxy_network=plan['agent'],
            owner_id='owner', control_ui_origin='https://' + self.instance + '.agents.test',
            config_policy_version=1 if ollama else 0)
        payload = e._payload(self.instance, self.spec, None, self.image_info,
                             proxy_network=plan['agent'])
        payload['Labels'].update({e.SPEC_LABEL: e._json(self.spec),
            e.CONFIG_LABEL: e._hash(e._projection(payload, payload['HostConfig'],
                e._expected_mounts(payload), self.image_info['Id']))})
        self.gateway = self.observation(self.gateway_id, payload,
            {'agent': plan['agent']['gateway_ip']}, gateway=True)
        sidecar_payload = e._proxy_sidecar_payload(self.instance, owner_id='owner',
            control_ui_origin=self.spec['control_ui_origin'], gateway_ip=plan['agent']['gateway_ip'],
            listen_ip=plan['frontend']['sidecar_ip'], image_id=e.image,
            host_path=self.spec['host_path'], plan=plan, image_info=self.image_info)
        self.sidecar = self.observation(self.sidecar_id, sidecar_payload,
            {role: plan[role]['sidecar_ip'] for role in plan})
        self.web = {'Id': self.web_id, 'State': {'Status': 'running'},
            'NetworkSettings': {'Networks': {plan['frontend']['name']: self.endpoint(
                'frontend', plan['frontend']['web_ip'])}}}
        self.objects = {obj['Id']: obj for obj in (self.gateway, self.sidecar, self.web)}
        self.networks = {}
        for role, network_id in self.network_ids.items():
            net = e._proxy_network_payload(self.instance, plan[role], role=role)
            net.update({'Id': network_id, 'Containers': {}, 'Ingress': False})
            self.networks[network_id] = net
        for obj in self.objects.values():
            for name, endpoint in obj['NetworkSettings']['Networks'].items():
                self.networks[endpoint['NetworkID']]['Containers'][obj['Id']] = {
                    'IPv4Address': endpoint['IPAMConfig']['IPv4Address'] + '/29'}
        e._find = lambda instance_id: copy.deepcopy(self.gateway)
        e._find_proxy_sidecar = lambda instance_id: copy.deepcopy(self.sidecar)
        e._image_info = lambda: copy.deepcopy(self.image_info)
        e._proxy_sidecar_image_info = lambda sidecar_image_id, web: copy.deepcopy(self.image_info)
        e._find_control_plane_web = lambda control_ui_domain: {
            'container_id': self.web_id, 'image_id': e.image, 'image_info': self.image_info,
            'networks': copy.deepcopy(self.web['NetworkSettings']['Networks'])}
        e._proxy_network_id = lambda instance_id, role, expected: self.network_ids[role]
        self.policies = (e._proxy_firewall_policy(self.instance, plan),)
        e.proxy_network_policies = lambda: self.policies
        self.ruleset: Any = expected_ruleset(self.policies)
        self.adapter = Mock()
        self.adapter.read.side_effect = lambda: copy.deepcopy(self.ruleset)
        e.firewall = FirewallManager(self.adapter, semantics_validated=True)
        self.calls = []
        self.after_start: Callable[[str], None] | None = None
        e._request = self.request
        e.control_ui_target = Mock(return_value=None)
        e._action = Mock(side_effect=AssertionError('by-name action forbidden'))
        e.inspect = Mock(side_effect=AssertionError('inspect may stop name replacements'))
        e._stop_proxy_containers = Mock(side_effect=AssertionError('by-name rollback forbidden'))
        if ollama:
            route = e._ollama_network_plan(self.instance, e.ollama_network_pool,
                                           endpoint_ip=e.ollama_ip)
            network_id = '8' * 64
            net = e._ollama_network_payload(self.instance, route)
            net.update({'Id': network_id, 'Ingress': False, 'Containers': {
                self.gateway_id: {'IPv4Address': route['gateway_ip'] + '/29'}}})
            self.networks[network_id] = net
            self.gateway['NetworkSettings']['Networks'][route['name']] = {
                'NetworkID': network_id, 'IPAddress': route['gateway_ip'],
                'IPAMConfig': {'IPv4Address': route['gateway_ip']}}
            e.host_route_provider = lambda: HostIPv4Inventory(
                (IPv4Route(route['subnet'], route['bridge'], 'unicast', 'kernel', 'link',
                           route['gateway']),),
                (IPv4InterfaceAddress(route['bridge'], route['gateway'], 29),))
            self.route_adapter = Mock()
            self.route_ruleset: Any = expected_ollama_ruleset(e.ollama_route_policies())
            self.route_adapter.read.side_effect = lambda: copy.deepcopy(self.route_ruleset)
            e.ollama_firewall = OllamaFirewallManager(self.route_adapter, semantics_validated=True)
            self.calls.clear()

    def endpoint(self, role, ip):
        return {'NetworkID': self.network_ids[role], 'IPAddress': ip,
                'IPAMConfig': {'IPv4Address': ip}}

    def observation(self, identity, payload, addresses, gateway=False):
        mounts = self.engine._expected_mounts(payload) if gateway else [
            {'Type': 'bind', 'Source': payload['HostConfig']['Mounts'][0]['Source'],
             'Destination': self.engine.PROXY_TOKEN_FILE_CONTAINER, 'RW': False}]
        return {'Id': identity, 'Image': self.engine.image,
            'Config': {k: copy.deepcopy(v) for k, v in payload.items()
                       if k not in {'HostConfig', 'NetworkingConfig'}},
            'HostConfig': copy.deepcopy(payload['HostConfig']), 'Mounts': mounts,
            'State': {'Status': 'exited', 'ExitCode': 0, 'Health': {'Status': 'starting'}},
            'NetworkSettings': {'Networks': {self.plan[role]['name']: self.endpoint(role, ip)
                                           for role, ip in addresses.items()}}}

    def request(self, method, path, payload=None, *, ok=(200,)):
        self.calls.append((method, path))
        if method == 'GET' and path == '/networks':
            return copy.deepcopy(list(self.networks.values()))
        if method == 'GET' and path.startswith('/networks?'):
            filters = json.loads(parse_qs(path.split('?', 1)[1])['filters'][0])
            return copy.deepcopy([net for net in self.networks.values()
                                  if net['Name'] in filters['name']])
        if method == 'GET' and path.startswith('/networks/'):
            return copy.deepcopy(self.networks[path.split('/')[2]])
        if path.startswith('/containers/'):
            identity, action = path.split('/')[2:4]
            obj = self.objects.get(identity)
            if obj is None:
                raise DockerEngineError('captured object absent')
            if method == 'GET' and action == 'json':
                return copy.deepcopy(obj)
            if method == 'POST' and action == 'start':
                obj['State']['Status'] = 'running'
                if self.after_start:
                    self.after_start(identity)
                return None
            if method == 'POST' and action == 'stop?t=10':
                obj['State']['Status'] = 'exited'
                return None
        raise AssertionError('unexpected Docker request: ' + repr((method, path)))


class IdentityBoundStartTests(unittest.TestCase):
    def test_created_pair_configuration_is_not_mistaken_for_live_readiness(self):
        f = ProxyFixture()
        for obj in (f.gateway, f.sidecar):
            obj['State']['Status'] = 'created'
            for endpoint in obj['NetworkSettings']['Networks'].values():
                endpoint['NetworkID'] = endpoint['IPAddress'] = ''
        for network in f.networks.values():
            network['Containers'] = {key: value for key, value in network['Containers'].items()
                                     if key == f.web_id}
        self.assertEqual(f.engine.recovery_identity(f.instance),
                         {'gateway_id': f.gateway_id, 'sidecar_id': f.sidecar_id})
        with self.assertRaises(DockerEngineError):
            f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        self.assertNotIn(('POST', '/containers/' + f.sidecar_id + '/start'), f.calls)
        self.assertEqual(f.gateway['State']['Status'], 'exited')

    def test_stop_bound_rejects_truncated_or_malformed_ids_before_requests(self):
        for invalid in ('a' * 12, 'a' * 63, 'g' * 64, 'A' * 64, ''):
            with self.subTest(invalid=invalid):
                f = ProxyFixture()
                with self.assertRaises(DockerEngineError):
                    f.engine.stop_bound(f.gateway_id, invalid)
                self.assertEqual(f.calls, [])

    def test_healthy_matching_target_returns_ready_identity(self):
        f = ProxyFixture()
        for obj in (f.gateway, f.sidecar):
            obj['State']['Health']['Status'] = 'healthy'
        identity = {'gateway_id': f.gateway_id, 'sidecar_id': f.sidecar_id,
                    'agent_network_id': f.network_ids['agent'],
                    'frontend_network_id': f.network_ids['frontend']}
        f.engine.control_ui_target.return_value = {'identity': identity}
        result = f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        self.assertEqual(result['proxy_state'], 'ready')
        self.assertEqual(result['gateway'], 'ready')
        self.assertEqual(result['proxy_identity'], identity)

    def test_replacement_of_each_captured_id_prevents_any_start(self):
        for role in ('gateway', 'sidecar'):
            with self.subTest(role=role):
                f = ProxyFixture()
                captured = f.engine.recovery_identity(f.instance)
                replacement = copy.deepcopy(getattr(f, role))
                replacement['Id'] = '7' * 64
                setattr(f, role, replacement)
                f.calls.clear()
                with self.assertRaises(DockerEngineError):
                    f.engine.start_bound(f.instance, captured['gateway_id'], captured['sidecar_id'])
                self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_missing_or_invalid_base_acceptance_gate_blocks_recovery_and_start(self):
        # FirewallManager's disabled semantics flag represents a missing/invalid
        # host receipt. No synthetic flag is evidence of Linux acceptance.
        for operation in ('recover', 'start'):
            for validated in (False, None, 'invalid'):
                with self.subTest(operation=operation, validated=validated):
                    f = ProxyFixture()
                    invalid_receipt: Any = validated
                    f.engine.firewall = FirewallManager(f.adapter, semantics_validated=invalid_receipt)
                    with self.assertRaises(DockerEngineError):
                        if operation == 'recover':
                            f.engine.recovery_identity(f.instance)
                        else:
                            f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
                    self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_wrong_base_firewall_readback_blocks_recovery_and_start(self):
        for operation in ('recover', 'start'):
            with self.subTest(operation=operation):
                f = ProxyFixture()
                f.ruleset = None
                with self.assertRaises(DockerEngineError):
                    if operation == 'recover':
                        f.engine.recovery_identity(f.instance)
                    else:
                        f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
                self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_runtime_payload_drift_is_rejected_by_real_pair_verifiers(self):
        for role in ('gateway', 'sidecar'):
            with self.subTest(role=role):
                f = ProxyFixture()
                getattr(f, role)['HostConfig']['Privileged'] = True
                with self.assertRaises(DockerEngineError):
                    f.engine.recovery_identity(f.instance)
                with self.assertRaises(DockerEngineError):
                    f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
                self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_foreign_network_member_blocks_recovery_and_start(self):
        for role in ('agent', 'frontend'):
            with self.subTest(role=role):
                f = ProxyFixture()
                f.networks[f.network_ids[role]]['Containers']['7' * 64] = {
                    'IPv4Address': '10.244.0.6/29'}
                with self.assertRaises(DockerEngineError):
                    f.engine.recovery_identity(f.instance)
                with self.assertRaises(DockerEngineError):
                    f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
                self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_recovery_requires_stopped_pair_not_live_or_dead(self):
        for role in ('gateway', 'sidecar'):
            for status in ('running', 'paused', 'restarting', 'dead'):
                with self.subTest(role=role, status=status):
                    f = ProxyFixture()
                    getattr(f, role)['State']['Status'] = status
                    with self.assertRaises(DockerEngineError):
                        f.engine.recovery_identity(f.instance)
                    self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_created_pair_can_be_recovered(self):
        f = ProxyFixture()
        for obj in (f.gateway, f.sidecar):
            obj['State']['Status'] = 'created'
        self.assertEqual(f.engine.recovery_identity(f.instance),
                         {'gateway_id': f.gateway_id, 'sidecar_id': f.sidecar_id})

    def test_missing_web_attachment_is_rejected_without_connecting_or_creating(self):
        f = ProxyFixture()
        f.web['NetworkSettings']['Networks'].clear()
        with self.assertRaises(DockerEngineError):
            f.engine.recovery_identity(f.instance)
        self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_base_firewall_drift_after_start_contains_pair(self):
        for failing_start in ('gateway', 'sidecar'):
            with self.subTest(failing_start=failing_start):
                f = ProxyFixture()
                def drift(identity):
                    if identity == getattr(f, failing_start + '_id'):
                        f.ruleset = None
                f.after_start = drift
                with self.assertRaises(DockerEngineError):
                    f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
                self.assertEqual(f.gateway['State']['Status'], 'exited')
                self.assertEqual(f.sidecar['State']['Status'], 'exited')
                if failing_start == 'gateway':
                    self.assertNotIn(('POST', '/containers/' + f.sidecar_id + '/start'), f.calls)

    def test_stop_bound_attempts_both_ids_and_reports_unverified_stop(self):
        f = ProxyFixture()
        f.gateway['State']['Status'] = f.sidecar['State']['Status'] = 'running'
        original_request = f.engine._request
        def request(method, path, payload=None, *, ok=(200,)):
            if method == 'POST' and path == '/containers/' + f.sidecar_id + '/stop?t=10':
                return None  # success without a stopped readback is not containment
            return original_request(method, path, payload, ok=ok)
        f.engine._request = request
        self.assertIs(f.engine.stop_bound(f.gateway_id, f.sidecar_id), False)
        self.assertEqual(f.gateway['State']['Status'], 'exited')
        self.assertEqual(f.sidecar['State']['Status'], 'running')

    def test_failed_rollback_is_reported_without_by_name_fallback(self):
        f = ProxyFixture()
        f.after_start = lambda identity: (_ for _ in ()).throw(DockerEngineError('lost response'))
        f.engine.stop_bound = Mock(return_value=False)
        with self.assertRaisesRegex(DockerEngineError, 'stop could not be verified'):
            f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        f.engine.stop_bound.assert_called_once_with(f.gateway_id, f.sidecar_id)
        f.engine._stop_proxy_containers.assert_not_called()

    def test_ollama_receipt_and_firewall_readback_gate_both_apis(self):
        for operation in ('recover', 'start'):
            for failure in ('receipt', 'ruleset', 'attachment'):
                with self.subTest(operation=operation, failure=failure):
                    f = ProxyFixture(ollama=True)
                    if failure == 'receipt':
                        f.engine.ollama_firewall = OllamaFirewallManager(
                            f.route_adapter, semantics_validated=False)
                    elif failure == 'ruleset':
                        f.route_ruleset = None
                    else:
                        del f.gateway['NetworkSettings']['Networks']['pa-ollama-' + f.instance]
                    with self.assertRaises(DockerEngineError):
                        if operation == 'recover':
                            f.engine.recovery_identity(f.instance)
                        else:
                            f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
                    self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_ollama_firewall_drift_after_start_contains_captured_pair(self):
        f = ProxyFixture(ollama=True)
        def drift(identity):
            f.route_ruleset = None
        f.after_start = drift
        with self.assertRaises(DockerEngineError):
            f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        self.assertEqual(f.gateway['State']['Status'], 'exited')
        self.assertEqual(f.sidecar['State']['Status'], 'exited')
        self.assertNotIn(('POST', '/containers/' + f.sidecar_id + '/start'), f.calls)

    def test_verified_existing_ollama_route_can_recover_and_start_without_create(self):
        f = ProxyFixture(ollama=True)
        self.assertEqual(f.engine.recovery_identity(f.instance),
                         {'gateway_id': f.gateway_id, 'sidecar_id': f.sidecar_id})
        result = f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        self.assertEqual(result['ollama_route_state'], 'ready')
        self.assertGreaterEqual(f.route_adapter.read.call_count, 4)
        self.assertTrue(all(method == 'GET' or path.endswith('/start')
                            for method, path in f.calls))

    def test_control_ui_target_for_another_pair_is_rejected(self):
        f = ProxyFixture()
        f.engine.control_ui_target.return_value = {'identity': {
            'gateway_id': f.gateway_id, 'sidecar_id': '7' * 64}}
        with self.assertRaises(DockerEngineError):
            f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        self.assertEqual(f.gateway['State']['Status'], 'exited')
        self.assertEqual(f.sidecar['State']['Status'], 'exited')

    def test_healthy_pair_without_control_ui_target_is_contained(self):
        f = ProxyFixture()
        for obj in (f.gateway, f.sidecar):
            obj['State']['Health']['Status'] = 'healthy'
        with self.assertRaises(DockerEngineError):
            f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        self.assertEqual(f.gateway['State']['Status'], 'exited')
        self.assertEqual(f.sidecar['State']['Status'], 'exited')

    def test_gateway_start_without_running_readback_never_starts_sidecar(self):
        f = ProxyFixture()
        def fail_start(identity):
            if identity == f.gateway_id:
                f.gateway['State']['Status'] = 'exited'
        f.after_start = fail_start
        with self.assertRaises(DockerEngineError):
            f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        self.assertNotIn(('POST', '/containers/' + f.sidecar_id + '/start'), f.calls)

    def test_configured_ollama_missing_route_blocks_recovery_and_start_without_create(self):
        for operation in ('recover', 'start'):
            with self.subTest(operation=operation):
                f = ProxyFixture()
                f.engine.ollama_config = {}
                with self.assertRaises(DockerEngineError):
                    if operation == 'recover':
                        f.engine.recovery_identity(f.instance)
                    else:
                        f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
                self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_post_start_replacement_rolls_back_only_captured_pair(self):
        for role in ('gateway', 'sidecar'):
            with self.subTest(role=role):
                f = ProxyFixture()
                replacement = copy.deepcopy(getattr(f, role))
                replacement['Id'] = '7' * 64
                replacement['State']['Status'] = 'running'
                def replace(identity):
                    if identity == f.sidecar_id:
                        setattr(f, role, replacement)
                f.after_start = replace
                with self.assertRaises(DockerEngineError):
                    f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
                self.assertEqual([path for method, path in f.calls if '/stop?' in path], [
                    '/containers/' + f.sidecar_id + '/stop?t=10',
                    '/containers/' + f.gateway_id + '/stop?t=10'])
                self.assertEqual(replacement['State']['Status'], 'running')
                self.assertEqual(f.objects[f.gateway_id]['State']['Status'], 'exited')
                self.assertEqual(f.objects[f.sidecar_id]['State']['Status'], 'exited')

    def test_bound_proxy_start_uses_full_pair_ids_and_rechecks_isolation(self):
        f = ProxyFixture()
        result = f.engine.start_bound(f.instance, f.gateway_id, f.sidecar_id)
        self.assertEqual(result['container_id'], f.gateway_id)
        self.assertEqual(result['state'], 'running')
        self.assertEqual(result['proxy_state'], 'not_ready')
        self.assertEqual([path for method, path in f.calls if method == 'POST'], [
            '/containers/' + f.gateway_id + '/start',
            '/containers/' + f.sidecar_id + '/start'])
        self.assertGreaterEqual(f.adapter.read.call_count, 3)

    def test_stop_bound_contains_captured_pair_not_current_name_replacements(self):
        f = ProxyFixture()
        f.gateway['State']['Status'] = f.sidecar['State']['Status'] = 'running'
        f.engine._find = Mock(side_effect=AssertionError('must not resolve names'))
        f.engine._find_proxy_sidecar = Mock(side_effect=AssertionError('must not resolve names'))
        self.assertIs(f.engine.stop_bound(f.gateway_id, f.sidecar_id), True)
        self.assertEqual([path for method, path in f.calls if method == 'POST'], [
            '/containers/' + f.sidecar_id + '/stop?t=10',
            '/containers/' + f.gateway_id + '/stop?t=10'])
        for identity in (f.gateway_id, f.sidecar_id):
            self.assertEqual(f.objects[identity]['State']['Status'], 'exited')
            self.assertIn(('GET', '/containers/' + identity + '/json'), f.calls)

    def test_recovery_identity_verifies_existing_stopped_proxy_without_writes(self):
        f = ProxyFixture()
        self.assertEqual(f.engine.recovery_identity(f.instance),
                         {'gateway_id': f.gateway_id, 'sidecar_id': f.sidecar_id})
        self.assertTrue(f.calls)
        self.assertTrue(all(method == 'GET' for method, _ in f.calls))

    def test_recovery_identity_verifies_existing_stopped_legacy(self):
        engine = object.__new__(DockerEngine)
        identity = 'a' * 64
        observed = {'Id': identity, 'State': {'Status': 'exited'},
                    'Config': {'Labels': {engine.SPEC_LABEL: '{"version": 1}'}}}
        engine._find = Mock(return_value=observed)
        engine._verify = Mock(return_value=identity)
        engine._request = Mock()
        self.assertEqual(engine.recovery_identity('a' * 32),
                         {'gateway_id': identity, 'sidecar_id': None})
        engine._verify.assert_called_once_with('a' * 32, observed)
        engine._request.assert_not_called()

    def test_replacement_is_not_started(self):
        engine = object.__new__(DockerEngine)
        engine._find = Mock(return_value={'Id': 'b' * 64, 'Config': {'Labels': {engine.SPEC_LABEL: '{"version": 1}'}}})
        engine._verify = Mock(return_value='b' * 64)
        engine._request = Mock()
        with self.assertRaises(DockerEngineError):
            engine.start_bound('a' * 32, 'a' * 64)
        engine._request.assert_not_called()

    def test_legacy_start_addresses_verified_full_id(self):
        engine = object.__new__(DockerEngine)
        identity = 'a' * 64
        engine._find = Mock(return_value={'Id': identity, 'Config': {'Labels': {engine.SPEC_LABEL: '{"version": 1}'}}})
        engine._verify = Mock(return_value=identity)
        engine._request = Mock()
        engine.inspect = Mock(return_value={'container_id': identity, 'state': 'running'})
        engine.start_bound('a' * 32, identity)
        engine._request.assert_called_once_with('POST', '/containers/' + identity + '/start', ok=(204, 304))

    def test_proxy_start_is_refused_without_identity_bound_pair(self):
        engine = object.__new__(DockerEngine)
        identity = 'a' * 64
        engine._find = Mock(return_value={'Id': identity, 'Config': {'Labels': {engine.SPEC_LABEL: '{"version": 3}'}}})
        engine._verify = Mock(return_value=identity)
        engine._request = Mock()
        with self.assertRaises(DockerEngineError):
            engine.start_bound('a' * 32, identity)
        engine._request.assert_not_called()
