"""Synthetic Docker API checks for the versioned per-agent network profile."""
import copy
import ipaddress
import json
import os
import secrets
import stat
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs

from supervisor.config import AgentLimits
from supervisor.docker_engine import DockerEngine, DockerEngineError
from supervisor.firewall import FirewallManager, NftablesAdapter
from supervisor.network_routes import (
    HostIPv4Inventory, IPv4InterfaceAddress, IPv4Route, parse_ipv4_networks,
)


def synthetic_ollama_host_inventory(plan, extra_routes=()):
    subnet = ipaddress.IPv4Network(plan['subnet'])
    bridge, gateway = plan['bridge'], plan['gateway']
    routes = (
        IPv4Route(plan['subnet'], bridge, 'unicast', 'kernel', 'link', gateway),
        IPv4Route(f'{gateway}/32', bridge, 'local', 'kernel', 'host', gateway),
        IPv4Route(f'{subnet.network_address}/32', bridge, 'broadcast', 'kernel', 'link', gateway),
        IPv4Route(f'{subnet.broadcast_address}/32', bridge, 'broadcast', 'kernel', 'link', gateway),
        *extra_routes,
    )
    addresses = (IPv4InterfaceAddress(bridge, gateway, subnet.prefixlen),)
    return HostIPv4Inventory(routes, addresses)


class DockerEngineNetworkTests(unittest.TestCase):
    @staticmethod
    def _sidecar_image_info(image_id, env=()):
        return {'Id': image_id, 'Config': {'Env': list(env)}}

    def test_ollama_egress_bridge_is_per_instance_external_but_gateway_only(self):
        instance_id = '7' * 32
        plan = DockerEngine._ollama_network_plan(
            instance_id, '172.20.0.0/16',
            occupied_subnets=('172.20.0.0/29',),
            host_routes=('172.20.0.8/29',))
        expected = {
            'name': 'pa-ollama-' + instance_id,
            'bridge': 'bzo' + instance_id[:12],
            'subnet': '172.20.0.16/29',
            'gateway': '172.20.0.17',
            'gateway_ip': '172.20.0.18',
        }
        self.assertEqual(plan, expected)

        payload = DockerEngine._ollama_network_payload(instance_id, plan)

        self.assertIs(payload['Internal'], False)
        self.assertIs(payload['Attachable'], False)
        self.assertIs(payload['EnableIPv6'], False)
        self.assertEqual(payload['IPAM']['Config'], [
            {'Subnet': expected['subnet'], 'Gateway': expected['gateway']}])
        self.assertEqual(payload['Options'], {
            'com.docker.network.bridge.name': expected['bridge'],
            'com.docker.network.bridge.enable_ip_masquerade': 'true',
            'com.docker.network.bridge.enable_icc': 'false',
        })
        self.assertEqual(payload['Labels'][DockerEngine.NETWORK_SCHEMA_LABEL], 'agent_ollama_v1')
        observed = {**payload, 'Id': 'c' * 64, 'Ingress': False, 'Containers': {}}
        self.assertEqual(
            DockerEngine._ollama_network_from_observation(
                instance_id, observed, '172.20.0.0/16'), plan)
        altered = copy.deepcopy(plan)
        altered['gateway_ip'] = '172.20.0.19'
        with self.assertRaises(ValueError):
            DockerEngine._ollama_network_payload(instance_id, altered)

    def test_ollama_route_engine_requires_explicit_disjoint_pool_and_stays_fail_closed(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b',
            'context_tokens': 8192,
            'max_tokens': 512,
            'think': False,
        }
        engine = DockerEngine(
            'sha256:' + 'a' * 64,
            agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18',
            ollama_config=config)
        self.assertEqual(engine.ollama_network_pool, '172.20.0.0/16')
        self.assertEqual(engine.ollama_egress_interface, 'ens18')
        assert engine.ollama_firewall is not None
        self.assertFalse(engine.ollama_firewall.can_apply)
        with self.assertRaises(ValueError):
            DockerEngine(
                'sha256:' + 'a' * 64,
                agent_network_pool='10.240.0.0/13',
                frontend_network_pool='10.248.0.0/13',
                ollama_network_pool='10.240.0.0/13',
                ollama_egress_interface='ens18', ollama_config=config)

    def test_ollama_route_policy_inventory_verifies_per_instance_network_identity(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b',
            'context_tokens': 8192,
            'max_tokens': 512,
            'think': False,
        }
        engine = DockerEngine(
            'sha256:' + 'a' * 64,
            agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18',
            ollama_config=config)
        instance_id = '8' * 32
        plan = DockerEngine._ollama_network_plan(instance_id, engine.ollama_network_pool)
        payload = DockerEngine._ollama_network_payload(instance_id, plan)
        network = {**payload, 'Id': 'd' * 64, 'Ingress': False, 'Containers': {}}
        engine.host_route_provider = lambda: synthetic_ollama_host_inventory(plan)
        engine._request = lambda method, path, payload=None, *, ok=(200,): (
            [{'Id': network['Id'], 'Name': network['Name'], 'IPAM': network['IPAM'],
              'Labels': network['Labels']}]
            if method == 'GET' and path == '/networks' else
            network if method == 'GET' and path == '/networks/' + network['Id'] else
            (_ for _ in ()).throw(AssertionError((method, path))))

        policies = engine.ollama_route_policies()

        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0].instance_id, instance_id)
        self.assertEqual(policies[0].subnet, plan['subnet'])
        self.assertEqual(policies[0].gateway_ip, plan['gateway_ip'])
        self.assertEqual(policies[0].ollama_ip, '10.99.0.10')
        self.assertEqual(policies[0].egress_interface, 'ens18')

    def test_ollama_attachment_verification_accepts_only_exact_configured_endpoint(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config)
        instance_id, container_id, network_id = '3' * 32, 'a' * 64, 'b' * 64
        plan = engine._ollama_network_plan(instance_id, engine.ollama_network_pool)
        payload = engine._ollama_network_payload(instance_id, plan)
        network = {**payload, 'Id': network_id, 'Ingress': False, 'Containers': {}}
        container = {
            'State': {'Status': 'created'},
            'NetworkSettings': {'Networks': {plan['name']: {
                'NetworkID': '', 'IPAddress': '',
                'IPAMConfig': {'IPv4Address': plan['gateway_ip']},
            }}},
        }
        engine._request = lambda method, path, payload=None, *, ok=(200,): (
            [{'Id': network_id}] if method == 'GET' and path.startswith('/networks?filters=') else
            network if method == 'GET' and path == '/networks/' + network_id else
            (_ for _ in ()).throw(AssertionError((method, path))))

        self.assertEqual(engine._verify_ollama_network_attachment(
            instance_id, container_id, container), (network_id, plan))
        container['NetworkSettings']['Networks'][plan['name']]['IPAMConfig']['IPv4Address'] = '172.20.0.99'
        with self.assertRaises(DockerEngineError):
            engine._verify_ollama_network_attachment(instance_id, container_id, container)

    def test_ollama_route_preparation_is_blocked_before_docker_without_receipt(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b',
            'context_tokens': 8192,
            'max_tokens': 512,
            'think': False,
        }
        engine = DockerEngine(
            'sha256:' + 'a' * 64,
            agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18',
            ollama_config=config)
        engine._request = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('Docker must not be contacted before route acceptance'))

        with self.assertRaises(DockerEngineError):
            engine.ensure_ollama_route('8' * 32)

    def test_ollama_route_inventory_rejects_foreign_overlapping_host_route(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config)
        instance_id = '6' * 32
        plan = engine._ollama_network_plan(instance_id, engine.ollama_network_pool)
        payload = engine._ollama_network_payload(instance_id, plan)
        network = {**payload, 'Id': 'd' * 64, 'Ingress': False, 'Containers': {}}
        foreign_route = IPv4Route(
            plan['subnet'], 'br-foreign', 'unicast', 'kernel', 'link', plan['gateway'])
        engine.host_route_provider = lambda: synthetic_ollama_host_inventory(
            plan, extra_routes=(foreign_route,))
        engine._request = lambda method, path, payload=None, *, ok=(200,): (
            [{'Id': network['Id'], 'Name': network['Name'], 'IPAM': network['IPAM'],
              'Labels': network['Labels']}]
            if method == 'GET' and path == '/networks' else
            network if method == 'GET' and path == '/networks/' + network['Id'] else
            (_ for _ in ()).throw(AssertionError((method, path))))

        with self.assertRaises(DockerEngineError):
            engine.ollama_route_policies()

    def test_ollama_route_inventory_rejects_ambiguous_connected_route_without_prefsrc(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config)
        instance_id = '0' * 32
        plan = engine._ollama_network_plan(instance_id, engine.ollama_network_pool)
        payload = engine._ollama_network_payload(instance_id, plan)
        network = {**payload, 'Id': 'd' * 64, 'Ingress': False, 'Containers': {}}
        ambiguous = IPv4Route(
            plan['subnet'], plan['bridge'], 'unicast', 'kernel', 'link', None)
        engine.host_route_provider = lambda: synthetic_ollama_host_inventory(
            plan, extra_routes=(ambiguous,))
        engine._request = lambda method, path, payload=None, *, ok=(200,): (
            [{'Id': network['Id'], 'Name': network['Name'], 'IPAM': network['IPAM'],
              'Labels': network['Labels']}]
            if method == 'GET' and path == '/networks' else
            network if method == 'GET' and path == '/networks/' + network['Id'] else
            (_ for _ in ()).throw(AssertionError((method, path))))

        with self.assertRaises(DockerEngineError):
            engine.ollama_route_policies()

    def test_ollama_route_is_firewall_ready_before_gateway_network_connect(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        instance_id = '5' * 32
        gateway_id, network_id = 'a' * 64, 'b' * 64
        events = []

        class RouteFirewall:
            can_apply = True
            def __init__(self):
                self.active = False
                self.events = events
            def ready(self, policies):
                self.events.append(('firewall', 'ready', tuple(policies)))
                return self.active
            def apply(self, policies):
                self.events.append(('firewall', 'apply', tuple(policies)))
                self.active = True

        firewall = RouteFirewall()
        host_inventory_state = {'inventory': HostIPv4Inventory((), ())}
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config,
            ollama_firewall=firewall,
            host_route_provider=lambda: host_inventory_state['inventory'])
        engine.__dict__['_find'] = lambda instance_id: {
            'Id': gateway_id,
            'Config': {'Labels': {
                **engine._labels(instance_id),
                engine.SPEC_LABEL: json.dumps({'version': 3, 'config_policy_version': 1}),
            }},
            'State': {'Status': 'created'},
            'NetworkSettings': {'Networks': {}},
        }
        engine._verify = lambda *_args, **_kwargs: gateway_id
        network_state: dict[str, Any] = {'created': None}

        def request(method, path, payload=None, *, ok=(200,)):
            events.append(('docker', method, path, copy.deepcopy(payload)))
            if method == 'GET' and path == '/networks':
                network = network_state['created']
                return [] if network is None else [{
                    'Id': network_id, 'Name': network['Name'],
                    'IPAM': network['IPAM'], 'Labels': network['Labels'],
                }]
            if method == 'POST' and path == '/networks/create':
                assert payload is not None
                network_state['created'] = {
                    **payload, 'Id': network_id, 'Ingress': False, 'Containers': {},
                }
                config = payload['IPAM']['Config'][0]
                host_inventory_state['inventory'] = synthetic_ollama_host_inventory({
                    'subnet': config['Subnet'],
                    'gateway': config['Gateway'],
                    'bridge': payload['Options']['com.docker.network.bridge.name'],
                })
                return {'Id': network_id}
            if method == 'GET' and path == '/networks/' + network_id:
                return network_state['created']
            raise AssertionError((method, path))

        def attach(container_id, actual_network_id, network_name, ipv4):
            events.append(('connect', container_id, actual_network_id, network_name, ipv4))
            network_state['created']['Containers'][gateway_id] = {
                'Name': 'pa-' + instance_id,
                'EndpointID': 'f' * 64, 'MacAddress': '02:42:ac:11:00:02',
                'IPv4Address': ipv4 + '/29', 'IPv6Address': '',
            }
            engine.__dict__['_find'] = lambda instance_id: {
                'Id': gateway_id,
                'Config': {'Labels': {
                    **engine._labels(instance_id),
                    engine.SPEC_LABEL: json.dumps({'version': 3, 'config_policy_version': 1}),
                }},
                'State': {'Status': 'created'},
                'NetworkSettings': {'Networks': {network_name: {
                    'NetworkID': actual_network_id, 'IPAddress': ipv4,
                    'IPAMConfig': {'IPv4Address': ipv4},
                }}},
            }
            return engine._find(instance_id)

        engine._request = request
        engine.__dict__['_ensure_container_network'] = attach

        result = engine.ensure_ollama_route(instance_id)

        self.assertTrue(result['ready'])
        create_event = next(event for event in events if event[1:3] == ('POST', '/networks/create'))
        connect_index = next(index for index, event in enumerate(events) if event[0] == 'connect')
        apply_index = next(index for index, event in enumerate(events)
                           if event[:2] == ('firewall', 'apply'))
        self.assertFalse(create_event[3]['Internal'])
        self.assertLess(apply_index, connect_index)
        self.assertEqual(len(events[-1][2]), 1)

    def test_failed_gateway_attach_rolls_back_new_empty_route_and_firewall_rules(self):
        from supervisor.ollama_firewall import OllamaRoutePolicy

        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        instance_id, gateway_id, network_id = '1' * 32, 'a' * 64, 'b' * 64

        class RouteFirewall:
            can_apply = True
            def __init__(self):
                self.applied = None
            def ready(self, policies):
                return self.applied == tuple(policies)
            def apply(self, policies):
                self.applied = tuple(policies)

        firewall = RouteFirewall()
        host_state: dict[str, Any] = {'inventory': HostIPv4Inventory((), ())}
        network_state: dict[str, Any] = {'network': None}
        events = []
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config,
            ollama_firewall=firewall,
            host_route_provider=lambda: host_state['inventory'])
        plan = engine._ollama_network_plan(instance_id, engine.ollama_network_pool)
        policy = OllamaRoutePolicy(
            instance_id, plan['subnet'], plan['gateway'], plan['gateway_ip'],
            '10.99.0.10', 'ens18')
        gateway = {
            'Id': gateway_id,
            'Config': {'Labels': {
                **engine._labels(instance_id),
                engine.SPEC_LABEL: json.dumps({'version': 3, 'config_policy_version': 1}),
            }},
            'State': {'Status': 'created'},
            'NetworkSettings': {'Networks': {}},
        }
        engine.__dict__['_find'] = lambda instance_id: gateway
        engine.__dict__['_verify'] = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        engine.__dict__['ollama_route_policies'] = lambda: (
            (policy,) if network_state['network'] is not None else ())

        def request(method, path, payload=None, *, ok=(200,)):
            events.append((method, path))
            if method == 'GET' and path == '/networks':
                current = network_state['network']
                return [] if current is None else [{
                    'Id': network_id, 'Name': current['Name'],
                    'IPAM': current['IPAM'], 'Labels': current['Labels'],
                }]
            if method == 'POST' and path == '/networks/create':
                assert payload is not None
                network_state['network'] = {
                    **payload, 'Id': network_id, 'Ingress': False, 'Containers': {},
                }
                ipam = payload['IPAM']['Config'][0]
                host_state['inventory'] = synthetic_ollama_host_inventory({
                    'subnet': ipam['Subnet'], 'gateway': ipam['Gateway'],
                    'bridge': payload['Options']['com.docker.network.bridge.name'],
                })
                return {'Id': network_id}
            if method == 'GET' and path.startswith('/networks?filters='):
                return [] if network_state['network'] is None else [{'Id': network_id}]
            if method == 'GET' and path == '/networks/' + network_id:
                return network_state['network']
            if method == 'DELETE' and path == '/networks/' + network_id:
                network_state['network'] = None
                return None
            raise AssertionError((method, path))

        def fail_attach(container_id, actual_network_id, network_name, ipv4):
            raise DockerEngineError('synthetic attach failure')

        engine._request = request
        engine.__dict__['_ensure_container_network'] = fail_attach

        with self.assertRaises(DockerEngineError):
            engine.ensure_ollama_route(instance_id)

        self.assertIsNone(network_state['network'])
        self.assertEqual(firewall.applied, ())
        self.assertIn(('DELETE', '/networks/' + network_id), events)

    def test_existing_route_attach_failure_preserves_network_but_keeps_gateway_stopped(self):
        from supervisor.ollama_firewall import OllamaRoutePolicy

        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        instance_id, gateway_id, network_id = '6' * 32, 'a' * 64, 'b' * 64

        class RouteFirewall:
            can_apply = True
            def __init__(self, policy):
                self.applied = (policy,)
            def ready(self, policies):
                return self.applied == tuple(policies)
            def apply(self, policies):
                self.applied = tuple(policies)

        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config)
        plan = engine._ollama_network_plan(instance_id, engine.ollama_network_pool)
        policy = OllamaRoutePolicy(
            instance_id, plan['subnet'], plan['gateway'], plan['gateway_ip'],
            '10.99.0.10', 'ens18')
        firewall = RouteFirewall(policy)
        engine.ollama_firewall = firewall
        engine.host_route_provider = lambda: synthetic_ollama_host_inventory(plan)
        network_payload = engine._ollama_network_payload(instance_id, plan)
        network: dict[str, Any] = {
            **network_payload, 'Id': network_id, 'Ingress': False, 'Containers': {},
        }
        gateway = {
            'Id': gateway_id,
            'Config': {'Labels': {
                **engine._labels(instance_id),
                engine.SPEC_LABEL: json.dumps({'version': 3, 'config_policy_version': 1}),
            }},
            'State': {'Status': 'created'},
            'NetworkSettings': {'Networks': {}},
        }
        engine.__dict__['_find'] = lambda instance_id: gateway
        engine.__dict__['_find_proxy_sidecar'] = lambda instance_id: None
        engine.__dict__['_verify'] = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        engine.__dict__['_proxy_firewall_ready'] = lambda instance_id, gateway_spec: True
        calls = []

        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path))
            if method == 'GET' and path == '/networks':
                return [{'Id': network_id, 'Name': network['Name'],
                         'IPAM': network['IPAM'], 'Labels': network['Labels']}]
            if method == 'GET' and path == '/networks/' + network_id:
                return network
            raise AssertionError((method, path))

        def attach_then_lose_response(container_id, actual_network_id, network_name, ipv4):
            network['Containers'][gateway_id] = {'IPv4Address': ipv4 + '/29'}
            gateway['NetworkSettings']['Networks'][network_name] = {
                'NetworkID': actual_network_id, 'IPAddress': ipv4,
                'IPAMConfig': {'IPv4Address': ipv4},
            }
            raise DockerEngineError('synthetic lost network-connect response')

        engine._request = request
        engine.__dict__['_ensure_container_network'] = attach_then_lose_response

        with self.assertRaises(DockerEngineError):
            engine.start(instance_id)

        self.assertEqual(gateway['State']['Status'], 'created')
        self.assertEqual(network['Containers'][gateway_id]['IPv4Address'],
                         plan['gateway_ip'] + '/29')
        self.assertNotIn(('DELETE', '/networks/' + network_id), calls)
        self.assertFalse(any(path.endswith('/start') for _, path in calls))
        self.assertEqual(firewall.applied, (policy,))

    def test_purge_route_network_removes_only_empty_bridge_and_rebuilds_firewall(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        instance_id, network_id = '2' * 32, 'c' * 64

        class RouteFirewall:
            can_apply = True
            def __init__(self):
                self.applied = None
                self.calls = []
            def ready(self, policies):
                self.calls.append(('ready', tuple(policies)))
                return self.applied == tuple(policies)
            def apply(self, policies):
                self.calls.append(('apply', tuple(policies)))
                self.applied = tuple(policies)

        firewall = RouteFirewall()
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config,
            ollama_firewall=firewall,
            host_route_provider=lambda: synthetic_ollama_host_inventory(plan))
        plan = engine._ollama_network_plan(instance_id, engine.ollama_network_pool)
        payload = engine._ollama_network_payload(instance_id, plan)
        network_state: dict[str, Any] = {'network': {
            **payload, 'Id': network_id, 'Ingress': False, 'Containers': {},
        }}
        events = []

        def request(method, path, payload=None, *, ok=(200,)):
            events.append((method, path))
            if method == 'GET' and path.startswith('/networks?filters='):
                current = network_state['network']
                return [] if current is None else [{'Id': network_id}]
            if method == 'GET' and path == '/networks/' + network_id:
                return network_state['network']
            if method == 'GET' and path == '/networks':
                current = network_state['network']
                return [] if current is None else [{
                    'Id': network_id, 'Name': current['Name'],
                    'IPAM': current['IPAM'], 'Labels': current['Labels'],
                }]
            if method == 'DELETE' and path == '/networks/' + network_id:
                network_state['network'] = None
                return None
            raise AssertionError((method, path))

        engine._request = request
        engine._find = lambda instance_id: None

        self.assertTrue(engine.remove_ollama_network(instance_id))
        self.assertIn(('DELETE', '/networks/' + network_id), events)
        self.assertEqual(firewall.applied, ())
        self.assertEqual(firewall.calls[-1], ('ready', ()))

    def test_ollama_route_creation_rejects_unparseable_docker_ipam_inventory(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        instance_id, gateway_id = '9' * 32, 'a' * 64
        firewall = SimpleNamespace(can_apply=True)
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config,
            ollama_firewall=firewall,
            host_route_provider=lambda: HostIPv4Inventory((), ()))
        instance_id_for_gateway = instance_id
        engine.__dict__['_find'] = lambda instance_id: {
            'Id': gateway_id,
            'Config': {'Labels': {
                **engine._labels(instance_id_for_gateway),
                engine.SPEC_LABEL: json.dumps({'version': 3, 'config_policy_version': 1}),
            }},
            'State': {'Status': 'created'},
            'NetworkSettings': {'Networks': {}},
        }
        engine.__dict__['_verify'] = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        calls = []
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path))
            if method == 'GET' and path == '/networks':
                return [{'Id': 'b' * 64, 'Name': 'foreign',
                         'IPAM': {'Config': [{'Subnet': None}]}}]
            raise AssertionError((method, path))
        engine._request = request

        with self.assertRaises(DockerEngineError):
            engine.ensure_ollama_route(instance_id)

        self.assertFalse(any(path == '/networks/create' for _, path in calls))

    def test_proxy_network_engine_requires_both_nonoverlapping_admin_pools(self):
        image = 'sha256:' + 'a' * 64
        with self.assertRaises(ValueError):
            DockerEngine(image, agent_network_pool='10.240.0.0/13')
        with self.assertRaises(ValueError):
            DockerEngine(image, agent_network_pool='10.240.0.0/13',
                         frontend_network_pool='10.240.0.0/12')
        engine = DockerEngine(image, agent_network_pool='10.240.0.0/13',
                              frontend_network_pool='10.248.0.0/13')
        self.assertEqual(engine.agent_network_pool, '10.240.0.0/13')
        self.assertEqual(engine.frontend_network_pool, '10.248.0.0/13')

    def test_proxy_network_policy_inventory_groups_both_exact_networks(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.248.0.0/24',
                              frontend_network_pool='10.249.0.0/24')
        instance_id = '6' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        agent_payload = engine._proxy_network_payload(instance_id, plan['agent'], role='agent')
        frontend_payload = engine._proxy_network_payload(instance_id, plan['frontend'], role='frontend')
        state = {'a' * 64: {**agent_payload, 'Id': 'a' * 64, 'Ingress': False, 'Containers': {}},
                 'b' * 64: {**frontend_payload, 'Id': 'b' * 64, 'Ingress': False, 'Containers': {}}}
        engine._request = lambda method, path, payload=None, *, ok=(200,): (
            [{'Id': key, 'Name': value['Name'], 'IPAM': value['IPAM'], 'Labels': value['Labels']}
             for key, value in state.items()]
            if method == 'GET' and path == '/networks' else
            state[path.rsplit('/', 1)[1]] if method == 'GET' and path.startswith('/networks/') else
            (_ for _ in ()).throw(AssertionError((method, path))))
        policies = engine.proxy_network_policies()
        self.assertEqual(policies, (engine._proxy_firewall_policy(instance_id, plan),))

    def test_boot_firewall_restore_applies_and_verifies_the_exact_proxy_inventory(self):
        class Firewall:
            can_apply = True
            def __init__(self):
                self.applied = None
                self.calls = []
            def apply(self, policies):
                self.calls.append(('apply', policies))
                self.applied = policies
            def ready(self, policies):
                self.calls.append(('ready', policies))
                return self.applied == policies

        firewall = Firewall()
        engine = DockerEngine('sha256:' + 'a' * 64, firewall=firewall)
        policies = (SimpleNamespace(instance_id='1' * 32), SimpleNamespace(instance_id='2' * 32))
        engine.proxy_network_policies = lambda: policies

        result = engine.restore_firewall()

        self.assertEqual(result, {
            'policy_count': 2, 'instance_ids': ['1' * 32, '2' * 32], 'ready': True,
        })
        self.assertEqual(firewall.calls, [
            ('ready', policies), ('apply', policies), ('ready', policies),
        ])

    def test_boot_firewall_restore_applies_receipt_gated_ollama_route_inventory(self):
        from supervisor.ollama_firewall import OllamaRoutePolicy

        class RouteFirewall:
            can_apply = True
            def __init__(self):
                self.applied = None
                self.calls = []
            def apply(self, policies):
                self.calls.append(('apply', policies))
                self.applied = policies
            def ready(self, policies):
                self.calls.append(('ready', policies))
                return self.applied == policies

        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        route_firewall = RouteFirewall()
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.240.0.0/13',
            frontend_network_pool='10.248.0.0/13',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config,
            ollama_firewall=route_firewall)
        policy = OllamaRoutePolicy(
            '1' * 32, '172.20.0.0/29', '172.20.0.1', '172.20.0.2',
            '10.99.0.10', 'ens18')
        engine.__dict__['proxy_network_policies'] = lambda: ()
        engine.__dict__['ollama_route_policies'] = lambda: (policy,)

        result = engine.restore_firewall()

        self.assertEqual(result, {
            'policy_count': 1, 'instance_ids': ['1' * 32], 'ready': True,
        })
        self.assertEqual(route_firewall.calls, [
            ('ready', (policy,)), ('apply', (policy,)), ('ready', (policy,)),
        ])

    def test_boot_firewall_restore_does_not_mutate_rules_when_no_proxy_networks_exist(self):
        class Firewall:
            can_apply = True
            def apply(self, _policies):
                raise AssertionError('empty boot inventory must not remove managed rules')
            def ready(self, _policies):
                raise AssertionError('empty boot inventory does not need firewall read-back')

        engine = DockerEngine('sha256:' + 'a' * 64, firewall=Firewall())
        engine.proxy_network_policies = lambda: ()
        self.assertEqual(engine.restore_firewall(), {
            'policy_count': 0, 'instance_ids': [], 'ready': True,
        })

    def test_boot_firewall_restore_fails_closed_without_receipt_gate(self):
        class Firewall:
            can_apply = False
            def apply(self, _policies):
                raise AssertionError('unvalidated firewall must not be written')
            def ready(self, _policies):
                return False

        engine = DockerEngine('sha256:' + 'a' * 64, firewall=Firewall())
        engine.proxy_network_policies = lambda: ('verified-policy',)
        with self.assertRaises(DockerEngineError):
            engine.restore_firewall()

    def test_proxy_network_policy_inventory_rejects_partial_instance_networks(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.248.0.0/24',
                              frontend_network_pool='10.249.0.0/24')
        instance_id = '7' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        payload = engine._proxy_network_payload(instance_id, plan['agent'], role='agent')
        state = {'a' * 64: {**payload, 'Id': 'a' * 64, 'Ingress': False, 'Containers': {}}}
        engine._request = lambda method, path, payload=None, *, ok=(200,): (
            [{'Id': key, 'Name': value['Name'], 'IPAM': value['IPAM'], 'Labels': value['Labels']}
             for key, value in state.items()]
            if method == 'GET' and path == '/networks' else
            state[path.rsplit('/', 1)[1]] if method == 'GET' and path.startswith('/networks/') else
            (_ for _ in ()).throw(AssertionError((method, path))))
        with self.assertRaises(DockerEngineError):
            engine.proxy_network_policies()

    def test_proxy_network_plan_uses_site_pools_and_fixed_private_addresses(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = '1' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.240.0.0/24',
            frontend_network_pool='10.241.0.0/24',
            occupied_subnets=('10.240.0.0/29', '10.241.0.0/29'))
        self.assertEqual(plan['agent']['name'], 'pa-agent-' + instance_id)
        self.assertEqual(plan['frontend']['name'], 'pa-front-' + instance_id)
        self.assertEqual(plan['agent']['bridge'], 'bza' + instance_id[:12])
        self.assertEqual(plan['frontend']['bridge'], 'bzf' + instance_id[:12])
        self.assertEqual(plan['agent']['subnet'], '10.240.0.8/29')
        self.assertEqual(plan['frontend']['subnet'], '10.241.0.8/29')
        self.assertEqual(plan['agent']['gateway'], '10.240.0.9')
        self.assertEqual(plan['agent']['sidecar_ip'], '10.240.0.10')
        self.assertEqual(plan['agent']['gateway_ip'], '10.240.0.11')
        self.assertEqual(plan['frontend']['gateway'], '10.241.0.9')
        self.assertEqual(plan['frontend']['web_ip'], '10.241.0.10')
        self.assertEqual(plan['frontend']['sidecar_ip'], '10.241.0.11')

    def test_proxy_network_plan_rejects_nondefault_host_route_overlap(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        with self.assertRaises(DockerEngineError):
            engine._proxy_network_plan(
                '3' * 32, agent_network_pool='10.240.0.0/24',
                frontend_network_pool='10.241.0.0/24',
                host_routes=('0.0.0.0/0', '10.0.0.0/8'))
        plan = engine._proxy_network_plan(
            '4' * 32, agent_network_pool='10.240.0.0/24',
            frontend_network_pool='10.241.0.0/24',
            host_routes=('0.0.0.0/0',))
        self.assertEqual(plan['agent']['subnet'], '10.240.0.0/29')

    def test_proxy_network_plan_skips_conflicting_host_route_and_uses_next_free_subnet(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        plan = engine._proxy_network_plan(
            '5' * 32, agent_network_pool='10.240.0.0/24',
            frontend_network_pool='10.241.0.0/24',
            host_routes=('10.240.0.0/29', '10.241.0.0/29'))
        self.assertEqual(plan['agent']['subnet'], '10.240.0.8/29')
        self.assertEqual(plan['frontend']['subnet'], '10.241.0.8/29')

    def test_proxy_network_payload_pins_bridge_ipam_and_internal_policy(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = '2' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.242.0.0/24',
            frontend_network_pool='10.243.0.0/24')
        agent = engine._proxy_network_payload(instance_id, plan['agent'], role='agent')
        frontend = engine._proxy_network_payload(instance_id, plan['frontend'], role='frontend')
        for payload, name, bridge in (
            (agent, 'pa-agent-' + instance_id, 'bza' + instance_id[:12]),
            (frontend, 'pa-front-' + instance_id, 'bzf' + instance_id[:12]),
        ):
            with self.subTest(name=name):
                self.assertEqual(payload['Name'], name)
                self.assertEqual(payload['Driver'], 'bridge')
                self.assertIs(payload['Internal'], True)
                self.assertIs(payload['Attachable'], False)
                self.assertIs(payload['EnableIPv6'], False)
                self.assertEqual(payload['Options']['com.docker.network.bridge.name'], bridge)
                self.assertEqual(payload['Options']['com.docker.network.bridge.enable_ip_masquerade'], 'false')
                self.assertEqual(payload['IPAM']['Config'][0]['Subnet'],
                                 plan['agent' if name.startswith('pa-agent-') else 'frontend']['subnet'])

    def test_web_sidecar_image_discovery_uses_unique_labeled_running_container_and_digest_id(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        container_id = '7' * 64
        image_id = 'sha256:' + 'c' * 64
        domain = 'agents.example.test'
        calls = []
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path))
            if method == 'GET' and path.startswith('/containers/json?'):
                return [{'Id': container_id, 'State': 'running'}]
            if method == 'GET' and path == f'/containers/{container_id}/json':
                return {'Id': container_id, 'Image': image_id,
                        'State': {'Running': True, 'Status': 'running'},
                        'NetworkSettings': {'Networks': {'web': {
                            'NetworkID': 'e' * 64, 'Gateway': '172.30.0.1',
                            'IPAddress': '172.30.0.2'}}},
                        'Config': {'Labels': {
                            engine.CONTROL_PLANE_LABEL: 'true',
                            'com.docker.compose.project': 'personal-agent-platform'},
                            'Env': ['AGENT_CONTROL_UI_DOMAIN=' + domain,
                                    'FORWARDED_ALLOW_IPS=127.0.0.1,172.30.0.1']}}
            if method == 'GET' and path == '/networks/' + 'e' * 64:
                return {'Id': 'e' * 64, 'Name': 'web', 'Driver': 'bridge',
                        'Internal': False, 'EnableIPv6': False,
                        'Labels': {'com.docker.compose.project': 'personal-agent-platform',
                                   'com.docker.compose.network': 'web'},
                        'IPAM': {'Config': [{'Subnet': '172.30.0.0/24',
                                             'Gateway': '172.30.0.1'}]}}
            if method == 'GET' and path.startswith('/images/'):
                return {'Id': image_id, 'Config': {'Volumes': None}}
            raise AssertionError((method, path))
        engine._request = request
        self.assertEqual(engine._discover_control_plane_image(domain), image_id)
        self.assertTrue(any(path.startswith('/images/') for _, path in calls))

    def test_sidecar_token_file_is_created_private_and_owned_by_runtime_uid(self):
        from types import SimpleNamespace
        engine = DockerEngine('sha256:' + 'a' * 64)
        path = '/srv/agent-data/' + '8' * 32
        token = 'S' * 43
        state = {'content': b'', 'file_flags': None, 'owned': None}
        def fake_open(name, flags, mode=0o777, *, dir_fd=None):
            if name == path and dir_fd is None:
                return 10
            if name == engine.PROXY_TOKEN_FILE_HOST and dir_fd == 10:
                state['file_flags'] = flags
                return 11
            raise AssertionError((name, flags, dir_fd))
        def fake_fstat(fd):
            if fd == 10:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0,
                                       st_gid=0, st_nlink=2, st_size=0)
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000,
                                   st_gid=1000, st_nlink=1, st_size=len(state['content']))
        with ExitStack() as stack:
            stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0x20000, create=True))
            stack.enter_context(patch.object(os, 'O_DIRECTORY', 0x40000, create=True))
            stack.enter_context(patch.object(os, 'open', side_effect=fake_open))
            stack.enter_context(patch.object(os, 'fstat', side_effect=fake_fstat))
            stack.enter_context(patch.object(os, 'fchown', side_effect=lambda fd, uid, gid: state.update(owned=(uid, gid)), create=True))
            stack.enter_context(patch.object(os, 'fchmod', create=True))
            stack.enter_context(patch.object(os, 'write', side_effect=lambda fd, data: (state.update(content=bytes(data)) or len(data))))
            stack.enter_context(patch.object(os, 'read', side_effect=lambda fd, size: state['content'][:size]))
            stack.enter_context(patch.object(os, 'lseek', return_value=0))
            stack.enter_context(patch.object(os, 'fsync'))
            stack.enter_context(patch.object(os, 'close'))
            stack.enter_context(patch.object(secrets, 'token_urlsafe', return_value=token))
            self.assertEqual(engine._ensure_proxy_token_file(path), token)
        self.assertEqual(state['owned'], (1000, 1000))
        self.assertEqual(state['content'], token.encode('ascii'))
        self.assertTrue(state['file_flags'] & 0x20000)

    def test_proxy_token_target_read_is_read_only_and_rejects_symlink_flags(self):
        from types import SimpleNamespace
        engine = DockerEngine('sha256:' + 'a' * 64)
        path = '/srv/agent-data/' + '1' * 32
        token = 'T' * 43
        opened = []
        def fake_open(name, flags, mode=0o777, *, dir_fd=None):
            opened.append((name, flags, dir_fd))
            return 10 if dir_fd is None else 11
        def fake_fstat(fd):
            return (SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0,
                                    st_gid=0, st_nlink=2, st_size=0) if fd == 10 else
                    SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000,
                                    st_gid=1000, st_nlink=1, st_size=43))
        with ExitStack() as stack:
            stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0x20000, create=True))
            stack.enter_context(patch.object(os, 'O_DIRECTORY', 0x40000, create=True))
            stack.enter_context(patch.object(os, 'open', side_effect=fake_open))
            stack.enter_context(patch.object(os, 'fstat', side_effect=fake_fstat))
            stack.enter_context(patch.object(os, 'read', return_value=token.encode('ascii')))
            stack.enter_context(patch.object(os, 'lseek', return_value=0))
            stack.enter_context(patch.object(os, 'close'))
            self.assertEqual(engine._read_existing_proxy_token_file(path), token)
        file_flags = opened[1][1]
        self.assertTrue(file_flags & 0x20000)
        self.assertFalse(file_flags & os.O_CREAT)
        self.assertFalse(file_flags & os.O_RDWR)

    def test_sidecar_secret_helpers_reject_nonroot_parent_directory_owner(self):
        from types import SimpleNamespace
        engine = DockerEngine('sha256:' + 'a' * 64)
        path = '/srv/agent-data/' + '2' * 32
        opened = []

        def fake_open(name, flags, mode=0o777, *, dir_fd=None):
            opened.append((name, dir_fd))
            if name == path and dir_fd is None:
                return 10
            raise PermissionError('mock child open')

        def fake_fstat(_fd):
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000,
                                   st_gid=1000, st_nlink=2, st_size=0)

        for helper_name in ('_read_existing_proxy_token_file', '_ensure_proxy_token_file'):
            with self.subTest(helper=helper_name):
                opened.clear()
                with ExitStack() as stack:
                    stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0x20000, create=True))
                    stack.enter_context(patch.object(os, 'O_DIRECTORY', 0x40000, create=True))
                    stack.enter_context(patch.object(os, 'open', side_effect=fake_open))
                    stack.enter_context(patch.object(os, 'fstat', side_effect=fake_fstat))
                    stack.enter_context(patch.object(os, 'close'))
                    with self.assertRaises(DockerEngineError):
                        getattr(engine, helper_name)(path)
                self.assertEqual(opened, [(path, None)])

    def test_proxy_firewall_policy_maps_both_networks_and_static_endpoint_pairs(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = '9' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.250.0.0/24',
            frontend_network_pool='10.251.0.0/24')
        policy = engine._proxy_firewall_policy(instance_id, plan)
        self.assertEqual(policy.agent_subnet, plan['agent']['subnet'])
        self.assertEqual(policy.frontend_subnet, plan['frontend']['subnet'])
        self.assertEqual(policy.agent_bridge, plan['agent']['bridge'])
        self.assertEqual(policy.frontend_bridge, plan['frontend']['bridge'])
        self.assertEqual({policy.agent_pair.left, policy.agent_pair.right},
                         {plan['agent']['sidecar_ip'], plan['agent']['gateway_ip']})
        self.assertEqual({policy.frontend_pair.left, policy.frontend_pair.right},
                         {plan['frontend']['web_ip'], plan['frontend']['sidecar_ip']})

    def test_sidecar_discovery_isolated_from_gateway_container_search(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = 'a' * 32
        sidecar_id = 'b' * 64
        inspect = {'Id': sidecar_id,
                   'Config': {'Labels': {
                       engine.INSTANCE_LABEL: instance_id,
                       engine.SIDECAR_ROLE_LABEL: engine.SIDECAR_ROLE,
                   }}}
        def request(method, path, payload=None, *, ok=(200,)):
            if method == 'GET' and path.startswith('/containers/json?'):
                return [{'Id': sidecar_id}]
            if method == 'GET' and path == f'/containers/{sidecar_id}/json':
                return inspect
            raise AssertionError((method, path))
        engine._request = request
        self.assertEqual(engine._find_proxy_sidecar(instance_id), inspect)

    def test_container_network_created_accepts_static_ipam_before_live_endpoint_exists(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        container_id, network_id = 'c' * 64, 'd' * 64
        network_name, address = 'pa-agent-' + 'e' * 32, '10.251.0.2'
        observed = {
            'Id': container_id, 'State': {'Status': 'created'},
            'NetworkSettings': {'Networks': {network_name: {
                'NetworkID': '', 'IPAddress': '',
                'IPAMConfig': {'IPv4Address': address},
            }}},
        }
        calls = []
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path, payload))
            if method == 'GET' and path == f'/containers/{container_id}/json':
                return observed
            raise AssertionError((method, path, payload))
        engine._request = request
        self.assertEqual(engine._ensure_container_network(
            container_id, network_id, network_name, address), observed)
        self.assertFalse(any(method == 'POST' for method, *_ in calls))
        endpoint = observed['NetworkSettings']['Networks'][network_name]
        endpoint['IPAMConfig']['IPv4Address'] = '10.251.0.99'
        with self.assertRaises(DockerEngineError):
            engine._ensure_container_network(container_id, network_id, network_name, address)
        endpoint['IPAMConfig']['IPv4Address'] = address
        endpoint['NetworkID'] = 'f' * 64
        with self.assertRaises(DockerEngineError):
            engine._ensure_container_network(container_id, network_id, network_name, address)
        endpoint['NetworkID'] = ''
        endpoint['IPAddress'] = '10.251.0.99'
        with self.assertRaises(DockerEngineError):
            engine._ensure_container_network(container_id, network_id, network_name, address)

    def test_container_network_attach_uses_static_ip_and_verifies_readback(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        container_id, network_id = 'c' * 64, 'd' * 64
        network_name, address = 'pa-front-' + 'e' * 32, '10.251.0.3'
        state = {'attached': False}
        calls = []
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path, payload))
            if method == 'GET' and path == f'/containers/{container_id}/json':
                networks = ({network_name: {
                    'NetworkID': network_id, 'IPAddress': address,
                    'IPAMConfig': {'IPv4Address': address}}}
                            if state['attached'] else {})
                return {'Id': container_id, 'State': {'Status': 'running'},
                        'NetworkSettings': {'Networks': networks}}
            if method == 'POST' and path == f'/networks/{network_id}/connect':
                assert payload is not None
                self.assertEqual(payload['EndpointConfig']['IPAMConfig']['IPv4Address'], address)
                state['attached'] = True
                return None
            raise AssertionError((method, path))
        engine._request = request
        result = engine._ensure_container_network(container_id, network_id, network_name, address)
        self.assertEqual(result['NetworkSettings']['Networks'][network_name]['IPAddress'], address)
        self.assertEqual(sum(method == 'POST' for method, *_ in calls), 1)

    def test_container_network_attach_rejects_wrong_existing_static_ip(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        container_id, network_id = 'c' * 64, 'd' * 64
        network_name, address = 'pa-front-' + 'e' * 32, '10.251.0.3'
        engine._request = lambda method, path, payload=None, *, ok=(200,): {
            'Id': container_id, 'State': {'Status': 'running'},
            'NetworkSettings': {'Networks': {
                network_name: {'NetworkID': network_id, 'IPAddress': '10.251.0.4',
                               'IPAMConfig': {'IPv4Address': address}}}}}
        with self.assertRaises(DockerEngineError):
            engine._ensure_container_network(container_id, network_id, network_name, address)

    def test_proxy_sidecar_verification_accepts_exact_networks_and_rejects_extra_attachment(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = 'f' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.252.0.0/24',
            frontend_network_pool='10.253.0.0/24')
        image_id = 'sha256:' + 'b' * 64
        image_info = self._sidecar_image_info(image_id, [
            'PATH=/usr/bin', 'HOME=/home/app',
            'WEBUI_SECRET_KEY=xxx',
            'OPENAI_API_KEY=yyy', 'PORT=18790',
        ])
        payload = engine._proxy_sidecar_payload(
            instance_id, owner_id='owner-f',
            control_ui_origin='https://' + instance_id + '.agents.example.test',
            gateway_ip=plan['agent']['gateway_ip'], listen_ip=plan['frontend']['sidecar_ip'],
            image_id=image_id,
            host_path='/srv/agent-data/' + instance_id, plan=plan, image_info=image_info)
        container_id, agent_id, frontend_id = 'a' * 64, 'c' * 64, 'd' * 64
        config = {key: copy.deepcopy(payload.get(key)) for key in (
            'Image', 'User', 'Entrypoint', 'Cmd', 'WorkingDir', 'Env',
            'Healthcheck', 'StopTimeout', 'Labels')}
        config['Env'] = ['PATH=/usr/bin', 'HOME=/home/app'] + [
            item for item in payload['Env'] if '=' in item] + [
            item for item in payload['Env'] if '=' not in item]
        mount = payload['HostConfig']['Mounts'][0]
        observed = {
            'Id': container_id, 'Image': payload['Image'], 'Config': config,
            'HostConfig': copy.deepcopy(payload['HostConfig']),
            'Mounts': [{'Type': 'bind', 'Source': mount['Source'],
                        'Destination': mount['Target'], 'RW': False}],
            'State': {'Status': 'running'},
            'NetworkSettings': {'Ports': {}, 'Networks': {
                plan['agent']['name']: {'NetworkID': agent_id,
                                        'IPAddress': plan['agent']['sidecar_ip'],
                                        'IPAMConfig': {'IPv4Address': plan['agent']['sidecar_ip']}},
                plan['frontend']['name']: {'NetworkID': frontend_id,
                                           'IPAddress': plan['frontend']['sidecar_ip'],
                                           'IPAMConfig': {'IPv4Address': plan['frontend']['sidecar_ip']}},
            }},
        }
        network_ids = {'agent': agent_id, 'frontend': frontend_id}
        self.assertEqual(engine._verify_proxy_sidecar(
            instance_id, observed, payload, plan, network_ids), container_id)
        config['Env'].append('UNEXPECTED')
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_sidecar(instance_id, observed, payload, plan, network_ids)
        config['Env'].pop()
        config['Env'].append('WEBUI_SECRET_KEY=bad')
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_sidecar(instance_id, observed, payload, plan, network_ids)
        config['Env'].pop()
        config['Env'].append('OPENAI_API_KEY=bad')
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_sidecar(instance_id, observed, payload, plan, network_ids)
        config['Env'].pop()
        observed['NetworkSettings']['Networks']['rogue'] = {}
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_sidecar(instance_id, observed, payload, plan, network_ids)
        observed['NetworkSettings']['Networks'].pop('rogue')
        observed['State'] = {'Status': 'created'}
        for role in ('agent', 'frontend'):
            endpoint = observed['NetworkSettings']['Networks'][plan[role]['name']]
            endpoint.update({'NetworkID': '', 'IPAddress': '',
                             'IPAMConfig': {'IPv4Address': plan[role]['sidecar_ip']}})
        self.assertEqual(engine._verify_proxy_sidecar(
            instance_id, observed, payload, plan, network_ids), container_id)
        observed['NetworkSettings']['Networks'][plan['agent']['name']][
            'IPAMConfig']['IPv4Address'] = '10.252.0.99'
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_sidecar(instance_id, observed, payload, plan, network_ids)
        endpoint = observed['NetworkSettings']['Networks'][plan['agent']['name']]
        endpoint['IPAMConfig']['IPv4Address'] = plan['agent']['sidecar_ip']
        endpoint['IPAddress'] = '10.252.0.99'
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_sidecar(instance_id, observed, payload, plan, network_ids)

    def test_proxy_sidecar_container_create_connects_agent_network_and_verifies(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = '9' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.250.0.0/24',
            frontend_network_pool='10.251.0.0/24')
        image_id = 'sha256:' + 'b' * 64
        image_env = [
            'PATH=/usr/bin', 'WEBUI_SECRET_KEY=xxx',
            'OPENAI_API_KEY=yyy',
        ]
        payload = engine._proxy_sidecar_payload(
            instance_id, owner_id='owner-9',
            control_ui_origin='https://' + instance_id + '.agents.example.test',
            gateway_ip=plan['agent']['gateway_ip'], listen_ip=plan['frontend']['sidecar_ip'],
            image_id=image_id, host_path='/srv/agent-data/' + instance_id,
            plan=plan, image_info=self._sidecar_image_info(image_id, image_env))
        sidecar_id, agent_network_id, frontend_network_id = 'a' * 64, 'c' * 64, 'd' * 64
        state = {'payload': None, 'agent_connected': False}
        calls = []
        def inspect_sidecar():
            networks = {plan['frontend']['name']: {
                'NetworkID': '', 'IPAddress': '',
                'IPAMConfig': {'IPv4Address': plan['frontend']['sidecar_ip']}}}
            if state['agent_connected']:
                networks[plan['agent']['name']] = {
                    'NetworkID': '', 'IPAddress': '',
                    'IPAMConfig': {'IPv4Address': plan['agent']['sidecar_ip']}}
            mount = payload['HostConfig']['Mounts'][0]
            config = {key: copy.deepcopy(payload.get(key)) for key in (
                'Image', 'User', 'Entrypoint', 'Cmd', 'WorkingDir', 'Env',
                'Healthcheck', 'StopTimeout', 'Labels')}
            config['Env'] = ['PATH=/usr/bin'] + [
                item for item in payload['Env'] if '=' in item]
            return {
                'Id': sidecar_id, 'Image': payload['Image'], 'Config': config,
                'HostConfig': copy.deepcopy(payload['HostConfig']),
                'Mounts': [{'Type': 'bind', 'Source': mount['Source'],
                            'Destination': mount['Target'], 'RW': False}],
                'State': {'Status': 'created'},
                'NetworkSettings': {'Ports': {}, 'Networks': networks},
            }
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path, copy.deepcopy(payload)))
            if method == 'GET' and path.startswith('/containers/json?'):
                return [{'Id': sidecar_id}] if state['payload'] is not None else []
            if method == 'POST' and path.startswith('/containers/create?'):
                state['payload'] = payload
                return {'Id': sidecar_id}
            if method == 'GET' and path == f'/containers/{sidecar_id}/json':
                return inspect_sidecar()
            if method == 'POST' and path == f'/networks/{agent_network_id}/connect':
                assert payload is not None
                self.assertEqual(payload['EndpointConfig']['IPAMConfig']['IPv4Address'],
                                 plan['agent']['sidecar_ip'])
                state['agent_connected'] = True
                return None
            raise AssertionError((method, path))
        engine._request = request
        self.assertEqual(engine._create_proxy_sidecar(instance_id, payload, plan, {
            'agent': agent_network_id, 'frontend': frontend_network_id}), sidecar_id)
        self.assertEqual(engine._create_proxy_sidecar(instance_id, payload, plan, {
            'agent': agent_network_id, 'frontend': frontend_network_id}), sidecar_id)
        self.assertTrue(state['agent_connected'])
        self.assertEqual(
            [item for item in state['payload']['Env'] if '=' not in item],
            ['OPENAI_API_KEY', 'WEBUI_SECRET_KEY'])
        self.assertNotIn('WEBUI_SECRET_KEY=xxx', json.dumps(state['payload']))
        self.assertNotIn('OPENAI_API_KEY=yyy', json.dumps(state['payload']))
        self.assertEqual(sum(method == 'POST' and path.startswith('/containers/create?')
                             for method, path, _ in calls), 1)
        self.assertEqual(sum(method == 'POST' and path == f'/networks/{agent_network_id}/connect'
                             for method, path, _ in calls), 1)

    def test_prepare_control_ui_connects_frontend_web_and_returns_agent_sidecar_identity(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = '5' * 32
        owner_id, domain = 'owner-5', 'agents.example.test'
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        web_id = 'e' * 64
        image_id = 'sha256:' + 'b' * 64
        events = []
        class ReadyFirewall:
            can_apply = True
            def apply(self, policies):
                events.append(('apply', policies))
            def ready(self, policies):
                return True
        engine.firewall = ReadyFirewall()
        engine.ensure_proxy_networks = lambda *_args, **_kwargs: plan
        engine.proxy_network_policies = lambda: (engine._proxy_firewall_policy(instance_id, plan),)
        engine._ensure_proxy_token_file = lambda _path: 'S' * 43
        engine._find_control_plane_web = lambda control_ui_domain: {
            'container_id': web_id, 'image_id': image_id,
            'image_info': self._sidecar_image_info(image_id), 'networks': {'web': {}},
            'docker_gateway': '172.30.0.1',
            'forwarded_allow_values': ('172.30.0.1',)}
        engine._proxy_network_id = lambda _instance, role, _expected: (
            'c' * 64 if role == 'agent' else 'd' * 64)
        endpoints = []
        engine.__dict__['_ensure_container_network'] = lambda container_id, network_id, network_name, ipv4: \
            (events.append(('web-attach', container_id, network_id)) or
             endpoints.append((container_id, network_id, network_name, ipv4)))
        payloads = []
        engine._proxy_sidecar_payload = lambda *args, **kwargs: {'fake': True}
        engine._find = lambda instance_id: None
        sidecar_id = 'f' * 64
        engine._create_proxy_sidecar = lambda instance_id, payload, plan, network_ids: (
            payloads.append('created') or sidecar_id)
        memberships = []
        engine.__dict__['_verify_proxy_network_membership'] = (
            lambda instance_id, role, network_id, expected_plan, expected_ids, **kwargs:
            (memberships.append((instance_id, role, network_id, expected_plan,
                                 expected_ids, kwargs)) or {}))
        result = engine.prepare_control_ui(instance_id, owner_id, domain,
                                           '/srv/agent-data/' + instance_id)
        self.assertEqual(result, {
            'sidecar_ip': plan['agent']['sidecar_ip'],
            'agent_subnet': plan['agent']['subnet'],
            'control_ui_origin': f'https://{instance_id}.{domain}',
        })
        self.assertEqual(endpoints, [(web_id, 'd' * 64, plan['frontend']['name'],
                                      plan['frontend']['web_ip'])])
        self.assertEqual(events[0][0], 'apply')
        self.assertLess(next(i for i, event in enumerate(events) if event[0] == 'apply'),
                        next(i for i, event in enumerate(events) if event[0] == 'web-attach'))
        self.assertEqual(payloads, ['created'])
        self.assertEqual([(item[1], item[4]) for item in memberships], [
            ('agent', {sidecar_id}), ('frontend', {web_id, sidecar_id})])

    def test_prepare_control_ui_refuses_to_attach_web_when_firewall_readiness_is_absent(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = '4' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        calls = []
        engine.ensure_proxy_networks = lambda *args, **kwargs: (calls.append('networks') or plan)
        with self.assertRaises(DockerEngineError):
            engine.prepare_control_ui(instance_id, 'owner-4', 'agents.example.test',
                                      '/srv/agent-data/' + instance_id)
        self.assertEqual(calls, [])

    def test_proxy_gateway_verify_accepts_created_ipam_then_requires_live_endpoint(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = 'b' * 32
        gateway_id, sidecar_id, network_id = 'c' * 64, 'd' * 64, 'e' * 64
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        origin = f'https://{instance_id}.agents.example.test'
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-b', control_ui_origin=origin)
        image_info = {'Id': engine.image,
                      'Config': {'Env': [], 'Entrypoint': [], 'WorkingDir': ''}}
        payload = engine._payload(instance_id, spec, None, image_info,
                                  proxy_network=plan['agent'])
        digest = engine._hash(engine._projection(
            payload, payload['HostConfig'], engine._expected_mounts(payload), image_info['Id']))
        payload['Labels'].update({engine.SPEC_LABEL: engine._json(spec),
                                  engine.CONFIG_LABEL: digest})
        attached = {'NetworkID': '', 'IPAddress': '',
                    'IPAMConfig': {'IPv4Address': plan['agent']['gateway_ip']}}
        observed = {
            'Id': gateway_id, 'Image': image_info['Id'],
            'Config': {key: copy.deepcopy(payload[key]) for key in (
                'Image', 'User', 'Cmd', 'Env', 'Entrypoint', 'WorkingDir',
                'Healthcheck', 'StopTimeout', 'Labels', 'Tty', 'OpenStdin', 'StdinOnce')},
            'HostConfig': copy.deepcopy(payload['HostConfig']),
            'Mounts': engine._expected_mounts(payload),
            'NetworkSettings': {'Ports': {}, 'Networks': {
                plan['agent']['name']: copy.deepcopy(attached)}},
            'State': {'Status': 'created'},
        }
        engine._image_info = lambda: image_info
        engine._proxy_network_id = lambda *_args, **_kwargs: network_id
        engine.__dict__['_find_proxy_sidecar'] = lambda instance_id: {'Id': sidecar_id}
        membership_calls = []
        engine._verify_proxy_network_membership = lambda *args, **kwargs: (
            membership_calls.append((args, kwargs)) or {})
        self.assertEqual(engine._verify(instance_id, observed, spec), gateway_id)
        self.assertTrue(membership_calls[0][1]['allow_unstarted'])
        for lifecycle in ('paused', 'restarting'):
            observed['State'] = {'Status': lifecycle}
            with self.assertRaises(DockerEngineError):
                engine._verify(instance_id, observed, spec)
        observed['State'] = {'Status': 'created'}

        observed['NetworkSettings']['Networks'][plan['agent']['name']]['IPAMConfig']['IPv4Address'] = '10.244.0.99'
        with self.assertRaises(DockerEngineError):
            engine._verify(instance_id, observed, spec)
        endpoint = observed['NetworkSettings']['Networks'][plan['agent']['name']]
        endpoint['IPAMConfig']['IPv4Address'] = plan['agent']['gateway_ip']
        endpoint['NetworkID'] = network_id
        endpoint['IPAddress'] = plan['agent']['gateway_ip']
        observed['State'] = {'Status': 'running'}
        self.assertEqual(engine._verify(instance_id, observed, spec), gateway_id)
        endpoint['NetworkID'] = ''
        with self.assertRaises(DockerEngineError):
            engine._verify(instance_id, observed, spec)
        endpoint['NetworkID'] = network_id
        endpoint['IPAddress'] = ''
        with self.assertRaises(DockerEngineError):
            engine._verify(instance_id, observed, spec)
        endpoint['IPAddress'] = '10.244.0.99'
        with self.assertRaises(DockerEngineError):
            engine._verify(instance_id, observed, spec)

    def test_proxy_gateway_verify_allows_only_receipt_route_as_second_network(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b',
            'context_tokens': 8192,
            'max_tokens': 512,
            'think': False,
        }
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.244.0.0/24',
            frontend_network_pool='10.245.0.0/24',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config)
        instance_id = '9' * 32
        gateway_id, sidecar_id = 'a' * 64, 'b' * 64
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        route_plan = engine._ollama_network_plan(instance_id, engine.ollama_network_pool)
        route_network_id = 'c' * 64
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-9',
                            control_ui_origin=f'https://{instance_id}.agents.example.test')
        image_info = {'Id': engine.image,
                      'Config': {'Env': [], 'Entrypoint': [], 'WorkingDir': ''}}
        payload = engine._payload(instance_id, spec, None, image_info,
                                  proxy_network=plan['agent'])
        digest = engine._hash(engine._projection(
            payload, payload['HostConfig'], engine._expected_mounts(payload), image_info['Id']))
        payload['Labels'].update({engine.SPEC_LABEL: engine._json(spec),
                                  engine.CONFIG_LABEL: digest})
        attached = {'NetworkID': 'd' * 64, 'IPAddress': plan['agent']['gateway_ip'],
                    'IPAMConfig': {'IPv4Address': plan['agent']['gateway_ip']}}
        route_attached = {
            'NetworkID': route_network_id, 'IPAddress': route_plan['gateway_ip'],
            'IPAMConfig': {'IPv4Address': route_plan['gateway_ip']},
        }
        observed = {
            'Id': gateway_id, 'Image': image_info['Id'],
            'Config': {key: copy.deepcopy(payload[key]) for key in (
                'Image', 'User', 'Cmd', 'Env', 'Entrypoint', 'WorkingDir',
                'Healthcheck', 'StopTimeout', 'Labels', 'Tty', 'OpenStdin', 'StdinOnce')},
            'HostConfig': copy.deepcopy(payload['HostConfig']),
            'Mounts': engine._expected_mounts(payload),
            'NetworkSettings': {'Ports': {}, 'Networks': {
                plan['agent']['name']: attached,
                'pa-ollama-' + instance_id: route_attached,
            }},
            'State': {'Status': 'created'},
        }
        engine._image_info = lambda: image_info
        engine._proxy_network_id = lambda *_args, **_kwargs: 'd' * 64
        engine.__dict__['_find_proxy_sidecar'] = lambda instance_id: {'Id': sidecar_id}
        membership_calls = []
        engine._verify_proxy_network_membership = lambda *args, **kwargs: (
            membership_calls.append((args, kwargs)) or {})
        route_checks = []
        engine.__dict__['_verify_ollama_network_attachment'] = lambda instance_id, container_id, observed: (
            route_checks.append((instance_id, container_id, observed)) or (route_network_id, route_plan))

        self.assertEqual(engine._verify(instance_id, observed, spec), gateway_id)
        self.assertEqual(len(route_checks), 1)
        observed['NetworkSettings']['Networks']['unapproved'] = {}
        with self.assertRaises(DockerEngineError):
            engine._verify(instance_id, observed, spec)

    def test_proxy_network_membership_allows_created_endpoint_without_runtime_member(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = '0' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        network_id, gateway_id, sidecar_id = 'a' * 64, 'b' * 64, 'c' * 64
        expected_ips = {gateway_id: plan['agent']['gateway_ip'],
                        sidecar_id: plan['agent']['sidecar_ip']}
        network = engine._proxy_network_payload(instance_id, plan['agent'], role='agent')
        network.update({'Id': network_id, 'Ingress': False, 'Containers': {}})
        containers = {
            container_id: {
                'Id': container_id, 'State': {'Status': 'created'},
                'NetworkSettings': {'Networks': {plan['agent']['name']: {
                    'NetworkID': '', 'IPAddress': '',
                    'IPAMConfig': {'IPv4Address': address}}}},
            }
            for container_id, address in expected_ips.items()
        }
        def request(method, path, payload=None, *, ok=(200,)):
            if method == 'GET' and path == f'/networks/{network_id}':
                return network
            if method == 'GET' and path.startswith('/containers/') and path.endswith('/json'):
                return containers[path.split('/')[2]]
            raise AssertionError((method, path))
        engine._request = request
        result = engine._verify_proxy_network_membership(
            instance_id, 'agent', network_id, plan['agent'], set(expected_ips),
            expected_ips=expected_ips, allow_unstarted=True)
        self.assertEqual(result, network)
        for lifecycle in ('paused', 'restarting'):
            containers[gateway_id]['State']['Status'] = lifecycle
            with self.assertRaises(DockerEngineError):
                engine._verify_proxy_network_membership(
                    instance_id, 'agent', network_id, plan['agent'], set(expected_ips),
                    expected_ips=expected_ips, allow_unstarted=True)
        containers[gateway_id]['State']['Status'] = 'created'
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_network_membership(
                instance_id, 'agent', network_id, plan['agent'], set(expected_ips),
                expected_ips=expected_ips)
        containers[sidecar_id]['NetworkSettings']['Networks'][plan['agent']['name']][
            'IPAMConfig']['IPv4Address'] = '10.244.0.99'
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_network_membership(
                instance_id, 'agent', network_id, plan['agent'], set(expected_ips),
                expected_ips=expected_ips, allow_unstarted=True)

    def test_proxy_network_membership_requires_running_runtime_membership_and_ip(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id, network_id, gateway_id = '0' * 32, 'a' * 64, 'b' * 64
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        address = plan['agent']['gateway_ip']
        network = engine._proxy_network_payload(instance_id, plan['agent'], role='agent')
        network.update({'Id': network_id, 'Ingress': False, 'Containers': {}})
        container = {
            'Id': gateway_id, 'State': {'Status': 'running'},
            'NetworkSettings': {'Networks': {plan['agent']['name']: {
                'NetworkID': network_id, 'IPAddress': address,
                'IPAMConfig': {'IPv4Address': address}}}},
        }
        engine._request = lambda method, path, payload=None, *, ok=(200,): (
            network if path == f'/networks/{network_id}' else container)
        expected_ips = {gateway_id: address}
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_network_membership(
                instance_id, 'agent', network_id, plan['agent'], {gateway_id},
                expected_ips=expected_ips, allow_unstarted=True)
        prefix = ipaddress.ip_network(plan['agent']['subnet']).prefixlen
        network['Containers'] = {gateway_id: {'IPv4Address': f'{address}/{prefix}'}}
        self.assertEqual(engine._verify_proxy_network_membership(
            instance_id, 'agent', network_id, plan['agent'], {gateway_id},
            expected_ips=expected_ips, allow_unstarted=True), network)
        self.assertEqual(engine._verify_proxy_network_membership(
            instance_id, 'agent', network_id, plan['agent'], {gateway_id},
            expected_ips=expected_ips), network)
        for lifecycle in ('paused', 'restarting'):
            container['State']['Status'] = lifecycle
            self.assertEqual(engine._verify_proxy_network_membership(
                instance_id, 'agent', network_id, plan['agent'], {gateway_id},
                expected_ips=expected_ips, allow_unstarted=True), network)
        container['State']['Status'] = 'running'
        network['Containers'][gateway_id]['IPv4Address'] = '10.244.0.99/29'
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_network_membership(
                instance_id, 'agent', network_id, plan['agent'], {gateway_id},
                expected_ips=expected_ips, allow_unstarted=True)

    def test_proxy_network_membership_rejects_unexpected_container_attachment(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = '0' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        network_id = 'a' * 64
        observed = engine._proxy_network_payload(instance_id, plan['agent'], role='agent')
        observed.update({'Id': network_id, 'Ingress': False,
                         'Containers': {'b' * 64: {}, 'c' * 64: {}}})
        engine._request = lambda method, path, payload=None, *, ok=(200,): observed
        with self.assertRaises(DockerEngineError):
            engine._verify_proxy_network_membership(
                instance_id, 'agent', network_id, plan['agent'], {'b' * 64},
                expected_ips={'b' * 64: plan['agent']['sidecar_ip']})

    def test_proxy_gateway_payload_uses_agent_network_without_gateway_token(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = 'b' * 32
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.244.0.0/24',
            frontend_network_pool='10.245.0.0/24')
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-b',
                            control_ui_origin='https://' + instance_id + '.agents.example.test')
        payload = engine._payload(
            instance_id, spec, None,
            {'Id': 'sha256:' + 'a' * 64, 'Config': {'Env': [], 'Entrypoint': [], 'WorkingDir': ''}},
            proxy_network=plan['agent'])
        env = dict(item.split('=', 1) for item in payload['Env'])
        self.assertNotIn('OPENCLAW_GATEWAY_TOKEN', env)
        self.assertEqual(payload['HostConfig']['NetworkMode'], plan['agent']['name'])
        self.assertEqual(payload['NetworkingConfig']['EndpointsConfig'][plan['agent']['name']]
                         ['IPAMConfig']['IPv4Address'], plan['agent']['gateway_ip'])
        self.assertEqual(payload['HostConfig']['PortBindings'], {})
        self.assertIs(payload['HostConfig']['PublishAllPorts'], False)

    def test_proxy_gateway_create_uses_trusted_network_and_never_receives_gateway_token(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = 'd' * 32
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        image_id, container_id = 'sha256:' + 'a' * 64, 'e' * 64
        engine._image_info = lambda: {
            'Id': image_id, 'Config': {'Env': [], 'Entrypoint': [], 'WorkingDir': ''}}
        engine.ensure_proxy_networks = lambda *_args, **_kwargs: plan
        state = {'created': False, 'payload': None}
        engine._find = lambda instance_id: (
            {'Id': container_id} if state['created'] else None)
        engine._verify = lambda instance_id, observed, expected_spec=None, expected_token=None, **kwargs: container_id
        def request(method, path, payload=None, *, ok=(200,)):
            self.assertEqual(method, 'POST')
            self.assertTrue(path.startswith('/containers/create?'))
            state['payload'] = payload
            state['created'] = True
            return {'Id': container_id}
        engine._request = request
        result = engine.create(
            instance_id, '/srv/agent-data/' + instance_id, limits, None,
            network_profile='agent_proxy_v1', owner_id='owner-d',
            sidecar_ip=plan['agent']['sidecar_ip'],
            control_ui_origin='https://' + instance_id + '.agents.example.test')
        self.assertEqual(result, container_id)
        payload = state['payload']
        self.assertEqual(payload['HostConfig']['NetworkMode'], plan['agent']['name'])
        self.assertEqual(payload['NetworkingConfig']['EndpointsConfig'][plan['agent']['name']]
                         ['IPAMConfig']['IPv4Address'], plan['agent']['gateway_ip'])
        self.assertNotIn('OPENCLAW_GATEWAY_TOKEN=', '\n'.join(payload['Env']))
        spec = json.loads(payload['Labels'][engine.SPEC_LABEL])
        self.assertEqual(spec['version'], 3)
        self.assertEqual(spec['owner_id'], 'owner-d')

    def test_control_ui_target_returns_private_frontend_sidecar_only_after_all_checks(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id, owner_id, domain = '1' * 32, 'owner-1', 'agents.example.test'
        origin = f'https://{instance_id}.{domain}'
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        host_path = '/srv/agent-data/' + instance_id
        web_id, gateway_id, sidecar_id = '2' * 64, '3' * 64, '4' * 64
        image_id = 'sha256:' + 'a' * 64
        image_info = self._sidecar_image_info(image_id)
        payload = engine._proxy_sidecar_payload(
            instance_id, owner_id=owner_id, control_ui_origin=origin,
            gateway_ip=plan['agent']['gateway_ip'], listen_ip=plan['frontend']['sidecar_ip'],
            image_id=image_id, host_path=host_path, plan=plan, image_info=image_info)
        gateway_spec = {
            'version': 3, 'image': engine.image, 'host_path': host_path,
            'limits': {'ram_bytes': 2**30, 'cpu_millicores': 1000,
                       'pids_limit': 256, 'disk_bytes': 10 * 1024**3},
            'proxy_network': plan['agent'], 'owner_id': owner_id,
            'control_ui_origin': origin,
        }
        gateway = {'Id': gateway_id, 'Config': {'Labels': {
            **engine._labels(instance_id), engine.SPEC_LABEL: engine._json(gateway_spec)}},
            'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}}
        sidecar = {
            'Id': sidecar_id, 'Image': image_id,
            'Config': {key: copy.deepcopy(payload.get(key)) for key in (
                'Image', 'User', 'Entrypoint', 'Cmd', 'WorkingDir', 'Env',
                'Healthcheck', 'StopTimeout', 'Labels')},
            'HostConfig': copy.deepcopy(payload['HostConfig']),
            'Mounts': [{'Type': 'bind', 'Source': payload['HostConfig']['Mounts'][0]['Source'],
                        'Destination': engine.PROXY_TOKEN_FILE_CONTAINER, 'RW': False}],
            'NetworkSettings': {'Networks': {
                plan['agent']['name']: {'NetworkID': '5' * 64,
                                        'IPAddress': plan['agent']['sidecar_ip'],
                                        'IPAMConfig': {'IPv4Address': plan['agent']['sidecar_ip']}},
                plan['frontend']['name']: {'NetworkID': '6' * 64,
                                           'IPAddress': plan['frontend']['sidecar_ip'],
                                           'IPAMConfig': {'IPv4Address': plan['frontend']['sidecar_ip']}},
            }},
            'State': {'Status': 'running', 'Health': {'Status': 'healthy'}},
        }
        class ReadyFirewall:
            def ready(self, policies):
                self.policies = policies
                return True
        engine.firewall = ReadyFirewall()
        engine._find = lambda instance_id: gateway
        engine._verify = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        engine._find_proxy_sidecar = lambda instance_id: sidecar
        engine._verify_proxy_sidecar = lambda instance_id, observed, expected, plan, network_ids: sidecar_id
        web_networks = {}
        trust_state = {'values': ('127.0.0.1,172.30.0.1',)}
        engine._find_control_plane_web = lambda control_ui_domain: {
            'container_id': web_id, 'image_id': image_id, 'image_info': image_info,
            'networks': web_networks, 'docker_gateway': '172.30.0.1',
            'forwarded_allow_values': trust_state['values']}
        engine._proxy_network_id = lambda instance_id, role, expected: (
            '5' * 64 if role == 'agent' else '6' * 64)
        reconnects = []
        def reconnect_web(container_id, network_id, network_name, ipv4):
            reconnects.append((container_id, network_id, network_name, ipv4))
            web_networks[network_name] = {
                'NetworkID': network_id, 'IPAddress': ipv4,
                'IPAMConfig': {'IPv4Address': ipv4}}
            return {'Id': container_id, 'NetworkSettings': {'Networks': web_networks}}
        engine._ensure_container_network = reconnect_web
        engine.proxy_network_policies = lambda: (engine._proxy_firewall_policy(instance_id, plan),)
        verified_memberships = []
        engine.__dict__['_verify_proxy_network_membership'] = (
            lambda instance_id, role, network_id, expected_plan, expected_ids, **kwargs:
            (verified_memberships.append((role, expected_ids)) or {}))
        token = 'T' * 43
        engine._read_existing_proxy_token_file = lambda host_path: token
        target = engine.control_ui_target(instance_id, owner_id)
        self.assertEqual(target, {
            'ip': plan['frontend']['sidecar_ip'], 'port': 18790, 'proxy_token': token,
            'identity': {'gateway_id': gateway_id, 'sidecar_id': sidecar_id,
                         'agent_network_id': '5' * 64, 'frontend_network_id': '6' * 64},
        })
        self.assertEqual([role for role, _ in verified_memberships],
                         ['agent', 'frontend', 'agent', 'frontend'])
        self.assertEqual(reconnects, [(web_id, '6' * 64, plan['frontend']['name'],
                                       plan['frontend']['web_ip'])])
        self.assertEqual(len(engine.firewall.policies), 1)
        web_networks.clear()
        self.assertTrue(engine._proxy_firewall_ready(instance_id, gateway_spec))
        self.assertEqual(len(reconnects), 2)
        trust_state['values'] = ('*',)
        self.assertIsNone(engine.control_ui_target(instance_id, owner_id))
        self.assertTrue(engine._proxy_firewall_ready(instance_id, gateway_spec))
        self.assertEqual(len(reconnects), 3)
        trust_state['values'] = ('127.0.0.1,172.30.0.1',)
        sidecar_labels = sidecar['Config']['Labels']
        stale_image_id = 'sha256:' + 'f' * 64
        stale_sidecar_spec = json.loads(sidecar_labels[engine.SIDECAR_SPEC_LABEL])
        stale_sidecar_spec['image_id'] = stale_image_id
        sidecar_labels[engine.SIDECAR_SPEC_LABEL] = engine._json(stale_sidecar_spec)
        sidecar_labels[engine.SIDECAR_CONFIG_LABEL] = engine._hash(stale_sidecar_spec)
        engine._proxy_sidecar_image_info = lambda sidecar_image_id, web: {
            'Id': sidecar_image_id, 'Config': image_info['Config']}
        stopped = []
        engine._stop_proxy_containers = lambda instance_id: stopped.append(instance_id) or True
        inspected = engine.inspect(instance_id)
        self.assertEqual(inspected['state'], 'running')
        self.assertEqual(inspected['proxy_state'], 'not_ready')
        self.assertEqual(stopped, [])
        sidecar['State']['Status'] = 'created'
        self.assertIsNone(engine.control_ui_target(instance_id, owner_id))

    def test_proxy_firewall_readiness_rejects_sidecar_runtime_drift(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = 'd' * 32
        owner_id = 'owner-d'
        origin = 'https://' + instance_id + '.agents.example.test'
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        gateway_spec = engine._spec(
            '/srv/agent-data/' + instance_id,
            AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                        pids_limit=256, disk_bytes=10 * 1024**3),
            version=3, instance_id=instance_id, proxy_network=plan['agent'],
            owner_id=owner_id, control_ui_origin=origin)
        image_id = 'sha256:' + 'a' * 64
        image_info = self._sidecar_image_info(image_id)
        sidecar_payload = engine._proxy_sidecar_payload(
            instance_id, owner_id=owner_id, control_ui_origin=origin,
            gateway_ip=plan['agent']['gateway_ip'],
            listen_ip=plan['frontend']['sidecar_ip'],
            image_id=image_id, host_path='/srv/agent-data/' + instance_id,
            plan=plan, image_info=image_info)
        gateway_id = '3' * 64
        gateway = {'Id': gateway_id, 'Config': {'Labels': {
            engine.SPEC_LABEL: engine._json(gateway_spec)}}}
        sidecar = {'Id': 'e' * 64, 'Config': {'Labels': sidecar_payload['Labels']}}
        engine.__dict__['_find'] = lambda instance_id: gateway
        engine.__dict__['_verify'] = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        engine.__dict__['_find_proxy_sidecar'] = lambda instance_id: sidecar
        engine.__dict__['_find_control_plane_web'] = lambda control_ui_domain: {
            'container_id': 'f' * 64, 'image_id': image_id, 'image_info': image_info}
        engine.__dict__['_proxy_network_id'] = lambda instance_id, role, expected: '1' * 64
        engine.__dict__['_verify_proxy_sidecar'] = lambda instance_id, observed, expected, plan, network_ids: (_ for _ in ()).throw(
            DockerEngineError('drift'))
        engine.proxy_network_policies = lambda: (engine._proxy_firewall_policy(instance_id, plan),)
        class ReadyFirewall:
            def ready(self, _policies):
                return True
        engine.firewall = ReadyFirewall()
        self.assertFalse(engine._proxy_firewall_ready(instance_id, gateway_spec))

    def test_default_engine_wires_disabled_real_firewall_adapter_before_network_changes(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24',
                              host_route_provider=lambda: HostIPv4Inventory((), ()))
        self.assertIsInstance(engine.firewall, FirewallManager)
        self.assertIsInstance(engine.firewall.adapter, NftablesAdapter)
        self.assertFalse(engine.firewall.can_apply)
        calls = []
        engine.ensure_proxy_networks = lambda *_args, **_kwargs: calls.append('networks')
        with self.assertRaises(DockerEngineError):
            engine.prepare_control_ui('8' * 32, 'owner-8', 'agents.example.test',
                                      '/srv/agent-data/' + '8' * 32)
        self.assertEqual(calls, [])

    def test_proxy_start_fails_closed_without_verified_firewall(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = 'c' * 32
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-c',
                            control_ui_origin='https://' + instance_id + '.agents.example.test')
        gateway_id = 'd' * 64
        observed = {'Id': gateway_id, 'Config': {'Labels': {
            **engine._labels(instance_id), engine.SPEC_LABEL: engine._json(spec)}}}
        engine._find = lambda instance_id: observed
        engine._verify = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        calls = []
        engine._request = lambda method, path, payload=None, *, ok=(200,): calls.append((method, path))
        engine.firewall = None
        with self.assertRaises(DockerEngineError):
            engine.start(instance_id)
        self.assertFalse(any(path.endswith('/start') for _, path in calls))

    def test_ollama_route_readiness_is_required_before_gateway_start(self):
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.244.0.0/24',
            frontend_network_pool='10.245.0.0/24',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config)
        instance_id = 'e' * 32
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-e',
                            control_ui_origin=f'https://{instance_id}.agents.example.test')
        gateway_id, sidecar_id = 'a' * 64, 'b' * 64
        gateway = {'Id': gateway_id, 'Config': {'Labels': {
            **engine._labels(instance_id), engine.SPEC_LABEL: engine._json(spec)}},
            'State': {'Status': 'created'}}
        engine.__dict__['_find'] = lambda instance_id: gateway
        engine.__dict__['_verify'] = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        engine.__dict__['_find_proxy_sidecar'] = lambda instance_id: {
            'Id': sidecar_id, 'State': {'Status': 'created'}}
        engine.__dict__['_proxy_firewall_ready'] = lambda instance_id, gateway_spec: True
        calls = []
        engine._request = lambda method, path, payload=None, *, ok=(200,): calls.append(path)

        with self.assertRaises(DockerEngineError):
            engine.start(instance_id)

        self.assertFalse(any(path.endswith('/start') for path in calls))
        self.assertFalse(any(path == '/networks/create' for path in calls))

    def test_inspect_stops_gateway_when_ollama_firewall_readback_is_not_ready(self):
        from supervisor.ollama_firewall import OllamaRoutePolicy
        config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        instance_id = '4' * 32

        class RouteFirewall:
            can_apply = False
            def ready(self, _policies):
                return False

        engine = DockerEngine(
            'sha256:' + 'a' * 64, agent_network_pool='10.244.0.0/24',
            frontend_network_pool='10.245.0.0/24',
            ollama_network_pool='172.20.0.0/16',
            ollama_egress_interface='ens18', ollama_config=config,
            ollama_firewall=RouteFirewall())
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-4',
                            control_ui_origin=f'https://{instance_id}.agents.example.test')
        gateway_id = 'a' * 64
        gateway = {'Id': gateway_id, 'Config': {'Labels': {
            engine.SPEC_LABEL: json.dumps(spec)}},
            'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}}
        engine.__dict__['_find'] = lambda instance_id: gateway
        engine.__dict__['_verify'] = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        engine.__dict__['control_ui_target'] = lambda instance_id, owner_id: {'identity': {}}
        engine.__dict__['_proxy_firewall_ready'] = lambda instance_id, gateway_spec: True
        policy = OllamaRoutePolicy(
            instance_id, '172.20.0.0/29', '172.20.0.1', '172.20.0.2',
            '10.99.0.10', 'ens18')
        engine.__dict__['ollama_route_policies'] = lambda: (policy,)
        def stop(instance_id):
            gateway['State'].update({'Status': 'exited', 'ExitCode': 0, 'OOMKilled': False})
            return True
        engine.__dict__['_stop_proxy_containers'] = stop

        result = engine.inspect(instance_id)

        self.assertEqual(result['state'], 'stopped')
        self.assertEqual(result['ollama_route_state'], 'not_ready')

    def test_proxy_start_stops_gateway_and_sidecar_after_live_check_failure(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = 'c' * 32
        gateway_id, sidecar_id = 'd' * 64, 'e' * 64
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-c',
                            control_ui_origin=f'https://{instance_id}.agents.example.test')
        gateway = {'Id': gateway_id, 'Config': {'Labels': {
            **engine._labels(instance_id), engine.SPEC_LABEL: engine._json(spec)}},
            'State': {'Status': 'created'}}
        sidecar = {'Id': sidecar_id, 'State': {'Status': 'created'}}
        engine._find = lambda instance_id: gateway
        engine._find_proxy_sidecar = lambda instance_id: sidecar
        engine._verify = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        readiness_calls = []
        engine._proxy_firewall_ready = lambda instance_id, gateway_spec: (
            readiness_calls.append('check') or len(readiness_calls) == 1)
        engine._action = lambda instance_id, action: (
            gateway['State'].__setitem__('Status', 'running') or
            {'state': 'running', 'container_id': gateway_id})
        calls = []
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path))
            if path == f'/containers/{sidecar_id}/start':
                sidecar['State']['Status'] = 'running'
            elif path == f'/containers/{sidecar_id}/stop?t=10':
                sidecar['State']['Status'] = 'exited'
            elif path == f'/containers/{gateway_id}/stop?t=10':
                gateway['State']['Status'] = 'exited'
            return None
        engine._request = request
        with self.assertRaises(DockerEngineError):
            engine.start(instance_id)
        self.assertEqual(gateway['State']['Status'], 'exited')
        self.assertEqual(sidecar['State']['Status'], 'exited')
        self.assertIn(('POST', f'/containers/{sidecar_id}/start'), calls)
        self.assertIn(('POST', f'/containers/{sidecar_id}/stop?t=10'), calls)
        self.assertIn(('POST', f'/containers/{gateway_id}/stop?t=10'), calls)

    def test_proxy_start_runs_live_checks_after_both_containers_start(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = 'c' * 32
        gateway_id, sidecar_id = 'd' * 64, 'e' * 64
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-c',
                            control_ui_origin=f'https://{instance_id}.agents.example.test')
        gateway = {'Id': gateway_id, 'Config': {'Labels': {
            **engine._labels(instance_id), engine.SPEC_LABEL: engine._json(spec)}},
            'State': {'Status': 'created', 'Health': {'Status': 'starting'}}}
        sidecar = {'Id': sidecar_id,
                   'State': {'Status': 'created', 'Health': {'Status': 'starting'}}}
        engine._find = lambda instance_id: gateway
        engine._find_proxy_sidecar = lambda instance_id: sidecar
        engine._verify = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        events = []
        def ready(instance_id, gateway_spec):
            events.append(('live-check', gateway['State']['Status'], sidecar['State']['Status']))
            return True
        engine._proxy_firewall_ready = ready
        def action(instance_id, action):
            events.append(('gateway-start', action))
            gateway['State']['Status'] = 'running'
            return {'state': 'running', 'container_id': gateway_id}
        engine._action = action
        def request(method, path, payload=None, *, ok=(200,)):
            events.append(('docker', method, path))
            if path == f'/containers/{sidecar_id}/start':
                sidecar['State']['Status'] = 'running'
                return None
            raise AssertionError((method, path))
        engine._request = request
        def inspect(instance_id):
            events.append(('inspect', gateway['State']['Status'], sidecar['State']['Status']))
            return {'state': 'running', 'container_id': gateway_id, 'proxy_state': 'not_ready'}
        engine.inspect = inspect
        result = engine.start(instance_id)
        self.assertEqual(result['proxy_state'], 'not_ready')
        checks = [event for event in events if event[0] == 'live-check']
        self.assertEqual(checks, [
            ('live-check', 'created', 'created'),
            ('live-check', 'running', 'running'),
            ('live-check', 'running', 'running'),
        ])
        self.assertLess(events.index(('gateway-start', 'start')),
                        next(i for i, event in enumerate(events)
                             if event[:2] == ('docker', 'POST')))
        self.assertEqual(events[events.index(('inspect', 'running', 'running'))],
                         ('inspect', 'running', 'running'))
        self.assertFalse(any(event[0] == 'docker' and 'stop' in event[2]
                             for event in events))

    def test_inspect_stops_proxy_containers_when_live_isolation_drift_is_detected(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.244.0.0/24',
                              frontend_network_pool='10.245.0.0/24')
        instance_id = 'c' * 32
        gateway_id, sidecar_id = 'd' * 64, 'e' * 64
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=3,
                            instance_id=instance_id, proxy_network=plan['agent'],
                            owner_id='owner-c',
                            control_ui_origin=f'https://{instance_id}.agents.example.test')
        gateway = {'Id': gateway_id, 'Config': {'Labels': {
            **engine._labels(instance_id), engine.SPEC_LABEL: engine._json(spec)}},
            'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}}
        sidecar = {'Id': sidecar_id,
                   'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}}
        engine._find = lambda instance_id: gateway
        engine._find_proxy_sidecar = lambda instance_id: sidecar
        engine._verify = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
        engine.control_ui_target = lambda instance_id, owner_id: None
        engine._proxy_firewall_ready = lambda instance_id, gateway_spec: False
        calls = []
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append(path)
            if path == f'/containers/{sidecar_id}/stop?t=10':
                sidecar['State']['Status'] = 'exited'
            elif path == f'/containers/{gateway_id}/stop?t=10':
                gateway['State'].update({'Status': 'exited', 'ExitCode': 0, 'OOMKilled': False})
            else:
                raise AssertionError((method, path))
            return None
        engine._request = request
        result = engine.inspect(instance_id)
        self.assertEqual(result['state'], 'stopped')
        self.assertEqual(result['proxy_state'], 'not_ready')
        self.assertIn(f'/containers/{sidecar_id}/stop?t=10', calls)
        self.assertIn(f'/containers/{gateway_id}/stop?t=10', calls)

    def test_proxy_remove_retains_ipam_unless_purge_is_requested(self):
        instance_id = '7' * 32
        gateway_id, sidecar_id = '8' * 64, '9' * 64
        ollama_config = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b', 'context_tokens': 8192,
            'max_tokens': 512, 'think': False,
        }
        def make_engine():
            engine = DockerEngine(
                'sha256:' + 'a' * 64,
                agent_network_pool='10.240.0.0/24',
                frontend_network_pool='10.241.0.0/24',
                ollama_network_pool='172.20.0.0/16',
                ollama_egress_interface='ens18', ollama_config=ollama_config)
            state: dict[str, Any] = {'gateway': {'Id': gateway_id}, 'sidecar': {'Id': sidecar_id}}
            deleted, detached, purged, cleanup = [], [], [], []
            engine._find = lambda instance_id: state['gateway']
            engine._verify = lambda instance_id, observed, expected_spec=None, expected_token=None: gateway_id
            engine._find_proxy_sidecar = lambda instance_id: state['sidecar']
            def delete(container_id):
                deleted.append(container_id)
                if container_id == gateway_id:
                    state['gateway'] = None
                if container_id == sidecar_id:
                    state['sidecar'] = None
            engine._delete_container = delete
            engine._disconnect_control_plane_from_frontend = lambda instance_id: detached.append(instance_id)
            engine._existing_proxy_network = lambda instance_id, role: None
            engine.__dict__['remove_ollama_network'] = lambda instance_id: (
                cleanup.append(('ollama_route', instance_id)) or True)
            def remove_proxy_networks(instance_id):
                purged.append(instance_id)
                cleanup.append(('proxy_networks', instance_id))
            engine.remove_proxy_networks = remove_proxy_networks
            return engine, deleted, detached, purged, cleanup
        retained, deleted, detached, purged, retained_cleanup = make_engine()
        retained._remove_proxy_resources(instance_id, retain_networks=True)
        self.assertEqual(set(deleted), {gateway_id, sidecar_id})
        self.assertEqual(detached, [instance_id])
        self.assertEqual(purged, [])
        self.assertEqual(retained_cleanup, [])
        purged_engine, _, _, purged_calls, cleanup = make_engine()
        purged_engine._remove_proxy_resources(instance_id, retain_networks=False)
        self.assertEqual(purged_calls, [instance_id])
        self.assertEqual(cleanup, [
            ('ollama_route', instance_id), ('proxy_networks', instance_id),
        ])

    def test_proxy_sidecar_payload_unsets_inherited_non_allowlisted_image_environment(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = 'c' * 32
        image_id = 'sha256:' + 'b' * 64
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.248.0.0/24',
            frontend_network_pool='10.249.0.0/24')
        inherited = [
            'PATH=/usr/bin', 'PYTHONPATH=/app/backend', 'HOME=/home/app',
            'LANG=C.UTF-8', 'WEBUI_SECRET_KEY=xxx',
            'OPENAI_API_KEY=yyy', 'PORT=18790',
            'CUSTOM_FLAG=unexpected', 'BEZR_SIDECAR_OWNER_ID=stale-owner',
        ]
        image = {'Id': image_id, 'Config': {'Env': inherited}}
        calls = []
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path))
            return image
        engine._request = request

        payload = engine._proxy_sidecar_payload(
            instance_id, owner_id='owner-c',
            control_ui_origin='https://' + instance_id + '.agents.example.test',
            gateway_ip=plan['agent']['gateway_ip'],
            listen_ip=plan['frontend']['sidecar_ip'], image_id=image_id,
            host_path='/srv/agent-data/' + instance_id, plan=plan)

        self.assertEqual(calls, [('GET', '/images/' + image_id.replace(':', '%3A') + '/json')])
        self.assertEqual(
            [item for item in payload['Env'] if '=' not in item],
            ['CUSTOM_FLAG', 'OPENAI_API_KEY', 'PORT', 'WEBUI_SECRET_KEY'])
        self.assertIn('BEZR_SIDECAR_OWNER_ID=owner-c', payload['Env'])
        self.assertNotIn('PATH', payload['Env'])
        self.assertNotIn('PYTHONPATH', payload['Env'])
        self.assertNotIn('HOME', payload['Env'])
        serialized = json.dumps(payload)
        self.assertNotIn('WEBUI_SECRET_KEY=xxx', serialized)
        self.assertNotIn('OPENAI_API_KEY=yyy', serialized)

    def test_proxy_sidecar_payload_rejects_invalid_image_environment_metadata(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = 'b' * 32
        image_id = 'sha256:' + 'c' * 64
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.248.0.0/24',
            frontend_network_pool='10.249.0.0/24')
        invalid_images = (
            [],
            {'Id': 'sha256:' + 'd' * 64, 'Config': {'Env': []}},
            {'Id': image_id, 'Config': []},
            {'Id': image_id, 'Config': {'Env': 'PORT=8080'}},
            {'Id': image_id, 'Config': {'Env': ['PORT']}},
            {'Id': image_id, 'Config': {'Env': ['PORT=8080', 'PORT=9090']}},
            {'Id': image_id, 'Config': {'Env': ['=invalid']}},
        )
        for image in invalid_images:
            with self.subTest(image=image):
                engine._request = lambda method, path, payload=None, *, ok=(200,): image
                with self.assertRaises(DockerEngineError):
                    engine._proxy_sidecar_payload(
                        instance_id, owner_id='owner-b',
                        control_ui_origin='https://' + instance_id + '.agents.example.test',
                        gateway_ip=plan['agent']['gateway_ip'],
                        listen_ip=plan['frontend']['sidecar_ip'], image_id=image_id,
                        host_path='/srv/agent-data/' + instance_id, plan=plan)

    def test_proxy_sidecar_payload_uses_web_image_static_networks_secret_file_and_limits(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = '6' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool='10.248.0.0/24',
            frontend_network_pool='10.249.0.0/24')
        image_id = 'sha256:' + 'b' * 64
        payload = engine._proxy_sidecar_payload(
            instance_id, owner_id='owner-6',
            control_ui_origin='https://' + instance_id + '.agents.example.test',
            gateway_ip=plan['agent']['gateway_ip'], listen_ip=plan['frontend']['sidecar_ip'],
            image_id=image_id,
            host_path='/srv/agent-data/' + instance_id, plan=plan,
            image_info=self._sidecar_image_info(image_id))
        self.assertEqual(payload['Image'], 'sha256:' + 'b' * 64)
        self.assertNotIn(engine.MANAGED_LABEL, payload['Labels'])
        self.assertEqual(payload['Labels'][engine.INSTANCE_LABEL], instance_id)
        self.assertEqual(payload['User'], '1000:1000')
        self.assertEqual(payload['Entrypoint'], ['python'])
        self.assertEqual(payload['Cmd'], ['-m', 'control_plane.proxy_sidecar'])
        env = dict(item.split('=', 1) for item in payload['Env'])
        self.assertEqual(env['BEZR_SIDECAR_OWNER_ID'], 'owner-6')
        self.assertEqual(env['BEZR_SIDECAR_PUBLIC_ORIGIN'],
                         'https://' + instance_id + '.agents.example.test')
        self.assertEqual(env['BEZR_SIDECAR_GATEWAY_IP'], plan['agent']['gateway_ip'])
        self.assertEqual(env['BEZR_SIDECAR_LISTEN_IP'], plan['frontend']['sidecar_ip'])
        self.assertEqual(env['BEZR_SIDECAR_PROXY_TOKEN_FILE'], '/run/secrets/bezr-proxy-token')
        self.assertNotIn('BEZR_SIDECAR_PROXY_TOKEN', env)
        self.assertEqual(payload['HostConfig']['Memory'], 128 * 1024 * 1024)
        self.assertEqual(payload['HostConfig']['MemorySwap'], 128 * 1024 * 1024)
        self.assertEqual(payload['HostConfig']['NanoCpus'], 100_000_000)
        self.assertEqual(payload['HostConfig']['PidsLimit'], 32)
        self.assertIn('/app/backend/data', payload['HostConfig']['Tmpfs'])
        self.assertEqual(payload['HostConfig']['NetworkMode'], plan['frontend']['name'])
        self.assertEqual(payload['HostConfig']['PortBindings'], {})
        self.assertIs(payload['HostConfig']['PublishAllPorts'], False)
        secret_mount = payload['HostConfig']['Mounts'][0]
        self.assertEqual(secret_mount['Source'], '/srv/agent-data/' + instance_id + '/.control-ui-proxy-token')
        self.assertEqual(secret_mount['Target'], '/run/secrets/bezr-proxy-token')
        self.assertIs(secret_mount['ReadOnly'], True)
        endpoints = payload['NetworkingConfig']['EndpointsConfig']
        self.assertEqual(set(endpoints), {plan['frontend']['name']})
        self.assertEqual(endpoints[plan['frontend']['name']]['IPAMConfig']['IPv4Address'],
                         plan['frontend']['sidecar_ip'])
        self.assertNotIn('S' * 43, json.dumps(payload))

    def test_proxy_network_lifecycle_creates_and_verifies_both_networks(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              host_route_provider=lambda: HostIPv4Inventory((), ()))
        instance_id = '3' * 32
        state = {}
        calls = []
        def request(method, path, payload=None, *, ok=(200,)):
            calls.append((method, path, copy.deepcopy(payload)))
            if method == 'GET' and (path == '/networks' or path.startswith('/networks?')):
                return [{'Id': net_id, 'Name': data['Name'], 'IPAM': data.get('IPAM', {})}
                        for net_id, data in state.items()]
            if method == 'POST' and path == '/networks/create':
                net_id = ('a' if payload['Name'].startswith('pa-agent') else 'b') * 64
                state[net_id] = copy.deepcopy(payload)
                return {'Id': net_id}
            if method == 'GET' and path.startswith('/networks/'):
                net_id = path.rsplit('/', 1)[1]
                data = state[net_id]
                return {'Id': net_id, 'Name': data['Name'], 'Driver': 'bridge',
                        'Internal': True, 'Attachable': False, 'EnableIPv6': False,
                        'Ingress': False, 'Labels': data['Labels'], 'Options': data['Options'],
                        'IPAM': data['IPAM'], 'Containers': {}}
            raise AssertionError((method, path))
        engine._request = request
        plan = engine.ensure_proxy_networks(instance_id, agent_network_pool='10.244.0.0/24',
                                            frontend_network_pool='10.245.0.0/24')
        self.assertEqual(set(state), {'a' * 64, 'b' * 64})
        self.assertEqual(plan['agent']['subnet'], '10.244.0.0/29')
        self.assertEqual(plan['frontend']['subnet'], '10.245.0.0/29')

    def test_existing_proxy_network_readback_returns_verified_id_and_plan(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.240.0.0/24',
                              frontend_network_pool='10.241.0.0/24')
        instance_id = '2' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        payload = engine._proxy_network_payload(instance_id, plan['frontend'], role='frontend')
        observed = {**payload, 'Id': 'b' * 64, 'Ingress': False, 'Containers': {}}
        def request(method, path, payload=None, *, ok=(200,)):
            if method == 'GET' and path.startswith('/networks?'):
                return [{'Id': 'b' * 64, 'Name': observed['Name'], 'IPAM': observed['IPAM']}]
            if method == 'GET' and path == '/networks/' + 'b' * 64:
                return observed
            raise AssertionError((method, path))
        engine._request = request
        self.assertEqual(engine._existing_proxy_network(instance_id, 'frontend'),
                         ('b' * 64, plan['frontend'], observed))

    def test_proxy_network_purge_syncs_remaining_firewall_policies(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.240.0.0/24',
                              frontend_network_pool='10.241.0.0/24',
                              host_route_provider=lambda: HostIPv4Inventory((), ()))
        instance_id, other_id = '2' * 32, '3' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        other_plan = engine._proxy_network_plan(
            other_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool,
            occupied_subnets=(plan['agent']['subnet'], plan['frontend']['subnet']))
        policies = (engine._proxy_firewall_policy(instance_id, plan),
                    engine._proxy_firewall_policy(other_id, other_plan))
        state = {}
        for role, network_id in (('agent', 'a' * 64), ('frontend', 'b' * 64)):
            payload = engine._proxy_network_payload(instance_id, plan[role], role=role)
            state[network_id] = {**payload, 'Id': network_id, 'Ingress': False,
                                 'Containers': {}}
        deleted, applied = [], []
        fail_once = {'enabled': True}
        def request(method, path, payload=None, *, ok=(200,)):
            if method == 'GET' and path.startswith('/networks?'):
                query = parse_qs(path.split('?', 1)[1])
                name = json.loads(query['filters'][0])['name'][0]
                return [{'Id': network_id, 'Name': value['Name'], 'IPAM': value['IPAM'],
                         'Labels': value['Labels']}
                        for network_id, value in state.items() if value['Name'] == name]
            if method == 'GET' and path.startswith('/networks/'):
                return state[path.rsplit('/', 1)[1]]
            if method == 'DELETE' and path.startswith('/networks/'):
                network_id = path.rsplit('/', 1)[1]
                deleted.append(network_id)
                state.pop(network_id)
                return None
            raise AssertionError((method, path))
        class Firewall:
            can_apply = True
            def apply(self, remaining):
                applied.append(tuple(remaining))
                if fail_once['enabled']:
                    fail_once['enabled'] = False
                    raise RuntimeError('synthetic adapter failure')
        engine.firewall = Firewall()
        engine.__dict__['_request'] = request
        engine.__dict__['proxy_network_policies'] = lambda: (policies[1],)
        with self.assertRaises(DockerEngineError):
            engine.remove_proxy_networks(instance_id)
        self.assertEqual(set(deleted), {'a' * 64, 'b' * 64})
        self.assertEqual(state, {})
        self.assertEqual(applied, [(policies[1],)])
        engine.remove_proxy_networks(instance_id)
        self.assertEqual(applied, [(policies[1],), (policies[1],)])

    def test_proxy_network_purge_reconciles_firewall_when_networks_are_already_absent(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.240.0.0/24',
                              frontend_network_pool='10.241.0.0/24',
                              host_route_provider=lambda: HostIPv4Inventory((), ()))
        instance_id, other_id = '2' * 32, '3' * 32
        other_plan = engine._proxy_network_plan(
            other_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        other_policy = engine._proxy_firewall_policy(other_id, other_plan)
        applied = []
        class Firewall:
            can_apply = True
            def apply(self, remaining):
                applied.append(tuple(remaining))
        engine.firewall = Firewall()
        engine.__dict__['_request'] = lambda method, path, *args, **kwargs: (
            [] if method == 'GET' and path.startswith('/networks?') else
            (_ for _ in ()).throw(AssertionError((method, path))))
        engine.__dict__['proxy_network_policies'] = lambda: (other_policy,)
        engine.remove_proxy_networks(instance_id)
        self.assertEqual(applied, [(other_policy,)])

    def test_proxy_network_purge_rejects_drift_before_deleting_any_network(self):
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.240.0.0/24',
                              frontend_network_pool='10.241.0.0/24')
        instance_id = '2' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        networks = {}
        for role, network_id in (('agent', 'a' * 64), ('frontend', 'b' * 64)):
            payload = engine._proxy_network_payload(instance_id, plan[role], role=role)
            networks[payload['Name']] = {**payload, 'Id': network_id,
                                         'Ingress': False, 'Containers': {}}
        networks['pa-agent-' + instance_id]['Options']['com.docker.network.bridge.enable_ip_masquerade'] = 'true'
        deleted = []
        def request(method, path, payload=None, *, ok=(200,)):
            if method == 'GET' and path.startswith('/networks?'):
                query = parse_qs(path.split('?', 1)[1])
                name = json.loads(query['filters'][0])['name'][0]
                row = networks.get(name)
                return [] if row is None else [{'Id': row['Id'], 'Name': row['Name'], 'IPAM': row['IPAM']}]
            if method == 'GET' and path.startswith('/networks/'):
                network_id = path.rsplit('/', 1)[1]
                return next(row for row in networks.values() if row['Id'] == network_id)
            if method == 'DELETE':
                deleted.append(path)
                return None
            raise AssertionError((method, path))
        engine._request = request
        with self.assertRaises(DockerEngineError):
            engine.remove_proxy_networks(instance_id)
        self.assertEqual(deleted, [])

    def test_proxy_network_lifecycle_reuses_retained_subnets_without_reallocation(self):
        inventory = HostIPv4Inventory((), ())
        engine = DockerEngine('sha256:' + 'a' * 64,
                              agent_network_pool='10.246.0.0/24',
                              frontend_network_pool='10.247.0.0/24',
                              host_route_provider=lambda: inventory)
        instance_id = '5' * 32
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        agent_payload = engine._proxy_network_payload(instance_id, plan['agent'], role='agent')
        front_payload = engine._proxy_network_payload(instance_id, plan['frontend'], role='frontend')
        state = {
            'a' * 64: {**agent_payload, 'Id': 'a' * 64, 'Ingress': False,
                       'Containers': {'c' * 64: {'Name': 'pa-' + instance_id},
                                      'd' * 64: {'Name': 'pa-proxy-' + instance_id}}},
            'b' * 64: {**front_payload, 'Id': 'b' * 64, 'Ingress': False,
                       'Containers': {'e' * 64: {'Name': 'web'},
                                      'd' * 64: {'Name': 'pa-proxy-' + instance_id}}},
        }
        route_rows, address_rows = [], []
        for role in ('agent', 'frontend'):
            network = plan[role]
            route_rows.extend((
                {'dst': network['subnet'], 'dev': network['bridge'],
                 'protocol': 'kernel', 'scope': 'link', 'prefsrc': network['gateway']},
                {'type': 'local', 'dst': network['gateway'], 'dev': network['bridge'],
                 'protocol': 'kernel', 'scope': 'host', 'prefsrc': network['gateway']},
                {'type': 'broadcast',
                 'dst': str(ipaddress.IPv4Network(network['subnet']).network_address),
                 'dev': network['bridge'], 'protocol': 'kernel', 'scope': 'link',
                 'prefsrc': network['gateway']},
                {'type': 'broadcast',
                 'dst': str(ipaddress.IPv4Network(network['subnet']).broadcast_address),
                 'dev': network['bridge'], 'protocol': 'kernel', 'scope': 'link',
                 'prefsrc': network['gateway']},
            ))
            address_rows.append({'ifname': network['bridge'], 'addr_info': [{
                'family': 'inet', 'local': network['gateway'], 'prefixlen': 29}]})
        inventory = parse_ipv4_networks(route_rows, address_rows)
        created = []
        def request(method, path, payload=None, *, ok=(200,)):
            if method == 'GET' and path == '/networks':
                return [{'Id': network_id, 'Name': row['Name'], 'IPAM': row['IPAM']}
                        for network_id, row in state.items()]
            if method == 'GET' and path.startswith('/networks/'):
                return state[path.rsplit('/', 1)[1]]
            if method == 'POST' and path == '/networks/create':
                created.append(payload)
                raise AssertionError('retained proxy networks must be reused')
            raise AssertionError((method, path))
        engine._request = request
        restored = engine.ensure_proxy_networks(instance_id,
            agent_network_pool=engine.agent_network_pool,
            frontend_network_pool=engine.frontend_network_pool)
        self.assertEqual(restored, plan)
        self.assertEqual(created, [])
        ambiguous_rows = [*route_rows, {
            'dst': plan['agent']['subnet'], 'dev': plan['agent']['bridge'],
            'protocol': 'kernel', 'scope': 'link',
        }]
        inventory = parse_ipv4_networks(ambiguous_rows, address_rows)
        with self.assertRaises(DockerEngineError):
            engine.ensure_proxy_networks(instance_id,
                agent_network_pool=engine.agent_network_pool,
                frontend_network_pool=engine.frontend_network_pool)
        inventory = parse_ipv4_networks(route_rows, address_rows)
        from supervisor.service import RuntimeService
        def prepare_restore(instance_id_value, owner_id, domain, host_path):
            plan_value = engine.ensure_proxy_networks(
                instance_id_value, agent_network_pool=engine.agent_network_pool,
                frontend_network_pool=engine.frontend_network_pool)
            return {'sidecar_ip': plan_value['agent']['sidecar_ip'],
                    'agent_subnet': plan_value['agent']['subnet'],
                    'control_ui_origin': f'https://{instance_id_value}.{domain}'}
        engine.__dict__['prepare_control_ui'] = prepare_restore
        service = RuntimeService.__new__(RuntimeService)
        service.engine = engine
        service.control_ui_domain = 'agents.example.test'
        service.agent_network_pool = engine.agent_network_pool
        restored_instance = service._prepare_control_ui_instance({
            'id': instance_id, 'actor': 'owner-5', 'gateway_token': 'synthetic-token',
            'network_profile': 'agent_proxy_v1',
        }, action='restore', host_path='/srv/agent-data/' + instance_id)
        self.assertEqual(restored_instance['agent_subnet'], plan['agent']['subnet'])
        self.assertEqual(restored_instance['sidecar_ip'], plan['agent']['sidecar_ip'])
        foreign_rows = [*route_rows, {
            'type': 'broadcast',
            'dst': str(ipaddress.IPv4Network(
                plan['agent']['subnet']).network_address),
            'dev': plan['agent']['bridge'], 'protocol': 'static', 'scope': 'link',
            'prefsrc': plan['agent']['gateway'],
        }]
        inventory = parse_ipv4_networks(foreign_rows, address_rows)
        with self.assertRaises(DockerEngineError):
            engine.ensure_proxy_networks(instance_id,
                agent_network_pool=engine.agent_network_pool,
                frontend_network_pool=engine.frontend_network_pool)
        inventory = parse_ipv4_networks(route_rows, address_rows)
        state['a' * 64]['Labels'][engine.INSTANCE_LABEL] = 'different-owner'
        with self.assertRaises(DockerEngineError):
            engine.ensure_proxy_networks(instance_id,
                agent_network_pool=engine.agent_network_pool,
                frontend_network_pool=engine.frontend_network_pool)
        state['a' * 64]['Labels'][engine.INSTANCE_LABEL] = instance_id
        state['a' * 64]['Id'] = 'c' * 64
        with self.assertRaises(DockerEngineError):
            engine.ensure_proxy_networks(instance_id,
                agent_network_pool=engine.agent_network_pool,
                frontend_network_pool=engine.frontend_network_pool)

    def test_gateway_config_is_read_only_mounted_and_config_read_only_mode_enabled(self):
        engine = DockerEngine('sha256:' + 'a' * 64)
        instance_id = '9' * 32
        limits = AgentLimits(ram_bytes=2**30, cpu_millicores=1000,
                             pids_limit=256, disk_bytes=10 * 1024**3)
        image_info = {
            'Id': 'sha256:' + 'a' * 64,
            'Config': {'Env': ['OPENCLAW_CONFIG_READONLY=0'], 'Entrypoint': [], 'WorkingDir': ''},
        }
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=1)
        self.assertEqual(spec['config_policy_version'], 1)

        payload = engine._payload(instance_id, spec, 'legacy-gateway-token', image_info)

        config_mount = next(mount for mount in payload['HostConfig']['Mounts']
                            if mount['Target'] == '/home/node/.openclaw/openclaw.json')
        self.assertEqual(config_mount['Source'], '/srv/agent-data/' + instance_id + '/state/openclaw.json')
        self.assertIs(config_mount['ReadOnly'], True)
        self.assertIs(config_mount['BindOptions']['CreateMountpoint'], False)
        env = dict(item.split('=', 1) for item in payload['Env'])
        self.assertEqual(env['OPENCLAW_CONFIG_READONLY'], '1')

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
        spec = engine._spec('/srv/agent-data/' + instance_id, limits, version=1,
                            config_policy_version=0)
        payload = engine._payload(instance_id, spec, token, image_info)
        self.assertNotIn('config_policy_version', spec)
        self.assertNotIn('OPENCLAW_CONFIG_READONLY=1', payload['Env'])
        self.assertNotIn('/home/node/.openclaw/openclaw.json',
                         [mount['Target'] for mount in payload['HostConfig']['Mounts']])
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
        self.assertEqual(engine._verify(instance_id, observed), container_id)
        # Existing legacy configuration is valid by itself, but create() requests
        # the current read-only config policy and must not adopt the older one.
        engine._find = lambda instance_id: observed
        with self.assertRaises(DockerEngineError):
            engine.create(instance_id, '/srv/agent-data/' + instance_id, limits, token)

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
