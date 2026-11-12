"""Shared strict contract for opt-in isolated Ollama packet acceptance."""
import hashlib
import json
import ipaddress
import os
import signal
import subprocess
import threading
from typing import Any
from supervisor.docker_engine import DockerEngine
from supervisor.firewall import EndpointPair, NetworkPolicy, expected_ruleset as proxy_ruleset
from supervisor.ollama_firewall import (OllamaRoutePolicy, build_ollama_route_receipt,
                                        expected_ollama_ruleset)

CHECKS = ('linux_ollama_route_check', 'linux_docker_ollama_route_acceptance')
LIMIT = 262144


def binding(agent_pool, frontend_pool, ollama_pool, endpoint, interface, host):
    value = build_ollama_route_receipt(host, agent_pool, frontend_pool, ollama_pool,
                                       endpoint, interface, accepted_at_unix=1)
    return {key: val for key, val in value.items()
            if key not in ('checks', 'accepted_at_unix')}


def proxy_plans(config):
    plans = []
    occupied = []
    for instance in ('1' * 32, '2' * 32):
        plan = DockerEngine._proxy_network_plan(instance,
            agent_network_pool=config['agent_network_pool'],
            frontend_network_pool=config['frontend_network_pool'], occupied_subnets=tuple(occupied))
        plans.append((instance, plan))
        occupied.extend(plan[role]['subnet'] for role in ('agent', 'frontend'))
    return plans


def proxy_policy(config):
    return proxy_ruleset(tuple(NetworkPolicy(instance, plan['agent']['subnet'],
        plan['frontend']['subnet'], plan['agent']['bridge'], plan['frontend']['bridge'],
        EndpointPair(plan['agent']['gateway_ip'], plan['agent']['sidecar_ip']),
        EndpointPair(plan['frontend']['web_ip'], plan['frontend']['sidecar_ip']))
        for instance, plan in proxy_plans(config)))


def network_specs(config):
    specs = []
    policies = make_plan(config)[0]
    for index, (instance, plan) in enumerate(proxy_plans(config), 1):
        policy = policies[index - 1]
        route = dict(name=policy.network_name, bridge=policy.bridge, subnet=policy.subnet,
                     gateway=policy.gateway, gateway_ip=policy.gateway_ip)
        specs.append((route, DockerEngine._ollama_network_payload(instance, route),
                      [(f'gw{index}', policy.gateway_ip)]))
        for role, members in (
            ('agent', [(f'gw{index}', plan['agent']['gateway_ip']),
                       (f'side{index}', plan['agent']['sidecar_ip'])]),
            ('frontend', [(f'side{index}', plan['frontend']['sidecar_ip']),
                          (f'web{index}', plan['frontend']['web_ip'])])):
            specs.append((plan[role], DockerEngine._proxy_network_payload(instance, plan[role], role=role), members))
    return specs


def make_plan(config):
    policies = []
    for instance in ('1' * 32, '2' * 32):
        plan = DockerEngine._ollama_network_plan(instance, config['ollama_network_pool'],
                    occupied_subnets=tuple(p.subnet for p in policies),
                    endpoint_ip=config['ollama_endpoint_ip'])
        policies.append(OllamaRoutePolicy(instance, plan['subnet'], plan['gateway'],
                        plan['gateway_ip'], config['ollama_endpoint_ip'], config['egress_interface']))
    pools = [ipaddress.IPv4Network(config[k]) for k in (
        'agent_network_pool', 'frontend_network_pool', 'ollama_network_pool')]
    endpoint = ipaddress.IPv4Address(config['ollama_endpoint_ip'])
    foreign = next((str(ipaddress.IPv4Address(int(endpoint) ^ bit))
                    for bit in (1, 2, 4, 8, 16, 32, 64, 128)
                    if not any(ipaddress.IPv4Address(int(endpoint) ^ bit) in p for p in pools)), None)
    if foreign is None:
        raise ValueError('No isolated foreign destination available')
    addresses = {'gw1': policies[0].gateway_ip, 'gw2': policies[1].gateway_ip,
                 'side1': str(ipaddress.IPv4Address(policies[0].gateway_ip) + 1),
                 'side2': str(ipaddress.IPv4Address(policies[1].gateway_ip) + 1),
                 'target': str(endpoint), 'foreign': foreign, 'host': policies[0].gateway}
    for index, (_, plan) in enumerate(proxy_plans(config), 1):
        addresses[f'side{index}'] = plan['agent']['sidecar_ip']
        addresses[f'web{index}'] = plan['frontend']['web_ip']
    probes = []
    def add(name, source, target, port=11434, allow=False):
        probes.append(dict(name=name, source=source, destination=addresses[target], port=port, allow=allow))
    for index in (1, 2):
        add(f'gateway{index}_exact_and_established_return', f'gw{index}', 'target', allow=True)
        add(f'gateway{index}_wrong_port', f'gw{index}', 'target', 11435)
        add(f'gateway{index}_foreign_ip', f'gw{index}', 'foreign')
        add(f'gateway{index}_host', f'gw{index}', 'host', 11435)
        add(f'sidecar{index}_ollama', f'side{index}', 'target')
        add(f'gateway{index}_other_gateway', f'gw{index}', f'gw{3-index}')
        add(f'gateway{index}_other_sidecar', f'gw{index}', f'side{3-index}')
        add(f'gateway{index}_own_sidecar', f'gw{index}', f'side{index}', allow=True)
        add(f'sidecar{index}_own_web', f'side{index}', f'web{index}', allow=True)
        add(f'sidecar{index}_other_web', f'side{index}', f'web{3-index}')
        add(f'unsolicited_target_gateway{index}', 'target', f'gw{index}')
    return tuple(policies), probes, addresses


def policy_digest(config):
    rules = {'ollama': expected_ollama_ruleset(make_plan(config)[0]), 'proxy': proxy_policy(config)}
    return hashlib.sha256(json.dumps(rules, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def new_report(config, check, run_id, caller_inode, router_inode) -> dict[str, Any]:
    return dict(schema_version=1, check=check, run_id=run_id, binding=config,
                policy_sha256=policy_digest(config), caller_netns_inode=caller_inode,
                router_netns_inode=router_inode, policy_readback=False, cleanup=False,
                cold_neighbors=False, probes=[])


def exact_json(left, right):
    return json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) == \
           json.dumps(right, sort_keys=True, separators=(',', ':'), allow_nan=False)


def validate_report(report, config, check, run_id):
    expected = new_report(config, check, run_id, '1', '2')
    if type(report) is not dict or set(report) != set(expected):
        raise ValueError('Invalid acceptance report fields')
    for key in ('schema_version', 'check', 'run_id', 'binding', 'policy_sha256'):
        if type(report[key]) is not type(expected[key]) or not exact_json(report[key], expected[key]):
            raise ValueError('Acceptance binding mismatch: ' + key)
    a, b = report['caller_netns_inode'], report['router_netns_inode']
    if not all(type(x) is str and x.isdecimal() and int(x) > 0 for x in (a, b)) or a == b:
        raise ValueError('Acceptance namespace isolation missing')
    if (report['cleanup'] is not True or report['policy_readback'] is not True
            or report['cold_neighbors'] is not True):
        raise ValueError('Acceptance cleanup or canonical policy readback missing')
    probes = make_plan(config)[1]
    if type(report['probes']) is not list or len(report['probes']) != len(probes):
        raise ValueError('Incomplete packet probe inventory')
    for observed, spec in zip(report['probes'], probes):
        if (type(observed) is not dict or set(observed) != {'name', 'spec', 'before', 'enforced', 'after'}
                or observed['name'] != spec['name'] or not exact_json(observed['spec'], spec)
                or any(type(observed[k]) is not bool for k in ('before', 'enforced', 'after'))
                or observed['before'] is not True or observed['after'] is not True
                or observed['enforced'] is not spec['allow']):
            raise ValueError('Packet transaction/positive-control evidence missing')
    return report


def network_argv(payload):
    subnet = payload['IPAM']['Config'][0]
    argv = ['network', 'create', '--driver', payload['Driver'], '--ipam-driver',
            payload['IPAM']['Driver'], '--subnet', subnet['Subnet'], '--gateway', subnet['Gateway']]
    for key, flag in (('Internal', '--internal'), ('Attachable', '--attachable'), ('EnableIPv6', '--ipv6')):
        if payload[key]:
            argv.append(flag)
    for key, value in sorted(payload['Options'].items()):
        argv.extend(('--opt', key + '=' + value))
    for key, value in sorted(payload['Labels'].items()):
        argv.extend(('--label', key + '=' + value))
    return [*argv, payload['Name']]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def command(argv, *, timeout: float = 30, input_text=None, pass_fds=(), env=None):
    """No shell; bounded output; Linux timeout kills the complete process group."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False,
                               start_new_session=True, pass_fds=pass_fds, env=env)
    assert process.stdout is not None
    output = bytearray()
    overflow = threading.Event()
    def read():
        while True:
            chunk = process.stdout.read(4096)
            if not chunk:
                break
            if len(output) + len(chunk) > LIMIT:
                overflow.set()
                process.kill()
                break
            output.extend(chunk)
    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        if input_text is not None:
            assert process.stdin is not None
            process.stdin.write(input_text.encode())
            process.stdin.close()
        process.wait(timeout=timeout)
        reader.join(timeout=3)
        if reader.is_alive() or overflow.is_set() or process.returncode:
            raise RuntimeError('Command failed or output exceeded bound: ' + argv[0])
        return output.decode('utf-8')
    finally:
        if os.name == 'posix':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        reader.join(timeout=3)
        if process.stdout:
            process.stdout.close()


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate report field')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
