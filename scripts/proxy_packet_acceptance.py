"""Independent agent_proxy_v1 packet contract, without an Ollama allow policy."""
from supervisor.docker_engine import DockerEngine
from supervisor.firewall_acceptance import build_firewall_acceptance_receipt


CHECKS = ('linux_proxy_isolated_check', 'linux_docker_proxy_acceptance')


def binding(agent_pool, frontend_pool, host):
    value = build_firewall_acceptance_receipt(host, agent_pool, frontend_pool, accepted_at_unix=1)
    return {key: item for key, item in value.items() if key not in ('checks', 'accepted_at_unix')}


def plans(config):
    result, occupied = [], []
    for instance in ('1' * 32, '2' * 32):
        plan = DockerEngine._proxy_network_plan(instance,
            agent_network_pool=config['agent_network_pool'],
            frontend_network_pool=config['frontend_network_pool'], occupied_subnets=tuple(occupied))
        result.append((instance, plan))
        occupied.extend(plan[role]['subnet'] for role in ('agent', 'frontend'))
    return result


def network_specs(config):
    result = []
    for index, (instance, plan) in enumerate(plans(config), 1):
        for role, members in (
            ('agent', [(f'gw{index}', plan['agent']['gateway_ip']),
                       (f'side{index}', plan['agent']['sidecar_ip'])]),
            ('frontend', [(f'side{index}', plan['frontend']['sidecar_ip']),
                          (f'web{index}', plan['frontend']['web_ip'])])):
            result.append((plan[role], DockerEngine._proxy_network_payload(instance, plan[role], role=role), members))
    return result


def make_plan(config):
    # External/host targets are controlled lab listeners, never caller endpoints.
    import ipaddress
    pools = [ipaddress.IPv4Network(config[k]) for k in ('agent_network_pool', 'frontend_network_pool')]
    target = next((value for value in ('192.168.255.250', '172.31.255.250', '10.255.255.250')
                   if not any(ipaddress.IPv4Address(value) in pool for pool in pools)), None)
    if target is None:
        raise ValueError('No private laboratory target available')
    addresses = {'target': target, 'foreign': str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(target)) ^ 1))}
    for index, (_, plan) in enumerate(plans(config), 1):
        addresses.update({f'gw{index}': plan['agent']['gateway_ip'],
                          f'side{index}': plan['agent']['sidecar_ip'],
                          f'side_front{index}': plan['frontend']['sidecar_ip'],
                          f'web{index}': plan['frontend']['web_ip']})
        if index == 1:
            addresses['host'] = plan['agent']['gateway']
    probes = []

    def add(name, source, destination, allow=False):
        probes.append(dict(name=name, source=source, destination=addresses[destination],
                           port=11434, allow=allow))

    for index in (1, 2):
        other = 3 - index
        for name, source, destination in (
            ('gateway_own_sidecar', f'gw{index}', f'side{index}'),
            ('sidecar_own_gateway', f'side{index}', f'gw{index}'),
            ('web_own_sidecar', f'web{index}', f'side_front{index}'),
            ('sidecar_own_web', f'side{index}', f'web{index}')):
            add(f'{name}_{index}', source, destination, True)
        for name, source, destination in (
            ('gateway_other_gateway', f'gw{index}', f'gw{other}'),
            ('gateway_other_sidecar', f'gw{index}', f'side{other}'),
            ('gateway_web', f'gw{index}', f'web{index}'),
            ('sidecar_other_gateway', f'side{index}', f'gw{other}'),
            ('sidecar_other_sidecar', f'side{index}', f'side{other}'),
            ('sidecar_other_web', f'side{index}', f'web{other}'),
            ('web_other_sidecar', f'web{index}', f'side_front{other}'),
            ('web_gateway', f'web{index}', f'gw{index}')):
            add(f'{name}_{index}', source, destination)
        for source in (f'gw{index}', f'side{index}', f'web{index}'):
            add(source + '_host', source, 'host')
            add(source + '_external', source, 'target')
    return probes, addresses


def policy_digest(config):
    import hashlib
    import json
    from scripts.ollama_route_acceptance import proxy_policy
    return hashlib.sha256(json.dumps(proxy_policy(config), sort_keys=True,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def new_report(config, check, run_id, caller_inode, router_inode):
    return dict(schema_version=1, profile='agent_proxy_v1', check=check, run_id=run_id,
                binding=binding(config['agent_network_pool'], config['frontend_network_pool'],
                                config['host_id_sha256']),
                policy_sha256=policy_digest(config), caller_netns_inode=caller_inode,
                router_netns_inode=router_inode, policy_readback=False, cleanup=False,
                cold_neighbors=False, probes=[])


def validate_report(report, config, check, run_id):
    from scripts.ollama_route_acceptance import exact_json
    expected = new_report(config, check, run_id, '1', '2')
    if check not in CHECKS or type(report) is not dict or set(report) != set(expected):
        raise ValueError('Invalid independent proxy report')
    for key in ('schema_version', 'profile', 'check', 'run_id', 'binding', 'policy_sha256'):
        if type(report[key]) is not type(expected[key]) or not exact_json(report[key], expected[key]):
            raise ValueError('Proxy acceptance binding mismatch: ' + key)
    a, b = report['caller_netns_inode'], report['router_netns_inode']
    if not all(type(x) is str and x.isdecimal() and int(x) > 0 for x in (a, b)) or a == b:
        raise ValueError('Proxy namespace isolation missing')
    if any(report[key] is not True for key in ('policy_readback', 'cleanup', 'cold_neighbors')):
        raise ValueError('Proxy cleanup, cold path or readback incomplete')
    probes = make_plan(config)[0]
    if type(report['probes']) is not list or len(report['probes']) != len(probes):
        raise ValueError('Incomplete proxy packet inventory')
    for observed, spec in zip(report['probes'], probes):
        if (type(observed) is not dict or set(observed) != {'name', 'spec', 'before', 'enforced', 'after'}
                or observed['name'] != spec['name'] or not exact_json(observed['spec'], spec)
                or any(type(observed[key]) is not bool for key in ('before', 'enforced', 'after'))
                or observed['before'] is not True or observed['after'] is not True
                or observed['enforced'] is not spec['allow']):
            raise ValueError('Proxy packet positive controls or enforcement mismatch')
    return report
