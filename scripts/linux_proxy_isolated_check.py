#!/usr/bin/env python3
"""Exercise Linux route/nftables semantics only inside a disposable net namespace.

This intentionally uses a synthetic Docker API fixture: it validates Linux
route output plus BEZR's Docker-identity checks, not a live Docker daemon.
"""
import argparse
from pathlib import Path
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from supervisor.docker_engine import DockerEngine, DockerEngineError
from supervisor.firewall import (
    NFTABLES_SEMANTICS_VALIDATED, NftablesAdapter, expected_ruleset,
)
from supervisor.firewall_acceptance import validate_firewall_network_pools
from supervisor.network_routes import read_host_ipv4_networks
from supervisor.probes import run_command

INSTANCE_ID = '5' * 32
PARENT_NETNS_ENV = 'BEZR_ISOLATED_PARENT_NETNS_INODE'


def _command(argv, *, timeout=10):
    try:
        result = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, shell=False, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('isolated Linux command failed') from None
    if result.returncode != 0:
        raise RuntimeError('isolated Linux command returned non-zero')


def _json_prefix_values(document):
    matches = []
    objects = document.get('nftables') if type(document) is dict else None
    if type(objects) is not list:
        raise RuntimeError('nft JSON response has no nftables array')
    for item in objects:
        rule = item.get('rule') if type(item) is dict else None
        expressions = rule.get('expr') if type(rule) is dict else None
        if type(expressions) is not list:
            continue
        for expression in expressions:
            match = expression.get('match') if type(expression) is dict else None
            right = match.get('right') if type(match) is dict else None
            if type(right) is dict and type(right.get('prefix')) is dict:
                matches.append(right['prefix'])
                if len(matches) >= 32:
                    return matches
    return matches


def _new_network_namespace(agent_pool, frontend_pool):
    if sys.platform != 'linux':
        raise RuntimeError('This acceptance check requires Linux')
    missing = [name for name in ('unshare', 'ip', 'nft') if shutil.which(name) is None]
    if missing:
        raise RuntimeError('Required existing commands are missing: ' + ', '.join(missing))
    parent_inode = str(os.stat('/proc/self/ns/net').st_ino)
    environment = dict(os.environ)
    environment[PARENT_NETNS_ENV] = parent_inode
    argv = ['unshare', '--net', '--fork', sys.executable, str(Path(__file__).resolve()),
            '--inside-netns', '--agent-pool', agent_pool,
            '--frontend-pool', frontend_pool]
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, shell=False, env=environment, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        process.communicate(timeout=2)
        raise RuntimeError('Isolated Linux check timed out') from None
    if len(output) > 2048:
        raise RuntimeError('Isolated Linux check produced excessive output')
    text = output.decode('utf-8', errors='replace').strip()
    if process.returncode != 0:
        raise RuntimeError(text or f'Isolated Linux check failed (exit {process.returncode})')
    return text


def _inside_namespace(agent_pool, frontend_pool):
    if sys.platform != 'linux':
        raise RuntimeError('This acceptance check requires Linux')
    parent_inode = os.environ.get(PARENT_NETNS_ENV)
    if (parent_inode is None or not parent_inode.isdigit()
            or str(os.stat('/proc/self/ns/net').st_ino) == parent_inode):
        raise RuntimeError('Refusing to run outside the newly created network namespace')

    engine = DockerEngine(
        'sha256:' + 'a' * 64,
        agent_network_pool=agent_pool,
        frontend_network_pool=frontend_pool,
        host_route_provider=read_host_ipv4_networks)
    plan = engine._proxy_network_plan(
        INSTANCE_ID, agent_network_pool=agent_pool,
        frontend_network_pool=frontend_pool)

    state = {}
    for role, network_id in (('agent', 'a' * 64), ('frontend', 'b' * 64)):
        payload = engine._proxy_network_payload(INSTANCE_ID, plan[role], role=role)
        subnet = ipaddress.IPv4Network(plan[role]['subnet'])
        broadcast = str(subnet.broadcast_address)
        _command(['ip', 'link', 'add', 'name', plan[role]['bridge'], 'type', 'bridge'])
        _command(['ip', 'address', 'add', plan[role]['gateway'] + '/29',
                  'brd', broadcast, 'dev', plan[role]['bridge']])
        _command(['ip', 'link', 'set', 'dev', plan[role]['bridge'], 'up'])
        state[network_id] = {
            **payload, 'Id': network_id, 'Ingress': False, 'Containers': {},
        }

    for role in ('agent', 'frontend'):
        network = plan[role]
        subnet = ipaddress.IPv4Network(network['subnet'])
        for address in (subnet.network_address, subnet.broadcast_address):
            destination = str(address)
            route_network = destination + '/32'
            inventory = read_host_ipv4_networks()
            expected = any(
                route.network == route_network and route.interface == network['bridge']
                and route.route_type == 'broadcast' and route.protocol == 'kernel'
                and route.scope == 'link' and route.prefsrc in (None, network['gateway'])
                for route in inventory.routes)
            if not expected:
                _command(['ip', 'route', 'add', 'broadcast', destination,
                          'dev', network['bridge'], 'table', 'local',
                          'proto', 'kernel', 'scope', 'link'])
                inventory = read_host_ipv4_networks()
                expected = any(
                    route.network == route_network and route.interface == network['bridge']
                    and route.route_type == 'broadcast' and route.protocol == 'kernel'
                    and route.scope == 'link' and route.prefsrc in (None, network['gateway'])
                    for route in inventory.routes)
            if not expected:
                raise RuntimeError('Linux namespace did not expose an expected kernel broadcast route')

    creates = []
    def docker_fixture(method, path, payload=None, *, ok=(200,)):
        if method == 'GET' and path == '/networks':
            return [{'Id': network_id, 'Name': value['Name'],
                     'IPAM': value['IPAM'], 'Labels': value['Labels']}
                    for network_id, value in state.items()]
        if method == 'GET' and path.startswith('/networks/'):
            return state[path.rsplit('/', 1)[1]]
        if method == 'POST' and path == '/networks/create':
            creates.append(payload)
            raise AssertionError('A verified retained network must not be recreated')
        raise AssertionError('Unexpected Docker API request in isolated fixture')

    engine.__dict__['_request'] = docker_fixture
    first = engine.ensure_proxy_networks(
        INSTANCE_ID, agent_network_pool=agent_pool,
        frontend_network_pool=frontend_pool)
    second = engine.ensure_proxy_networks(
        INSTANCE_ID, agent_network_pool=agent_pool,
        frontend_network_pool=frontend_pool)
    if first != plan or second != plan or creates:
        raise RuntimeError('Retained-network route revalidation failed')

    # Restore enters the same preparation route. Keep the API fixture and real
    # netlink inventory live, but do not create containers or touch user data.
    from supervisor.service import RuntimeService
    def prepare_restore(instance_id, owner_id, domain, host_path):
        restored = engine.ensure_proxy_networks(
            instance_id, agent_network_pool=agent_pool,
            frontend_network_pool=frontend_pool)
        return {
            'sidecar_ip': restored['agent']['sidecar_ip'],
            'agent_subnet': restored['agent']['subnet'],
            'control_ui_origin': f'https://{instance_id}.{domain}',
        }
    engine.__dict__['prepare_control_ui'] = prepare_restore
    service = RuntimeService.__new__(RuntimeService)
    service.engine = engine
    service.control_ui_domain = 'agents.example.test'
    service.agent_network_pool = agent_pool
    prepared = service._prepare_control_ui_instance({
        'id': INSTANCE_ID, 'actor': 'isolated-owner',
        'gateway_token': 'synthetic-only', 'network_profile': 'agent_proxy_v1',
    }, action='restore', host_path='/unused/' + INSTANCE_ID)
    if (prepared['agent_subnet'] != plan['agent']['subnet']
            or prepared['sidecar_ip'] != plan['agent']['sidecar_ip']):
        raise RuntimeError('Restore did not preserve verified per-instance IPAM')

    # Prove that a same-subnet route on a different interface is not exempted
    # just because the BEZR bridge exists. This route exists only in this netns.
    dummy = 'bzrtmp0'
    _command(['ip', 'link', 'add', 'name', dummy, 'type', 'dummy'])
    _command(['ip', 'link', 'set', 'dev', dummy, 'up'])
    foreign_route = plan['agent']['subnet']
    _command(['ip', 'route', 'add', foreign_route, 'dev', dummy, 'table', '42420'])
    try:
        try:
            engine.ensure_proxy_networks(
                INSTANCE_ID, agent_network_pool=agent_pool,
                frontend_network_pool=frontend_pool)
        except DockerEngineError:
            pass
        else:
            raise RuntimeError('A non-BEZR host route was incorrectly exempted')
    finally:
        _command(['ip', 'route', 'del', foreign_route, 'dev', dummy, 'table', '42420'])
        _command(['ip', 'link', 'del', 'dev', dummy])

    policy = engine._proxy_firewall_policy(INSTANCE_ID, plan)
    adapter = NftablesAdapter()
    expected = expected_ruleset((policy,))
    adapter.replace(expected)
    prefix_values = {}
    for family in ('inet', 'bridge'):
        raw = run_command(
            [adapter.nft_binary, '-a', '-j', 'list', 'table', family, 'agent_proxy_v1'],
            timeout=5, max_output_bytes=65536)
        values = _json_prefix_values(json.loads(raw))
        if values:
            prefix_values[family] = values
    try:
        readback = adapter.read()
    except Exception:
        readback = None
    if readback != expected:
        if prefix_values:
            prefix_sample = json.dumps(prefix_values, sort_keys=True, separators=(',', ':'))[:512]
            raise RuntimeError(
                'nft JSON read-back mismatch; prefix objects observed: ' + prefix_sample)
        raise RuntimeError('Live nftables JSON/handle read-back did not match')
    for family in ('inet', 'bridge'):
        table = adapter._family_table(family)
        if type(table) is not dict or type(table.get('handle')) is not int or table['handle'] <= 0:
            raise RuntimeError('nftables did not return a positive table handle')
    if NFTABLES_SEMANTICS_VALIDATED is not False:
        raise RuntimeError('The source-level firewall default must remain fail-closed')
    return ('PASS: current netns route data including broadcast routes, repeat preparation, '
            'restore preparation, foreign-route rejection, nft -a -j handles and exact '
            'ruleset read-back. No Docker daemon or user data used; no acceptance receipt is written.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-pool', required=True,
                        help='Explicit RFC1918 IPv4 pool for this isolated route check')
    parser.add_argument('--frontend-pool', required=True,
                        help='Second explicit, disjoint RFC1918 IPv4 pool')
    parser.add_argument('--inside-netns', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        agent_pool, frontend_pool = validate_firewall_network_pools(
            args.agent_pool, args.frontend_pool)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        if args.inside_netns:
            print(_inside_namespace(agent_pool, frontend_pool))
        else:
            print(_new_network_namespace(agent_pool, frontend_pool))
        return 0
    except Exception as exc:
        message = str(exc)
        print(message[:512] or 'Isolated Linux check failed')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
