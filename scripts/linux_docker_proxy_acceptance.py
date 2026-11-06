#!/usr/bin/env python3
"""Disposable-host Docker/nftables packet-isolation acceptance for agent_proxy_v1.

This is destructive only to resources it creates under a random run ID. It must
be run only on a disposable Linux/Docker VM. It never pulls images, creates
volumes, touches project SQLite/XFS paths, or removes unrelated containers.
"""
import argparse
import ipaddress
import json
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from supervisor.docker_engine import DockerEngine
from supervisor.firewall import FirewallManager, NftablesAdapter
from supervisor.network_routes import read_host_ipv4_networks

PROBE = (
    "import socket,sys; host=sys.argv[1]; port=int(sys.argv[2]); expected=sys.argv[3]; "
    "s=socket.socket(); s.settimeout(1.5); "
    "\ntry:\n s.connect((host,port)); s.settimeout(1); data=s.recv(64); s.close(); "
    "\n if expected=='deny': sys.exit(41); "
    "\n if data!=b'BEZR-TEST-OK': sys.exit(42); sys.exit(0) "
    "\nexcept OSError:\n sys.exit(0 if expected=='deny' else 43)"
)
SERVER = (
    "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
    "s.bind(('0.0.0.0',int(__import__('sys').argv[1]))); s.listen(); "
    "\nwhile True:\n c,_=s.accept(); c.sendall(b'BEZR-TEST-OK'); c.close()"
)
IDLE = "import time; time.sleep(3600)"


def _run(argv, *, timeout=30, input_text=None):
    try:
        result = subprocess.run(argv, input=input_text, text=True,
                                stdin=subprocess.DEVNULL if input_text is None else None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=False, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('required command failed or timed out') from None
    if result.returncode != 0:
        raise RuntimeError('required command returned non-zero')
    if len(result.stdout.encode('utf-8')) > 1_000_000:
        raise RuntimeError('command output exceeded the safety limit')
    return result.stdout.strip()


def _docker_json(*args):
    raw = _run(['docker', *args])
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        raise RuntimeError('Docker returned invalid JSON') from None


def _existing_docker_subnets():
    ids = _run(['docker', 'network', 'ls', '--quiet']).splitlines()
    if len(ids) > 4096:
        raise RuntimeError('Docker network inventory exceeds the safety limit')
    if not ids:
        return []
    result = []
    for offset in range(0, len(ids), 64):
        batch = ids[offset:offset + 64]
        rows = _docker_json('network', 'inspect', *batch)
        if type(rows) is not list or len(rows) != len(batch):
            raise RuntimeError('Docker network inventory is incomplete')
        for row in rows:
            try:
                configs = row['IPAM']['Config'] or []
                for config in configs:
                    value = config.get('Subnet')
                    if value:
                        result.append(str(ipaddress.IPv4Network(value, strict=True)))
            except (KeyError, TypeError, ValueError):
                raise RuntimeError('Docker network IPAM inventory is invalid') from None
    return result


def _network_create(payload, resources):
    ipam = payload['IPAM']['Config'][0]
    labels = dict(payload['Labels'])
    name = payload['Name']
    argv = [
        'docker', 'network', 'create',
        '--driver', 'bridge',
        '--internal',
        '--subnet', ipam['Subnet'],
        '--gateway', ipam['Gateway'],
    ]
    for key, value in sorted(payload['Options'].items()):
        argv.extend(['--opt', f'{key}={value}'])
    for key, value in sorted(labels.items()):
        argv.extend(['--label', key + '=' + value])
    argv.append(name)
    try:
        network_id = _run(argv, timeout=60).strip()
    except Exception:
        try:
            rows = _docker_json('network', 'inspect', name)
            if (type(rows) is list and len(rows) == 1
                    and rows[0].get('Labels') == labels):
                resources['networks'].append(rows[0]['Id'])
        except Exception:
            pass
        raise
    if not network_id or len(network_id) > 128:
        raise RuntimeError('Docker did not return a network ID')
    resources['networks'].append(network_id)
    observed_rows = _docker_json('network', 'inspect', network_id)
    if type(observed_rows) is not list or len(observed_rows) != 1:
        raise RuntimeError('Created Docker network could not be re-inspected')
    observed = observed_rows[0]
    options = observed.get('Options') or {}
    actual_ipam = (observed.get('IPAM') or {}).get('Config') or []
    if (observed.get('Id') != network_id or observed.get('Name') != name
            or observed.get('Driver') != 'bridge' or observed.get('Internal') is not True
            or observed.get('EnableIPv6') is not False
            or options.get('com.docker.network.bridge.name')
               != payload['Options']['com.docker.network.bridge.name']
            or observed.get('Labels') != labels
            or len(actual_ipam) != 1
            or actual_ipam[0].get('Subnet') != ipam['Subnet']
            or actual_ipam[0].get('Gateway') != ipam['Gateway']):
        raise RuntimeError('Docker network read-back differs from the isolated plan')
    return network_id, name


def _container_name(run_id, role, instance_id=''):
    return 'bezt-' + run_id[:8] + '-' + role + (('-' + instance_id[:8]) if instance_id else '')


def _run_container(run_id, image_id, name, network_name, address, resources, *, port=None):
    code = SERVER if port is not None else IDLE
    argv = [
        'docker', 'run', '--detach', '--name', name,
        '--label', 'io.bezr.acceptance-run=' + run_id,
        '--network', network_name, '--ip', address,
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
        '--memory', '64m', '--cpus', '0.10', '--pids-limit', '16',
        '--entrypoint', 'python', image_id, '-B', '-c', code,
    ]
    if port is not None:
        argv.append(str(port))
    try:
        container_id = _run(argv, timeout=60).strip()
    except Exception:
        try:
            rows = _docker_json('container', 'inspect', name)
            if (type(rows) is list and len(rows) == 1
                    and (rows[0].get('Config') or {}).get('Labels', {}).get(
                        'io.bezr.acceptance-run') == run_id):
                resources['containers'].append(rows[0]['Id'])
        except Exception:
            pass
        raise
    if not container_id or len(container_id) > 128:
        raise RuntimeError('Docker did not return a container ID')
    resources['containers'].append(container_id)
    return container_id


def _probe_container(container_id, host, port, *, allow):
    expected = 'allow' if allow else 'deny'
    _run(['docker', 'exec', container_id, 'python', '-B', '-c', PROBE,
          host, str(port), expected], timeout=8)


def _wait_allowed(container_id, host, port):
    deadline = time.monotonic() + 12
    last_error = None
    while time.monotonic() < deadline:
        try:
            _probe_container(container_id, host, port, allow=True)
            return
        except RuntimeError as error:
            last_error = error
            time.sleep(0.25)
    raise RuntimeError('Expected allowed probe did not become ready') from last_error


def _host_probe_blocked(host, port):
    try:
        with socket.create_connection((host, port), timeout=1.5):
            raise RuntimeError('Host unexpectedly reached an isolated container endpoint')
    except OSError:
        return


def _host_listener(host):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, 0))
    listener.listen(8)
    listener.settimeout(0.5)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with conn:
                    conn.sendall(b'BEZR-HOST-REACHED')
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, stop, listener, thread


def _check_environment(args):
    if sys.platform != 'linux':
        raise RuntimeError('This acceptance check requires Linux')
    missing = [name for name in ('docker', 'nft', 'ip') if shutil.which(name) is None]
    if missing:
        raise RuntimeError('Required existing commands are missing: ' + ', '.join(missing))
    if not args.execute or not args.confirm_disposable_host:
        raise RuntimeError('Refusing side effects without --execute --confirm-disposable-host')
    if not hasattr(__import__('os'), 'geteuid') or __import__('os').geteuid() != 0:
        raise RuntimeError('Run only as root inside the disposable test VM')
    if not args.probe_image.startswith('sha256:') or len(args.probe_image) != 71:
        raise RuntimeError('--probe-image must be a local immutable sha256 image ID')
    image_id = _run(['docker', 'image', 'inspect', '--format', '{{.Id}}',
                     args.probe_image]).strip()
    if image_id != args.probe_image:
        raise RuntimeError('The exact probe image must already exist locally; no pulls are performed')
    _run(['docker', 'info', '--format', '{{.ServerVersion}}'])


def _plans(args):
    engine = DockerEngine('sha256:' + 'a' * 64,
                          agent_network_pool=args.agent_pool,
                          frontend_network_pool=args.frontend_pool)
    inventory = read_host_ipv4_networks()
    host_routes = [route.network for route in inventory.routes
                   if ipaddress.IPv4Network(route.network).prefixlen > 0]
    occupied = _existing_docker_subnets()
    run_id = secrets.token_hex(16)
    instances = [secrets.token_hex(16), secrets.token_hex(16)]
    plans = []
    for instance_id in instances:
        plan = engine._proxy_network_plan(
            instance_id, agent_network_pool=args.agent_pool,
            frontend_network_pool=args.frontend_pool,
            occupied_subnets=occupied, host_routes=host_routes)
        occupied.extend((plan['agent']['subnet'], plan['frontend']['subnet']))
        plans.append((instance_id, plan))
    return engine, run_id, plans


def _create_probe_topology(run_id, image_id, plans, resources):
    network_names = {}
    network_ids = {}
    planned_network_names = {plan[role]['name'] for _instance_id, plan in plans
                             for role in ('agent', 'frontend')}
    planned_container_names = {
        _container_name(run_id, 'web'),
        *(_container_name(run_id, 'sidecar', instance_id) for instance_id, _plan in plans),
        *(_container_name(run_id, 'gateway', instance_id) for instance_id, _plan in plans),
    }
    existing_network_names = set(_run(['docker', 'network', 'ls', '--format', '{{.Name}}']).splitlines())
    existing_container_names = set(_run(['docker', 'container', 'ls', '--all',
                                         '--format', '{{.Names}}']).splitlines())
    if planned_network_names & existing_network_names:
        raise RuntimeError('A generated test network name already exists; refusing to reuse it')
    if planned_container_names & existing_container_names:
        raise RuntimeError('A generated test container name already exists; refusing to reuse it')
    for instance_id, plan in plans:
        for role in ('agent', 'frontend'):
            payload = DockerEngine._proxy_network_payload(instance_id, plan[role], role=role)
            network_id, name = _network_create(payload, resources)
            network_names[(instance_id, role)] = name
            network_ids[(instance_id, role)] = network_id

    first_id, first = plans[0]
    second_id, second = plans[1]
    web_name = _container_name(run_id, 'web')
    web_id = _run_container(run_id, image_id, web_name,
                            network_names[(first_id, 'frontend')], first['frontend']['web_ip'],
                            resources)
    _run(['docker', 'network', 'connect', '--ip', second['frontend']['web_ip'],
          network_names[(second_id, 'frontend')], web_id])

    sidecars, gateways = {}, {}
    for instance_id, plan in plans:
        sidecar_name = _container_name(run_id, 'sidecar', instance_id)
        sidecar_id = _run_container(run_id, image_id, sidecar_name,
                                    network_names[(instance_id, 'frontend')],
                                    plan['frontend']['sidecar_ip'], resources, port=18790)
        _run(['docker', 'network', 'connect', '--ip', plan['agent']['sidecar_ip'],
              network_names[(instance_id, 'agent')], sidecar_id])
        gateway_name = _container_name(run_id, 'gateway', instance_id)
        gateway_id = _run_container(run_id, image_id, gateway_name,
                                    network_names[(instance_id, 'agent')],
                                    plan['agent']['gateway_ip'], resources, port=18789)
        sidecars[instance_id] = sidecar_id
        gateways[instance_id] = gateway_id
    return web_id, sidecars, gateways, network_names, network_ids


def _verify_retained_docker_routes(engine, plans, network_ids):
    inventory = read_host_ipv4_networks()
    evidence = []
    for instance_id, plan in plans:
        for role in ('agent', 'frontend'):
            network = plan[role]
            network_id = network_ids[(instance_id, role)]
            rows = _docker_json('network', 'inspect', network_id)
            if type(rows) is not list or len(rows) != 1:
                raise RuntimeError('Docker bridge disappeared during route verification')
            observed = rows[0]
            if engine._retained_proxy_network_has_foreign_host_route(
                    inventory, instance_id, role, network_id, observed, network):
                raise RuntimeError('Docker-created bridge route failed the retained-network ownership check')
            subnet = ipaddress.IPv4Network(network['subnet'])
            expected_broadcasts = {
                str(ipaddress.IPv4Network(str(subnet.network_address) + '/32')),
                str(ipaddress.IPv4Network(str(subnet.broadcast_address) + '/32')),
            }
            observed_broadcasts = {
                route.network for route in inventory.routes
                if route.interface == network['bridge'] and route.route_type == 'broadcast'
                and route.protocol == 'kernel' and route.scope == 'link'
            }
            present = sorted(expected_broadcasts & observed_broadcasts)
            evidence.append(f'{role}:{network["bridge"]}:broadcast={present or "none-emitted"}')
    print('ROUTES: ' + '; '.join(evidence))


def _verify_memberships(plans, web_id, sidecars, gateways, network_names):
    web = _docker_json('inspect', web_id)[0]['NetworkSettings']['Networks']
    expected_web = {network_names[(instance_id, 'frontend')] for instance_id, _ in plans}
    if set(web) != expected_web:
        raise RuntimeError('Web probe has unexpected Docker network membership')
    for instance_id, plan in plans:
        sidecar = _docker_json('inspect', sidecars[instance_id])[0]['NetworkSettings']['Networks']
        gateway = _docker_json('inspect', gateways[instance_id])[0]['NetworkSettings']['Networks']
        if set(sidecar) != {network_names[(instance_id, 'agent')],
                            network_names[(instance_id, 'frontend')]}:
            raise RuntimeError('Sidecar probe has unexpected Docker network membership')
        if set(gateway) != {network_names[(instance_id, 'agent')]}:
            raise RuntimeError('Gateway probe has unexpected Docker network membership')
        if sidecar[network_names[(instance_id, 'agent')]].get('IPAddress') != plan['agent']['sidecar_ip']:
            raise RuntimeError('Sidecar agent IP read-back mismatch')
        if sidecar[network_names[(instance_id, 'frontend')]].get('IPAddress') != plan['frontend']['sidecar_ip']:
            raise RuntimeError('Sidecar frontend IP read-back mismatch')
        if gateway[network_names[(instance_id, 'agent')]].get('IPAddress') != plan['agent']['gateway_ip']:
            raise RuntimeError('Gateway agent IP read-back mismatch')


def _packet_checks(plans, web_id, sidecars, gateways):
    first_id, first = plans[0]
    second_id, second = plans[1]
    for container, host, port in (
        (web_id, first['frontend']['sidecar_ip'], 18790),
        (web_id, second['frontend']['sidecar_ip'], 18790),
        (sidecars[first_id], first['agent']['gateway_ip'], 18789),
        (sidecars[second_id], second['agent']['gateway_ip'], 18789),
    ):
        _wait_allowed(container, host, port)

    denied = (
        (web_id, first['agent']['gateway_ip'], 18789),
        (web_id, second['agent']['gateway_ip'], 18789),
        (sidecars[first_id], second['agent']['gateway_ip'], 18789),
        (sidecars[second_id], first['agent']['gateway_ip'], 18789),
        (gateways[first_id], second['agent']['gateway_ip'], 18789),
        (gateways[second_id], first['agent']['gateway_ip'], 18789),
        (sidecars[first_id], second['frontend']['sidecar_ip'], 18790),
        (sidecars[second_id], first['frontend']['sidecar_ip'], 18790),
    )
    for container, host, port in denied:
        _probe_container(container, host, port, allow=False)

    for _instance_id, plan in plans:
        for address, port in ((plan['agent']['gateway_ip'], 18789),
                              (plan['agent']['sidecar_ip'], 18790),
                              (plan['frontend']['sidecar_ip'], 18790)):
            _host_probe_blocked(address, port)

    host_listeners = []
    try:
        for _instance_id, plan in plans:
            for role in ('agent', 'frontend'):
                gateway = plan[role]['gateway']
                port, stop, listener, thread = _host_listener(gateway)
                host_listeners.append((stop, listener, thread))
                for container in (web_id, *sidecars.values(), *gateways.values()):
                    _probe_container(container, gateway, port, allow=False)
    finally:
        for stop, listener, thread in host_listeners:
            stop.set()
            listener.close()
            thread.join(timeout=1)


def _cleanup(resources, manager):
    failures = []
    for container_id in reversed(resources['containers']):
        try:
            _run(['docker', 'rm', '--force', container_id], timeout=30)
        except Exception:
            failures.append('container ' + container_id)
    for network_id in reversed(resources['networks']):
        try:
            _run(['docker', 'network', 'rm', network_id], timeout=30)
        except Exception:
            failures.append('network ' + network_id)
    if manager is not None:
        try:
            manager.apply(())
            if manager.adapter.read() is not None:
                failures.append('owned nftables test tables')
        except Exception:
            failures.append('owned nftables test tables')
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-pool', required=True,
                        help='Explicit RFC1918 test pool, checked against live routes and Docker IPAM')
    parser.add_argument('--frontend-pool', required=True,
                        help='Second explicit, non-overlapping RFC1918 test pool')
    parser.add_argument('--probe-image', required=True,
                        help='Already-local immutable sha256 image containing Python 3; never pulled')
    parser.add_argument('--execute', action='store_true',
                        help='Actually create temporary Docker networks/containers and nftables tables')
    parser.add_argument('--confirm-disposable-host', action='store_true',
                        help='Confirm this Linux host is disposable and has no user workloads/data')
    args = parser.parse_args()

    try:
        _check_environment(args)
        engine, run_id, plans = _plans(args)
        policies = tuple(engine._proxy_firewall_policy(instance_id, plan)
                         for instance_id, plan in plans)
        adapter = NftablesAdapter()
        if adapter.read() is not None:
            raise RuntimeError('Refusing to replace existing agent_proxy_v1 nftables tables')
        manager = FirewallManager(adapter, semantics_validated=True)
        resources = {'containers': [], 'networks': []}
        if len(plans) != 2 or len(policies) != 2:
            raise RuntimeError('Exactly two isolated test owners are required')
        failure = None
        try:
            web_id, sidecars, gateways, network_names, network_ids = _create_probe_topology(
                run_id, args.probe_image, plans, resources)
            _verify_retained_docker_routes(engine, plans, network_ids)
            _verify_memberships(plans, web_id, sidecars, gateways, network_names)
            manager.apply(policies)
            if not manager.ready(policies):
                raise RuntimeError('nftables ruleset read-back did not match the exact policy')
            _packet_checks(plans, web_id, sidecars, gateways)
        except Exception as error:
            failure = error
        finally:
            failures = _cleanup(resources, manager if manager.can_apply else None)
        if failures:
            print('CLEANUP INCOMPLETE for generated resources: ' + ', '.join(failures), file=sys.stderr)
            return 2
        if failure is not None:
            raise failure
        print('PASS: live Docker IPAM/membership and allowed/denied packet probes matched the two-owner policy.')
        print('PASS: nft -a -j read-back matched; temporary containers, networks, and firewall tables are cleaned up.')
        print('NOTE: the Supervisor source gate remains false; this test-only manager override is not production readiness.')
        return 0
    except Exception as error:
        message = str(error).replace('\n', ' ')[:240]
        print('FAIL: ' + (message or 'isolated Docker acceptance failed'), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
