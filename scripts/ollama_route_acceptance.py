"""Shared strict contract for opt-in isolated Ollama packet acceptance."""
import hashlib
import json
import ipaddress
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Any
from supervisor.docker_engine import DockerEngine
from supervisor.firewall import EndpointPair, NetworkPolicy, expected_ruleset as proxy_ruleset
from supervisor.ollama_firewall import (OllamaRoutePolicy, build_ollama_route_receipt,
                                        expected_ollama_ruleset)

TOPOLOGIES = ('routed', 'host-local')
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
    return tuple(policies), [dict(spec, topology=topology)
                             for topology in TOPOLOGIES for spec in probes], addresses


def policy_digest(config):
    rules = {'ollama': expected_ollama_ruleset(make_plan(config)[0]), 'proxy': proxy_policy(config)}
    return hashlib.sha256(json.dumps(rules, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def topology_evidence(config, topology):
    if topology not in TOPOLOGIES:
        raise ValueError('Unsupported packet topology')
    local = topology == 'host-local'
    return dict(topology=topology, endpoint_namespace='router' if local else 'target',
                endpoint_interface='lo' if local else 'bzrtarget',
                route_type='local' if local else 'unicast',
                route_interface='lo' if local else config['egress_interface'],
                policy_readback=False, cold_neighbors=False)


def new_report(config, check, run_id, caller_inode, router_inode) -> dict[str, Any]:
    return dict(schema_version=2, check=check, run_id=run_id, binding=config,
                policy_sha256=policy_digest(config), caller_netns_inode=caller_inode,
                router_netns_inode=router_inode, policy_readback=False, cleanup=False,
                cold_neighbors=False, topologies=[], probes=[])


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
    topologies = [dict(topology_evidence(config, topology), policy_readback=True, cold_neighbors=True)
                  for topology in TOPOLOGIES]
    if type(report['topologies']) is not list or not exact_json(report['topologies'], topologies):
        raise ValueError('Incomplete or mismatched endpoint topology evidence')
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


def _parent_death_setup():
    """Arm Linux direct-child SIGKILL before exec, including the fork race.

    Load/resolve ctypes in the parent, not after fork. This hook is for the
    standalone, single-threaded wrappers; arbitrary threaded embedders must
    not use Python preexec_fn. Windows and other platforms have no such hook.
    """
    if sys.platform != 'linux':
        return None
    import ctypes
    parent_pid = os.getpid()
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                     ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    sigkill = signal.SIGKILL

    def arm():
        if prctl(1, sigkill, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            os._exit(127)  # Fail closed: never exec an unprotected child.
        if os.getppid() != parent_pid:
            os.kill(os.getpid(), sigkill)

    return arm


def _kill_command(process, *, start_new_session=True):
    # Only an owned session permits group signalling. An inherited session may
    # contain our caller, so its direct child alone is safe to kill here.
    if os.name == 'posix' and start_new_session:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()


def command(argv, *, timeout: float = 30, input_text=None, pass_fds=(), env=None,
            start_new_session=True, on_failure=None, separate_stderr=False):
    """Bound concurrent pipe I/O and process wait by one monotonic deadline.

    Nonblocking pipe operations also let both workers stop when a descendant
    retains an inherited pipe; closing a buffered pipe from another thread can
    itself block forever. Retained output is capped before every append.
    """
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE if separate_stderr else subprocess.STDOUT, shell=False,
                               start_new_session=start_new_session, pass_fds=pass_fds, env=env,
                               bufsize=0, preexec_fn=_parent_death_setup())
    output = bytearray()
    stderr_output = bytearray()
    output_lock = threading.Lock()
    cancel = threading.Event()
    overflow = threading.Event()
    errors = []
    workers = []

    def read(stream, destination):
        try:
            while not cancel.is_set():
                try:
                    chunk = os.read(stream.fileno(), 4096)
                except BlockingIOError:
                    cancel.wait(.01)
                    continue
                if not chunk:
                    return
                with output_lock:
                    if len(output) + len(stderr_output) + len(chunk) > LIMIT:
                        overflow.set()
                        return
                    destination.extend(chunk)
        except OSError as error:
            errors.append(error)

    def write():
        assert process.stdin is not None and input_text is not None
        try:
            # Encode in bounded pieces instead of duplicating a multi-MB input.
            for offset in range(0, len(input_text), 4096):
                data = memoryview(input_text[offset:offset + 4096].encode('utf-8'))
                while data and not cancel.is_set():
                    try:
                        written = os.write(process.stdin.fileno(), data)
                        data = data[written:]
                    except BlockingIOError:
                        cancel.wait(.01)
                if cancel.is_set():
                    return
        except BrokenPipeError:
            pass  # A child is allowed to finish without consuming all input.
        except (OSError, UnicodeError) as error:
            errors.append(error)
        finally:
            process.stdin.close()

    try:
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        workers.append(threading.Thread(target=read, args=(process.stdout, output),
                                        name='acceptance-stdout'))
        if process.stderr is not None:
            os.set_blocking(process.stderr.fileno(), False)
            workers.append(threading.Thread(target=read, args=(process.stderr, stderr_output),
                                            name='acceptance-stderr'))
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            workers.append(threading.Thread(target=write, name='acceptance-stdin'))
        for worker in workers:
            worker.start()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            if overflow.is_set() or errors:
                raise RuntimeError('Command failed or output exceeded bound: ' + argv[0])
            if process.poll() is not None and not any(worker.is_alive() for worker in workers):
                # Recheck after workers finish: a worker may have published a
                # failure between the earlier check and the liveness check.
                if process.returncode or overflow.is_set() or errors:
                    # Internal callers may inspect their own bounded diagnostic
                    # marker. Raw child output remains captured and is never
                    # included in this exception or emitted by this function.
                    if (process.returncode and not overflow.is_set() and not errors
                            and on_failure is not None):
                        try:
                            on_failure((output + stderr_output).decode('utf-8', 'replace'), process.returncode)
                        except Exception:
                            pass
                    raise RuntimeError('Command failed or output exceeded bound: ' + argv[0])
                return output.decode('utf-8')
            cancel.wait(min(.01, remaining))
    finally:
        cancel.set()
        try:
            _kill_command(process, start_new_session=start_new_session)
            process.wait(timeout=5)
        finally:
            for worker in workers:
                if worker.ident is not None:
                    worker.join(timeout=1)
            if any(worker.is_alive() for worker in workers):
                raise RuntimeError('Command pipe workers failed to stop')
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


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
