"""Opt-in Linux implementation. No imports execute commands or change state.

All network mutations require an inherited caller netns FD and a different
current inode. The outer PID namespace is the final fail-safe teardown boundary.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from scripts.ollama_route_acceptance import (
    CHECKS, binding, command, make_plan, network_argv, network_specs, proxy_policy, new_report, stop,
    strict_json, validate_report,
)
from supervisor.docker_engine import DockerEngine
from supervisor.firewall import NftablesAdapter
from supervisor.firewall_acceptance import machine_id_sha256
from supervisor.ollama_firewall import TABLE_NAME, expected_ollama_ruleset

ROOT = Path(__file__).resolve().parents[1]
# The image must already contain Python 3. No package installation or image pull.
SERVER = r'''
import http.server, sys, threading
body = (sys.argv[1] + ':BEZR-return-path:').encode() * 1024
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
    def log_message(self, *args): pass
servers = [http.server.ThreadingHTTPServer(('0.0.0.0', p), Handler) for p in (11434,11435)]
for s in servers:
    threading.Thread(target=s.serve_forever, daemon=True).start()
threading.Event().wait()
'''
CLIENT = r'''
import http.client, json, socket, sys
expected = (sys.argv[3] + ':BEZR-return-path:').encode() * 1024
connection = http.client.HTTPConnection(sys.argv[1], int(sys.argv[2]), timeout=2,
    source_address=(sys.argv[4], 0) if sys.argv[4] else None)
try:
    connection.request('GET', '/bezr-packet-acceptance')
    response = connection.getresponse()
    body = response.read(len(expected) + 1)
    if response.status != 200 or body != expected:
        raise RuntimeError('Listener transaction mismatch')
    print('HTTP_OK')
except (TimeoutError, ConnectionRefusedError, ConnectionResetError, OSError):
    print('CONNECT_DENIED')
finally:
    connection.close()
'''


def arguments(parser, *, docker=False):
    for flag in ('agent-pool', 'frontend-pool', 'ollama-pool', 'endpoint', 'interface'):
        parser.add_argument('--' + flag, required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--confirm-disposable-host', action='store_true')
    parser.add_argument('--run-id', default=None)
    if docker:
        parser.add_argument('--image-archive', required=True)
        parser.add_argument('--probe-image', required=True, help='Exact sha256 image ID containing python3')


def require_opt_in(parser, args):
    if (sys.platform != 'linux' or getattr(os, 'geteuid', lambda: -1)() != 0
            or not args.execute or not args.confirm_disposable_host):
        parser.error('Linux root, --execute and --confirm-disposable-host are required')


def prerequisites(args, *, docker):
    required = ['unshare', 'ip', 'nft', 'nsenter', 'mount', 'sleep']
    if docker:
        required += ['docker', 'dockerd']
        if re.fullmatch(r'sha256:[0-9a-f]{64}', args.probe_image) is None:
            raise ValueError('Explicit sha256 image ID required')
        archive = Path(args.image_archive)
        if not archive.is_absolute() or not archive.is_file() or archive.is_symlink():
            raise ValueError('Explicit existing absolute image archive required')
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise RuntimeError('Missing existing binaries (never installed): ' + ', '.join(missing))


def config_from(args):
    return binding(args.agent_pool, args.frontend_pool, args.ollama_pool,
                   args.endpoint, args.interface, machine_id_sha256())


def inode(pid: str | int = 'self'):
    return os.stat('/proc/' + str(pid) + '/ns/net').st_ino


def current_namespaces():
    return {name: os.stat('/proc/self/ns/' + name).st_ino for name in ('net', 'mnt', 'pid')}


def validate_lab_boundary(args):
    """Internal flags alone grant nothing: require the whole disposable boundary."""
    current, parent = current_namespaces(), {}
    for name in ('net', 'mnt', 'pid'):
        descriptor = getattr(args, 'parent_' + name + 'ns_fd', None)
        if type(descriptor) is not int or descriptor < 0:
            raise RuntimeError('All inherited caller namespace descriptors are required')
        observed = os.fstat(descriptor).st_ino
        if (os.readlink('/proc/self/fd/' + str(descriptor)) != f'{name}:[{observed}]'
                or observed == current[name]):
            raise RuntimeError('Network, mount and PID namespaces must all be isolated')
        parent[name] = observed
    if os.getpid() != 1 or os.stat('/proc/1/ns/pid').st_ino != current['pid']:
        raise RuntimeError('Private PID namespace init and matching private procfs required')
    with open('/proc/self/mountinfo', 'r', encoding='ascii') as source:
        mounts = source.read(524289)
    if not mounts or len(mounts) > 524288:
        raise RuntimeError('Private mount propagation proof unavailable')
    private_proc = False
    for line in mounts.splitlines():
        fields = line.split()
        if '-' not in fields or fields.index('-') < 6:
            raise RuntimeError('Malformed mount propagation proof')
        separator = fields.index('-')
        if len(fields) < separator + 4:
            raise RuntimeError('Malformed mount propagation proof')
        if any(value.startswith(('shared:', 'master:', 'propagate_from:'))
               for value in fields[6:separator]):
            raise RuntimeError('Caller-visible mount propagation is prohibited')
        if fields[4] == '/proc' and fields[separator + 1] == 'proc':
            private_proc = True
    if not private_proc:
        raise RuntimeError('Matching private procfs mount required')
    return current, parent


def daemon_argv(base, run_id):
    return ['dockerd', '--config-file', str(base / 'daemon.json'),
            '--host', 'unix://' + str(base / 'docker.sock'), '--data-root', str(base / 'data'),
            '--exec-root', str(base / 'exec'), '--pidfile', str(base / 'dockerd.pid'),
            '--storage-driver', 'vfs', '--bridge', 'none', '--iptables=false',
            '--ip6tables=false', '--ip-forward=false', '--ip-masq=false',
            '--userland-proxy=false', '--exec-opt', 'native.cgroupdriver=cgroupfs',
            '--containerd-namespace', 'bezr-' + run_id,
            '--containerd-plugins-namespace', 'bezr-' + run_id]


def verify_network_readback(observed, identity, payload):
    """Keep exact payload checks; permit only Docker's empty default IPAM options."""
    if type(observed) is not dict or observed.get('Id') != identity:
        raise RuntimeError('Docker network ID readback mismatch')
    for key, expected in payload.items():
        if key == 'IPAM':
            ipam = observed.get(key)
            if (type(ipam) is not dict or set(ipam) - set(expected) - {'Options'}
                    or ipam.get('Options') not in (None, {})
                    or any(ipam.get(field) != value for field, value in expected.items())):
                raise RuntimeError('Canonical Docker IPAM readback mismatch')
        elif observed.get(key) != expected:
            raise RuntimeError('Canonical Docker network readback mismatch: ' + key)


class Lab:
    def __init__(self, args, config, docker):
        self.args, self.config, self.docker = args, config, docker
        self.namespace_binding, caller_namespaces = validate_lab_boundary(args)
        self.caller = caller_namespaces['net']
        self.router = self.namespace_binding['net']
        self.guard()
        self.policies, self.probes, self.addresses = make_plan(config)
        self.holders, self.processes, self.links, self.containers, self.networks = {}, [], [], [], []
        self.daemon = None
        self.socket = None
        self.temp = None
        self.adapter = NftablesAdapter(table_name=TABLE_NAME, runner=self.run,
                                       batch_runner=lambda argv, text: self.run(argv, input_text=text))
        self.rules = expected_ollama_ruleset(self.policies)
        self.proxy_adapter = NftablesAdapter(runner=self.run,
                                batch_runner=lambda argv, text: self.run(argv, input_text=text))
        self.proxy_rules = proxy_policy(config)
        self.specs = network_specs(config)

    def guard(self):
        if (self.caller == self.router or current_namespaces() != self.namespace_binding
                or os.getpid() != 1):
            raise RuntimeError('Refusing mutation outside complete disposable namespace boundary')

    def run(self, argv, **kwargs):
        self.guard()
        return command(argv, **kwargs)

    def ns(self, role, argv):
        self.guard()
        process = self.holders[role]
        if process.poll() is not None or inode(process.pid) in (self.router, self.caller):
            raise RuntimeError('Target namespace isolation proof failed')
        return ['nsenter', '--target', str(process.pid), '--net', '--', *argv]

    def spawn(self, argv):
        self.guard()
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, shell=False)
        self.processes.append(process)
        return process

    def holder(self, role):
        self.guard()
        process = self.spawn(['unshare', '--net', '--', 'sleep', '900'])
        self.holders[role] = process
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            if inode(process.pid) not in (self.router, self.caller):
                return
            time.sleep(.02)
        raise RuntimeError('New target namespace failed isolation proof')

    def link(self, local, peer, role):
        self.guard()
        self.run(['ip', 'link', 'add', local, 'type', 'veth', 'peer', 'name', peer])
        self.links.append(local)
        # Prove the destination differs immediately before moving a link.
        self.ns(role, ['true'])
        self.run(['ip', 'link', 'set', peer, 'netns', str(self.holders[role].pid)])
        self.run(self.ns(role, ['ip', 'link', 'set', 'lo', 'up']))
        self.run(self.ns(role, ['ip', 'link', 'set', peer, 'up']))
        self.run(['ip', 'link', 'set', local, 'up'])

    def setup(self):
        self.guard()
        # Mount namespace is private (unshare --propagation private). All /run
        # sockets, netns mounts and daemon runtime state remain disposable.
        self.run(['mount', '-t', 'tmpfs', '-o', 'mode=755,size=64m', 'tmpfs', '/run'])
        self.run(['ip', 'link', 'set', 'lo', 'up'])
        self.guard()
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
        self.holder('target')
        self.link(self.args.interface, 'bzrtarget', 'target')
        self.run(['ip', 'address', 'add', '169.254.254.1/30', 'dev', self.args.interface])
        self.run(self.ns('target', ['ip', 'address', 'add', '169.254.254.2/30', 'dev', 'bzrtarget']))
        for destination in ('target', 'foreign'):
            address = self.addresses[destination]
            self.run(self.ns('target', ['ip', 'address', 'add', address + '/32', 'dev', 'bzrtarget']))
            self.run(['ip', 'route', 'add', address + '/32', 'via', '169.254.254.2',
                      'dev', self.args.interface])
        self.run(self.ns('target', ['ip', 'route', 'add', 'default', 'via', '169.254.254.1']))
        if self.docker:
            self.setup_docker()
        else:
            roles = sorted({role for _, _, members in self.specs for role, _ in members})
            for role in roles:
                self.holder(role)
            serial = 0
            defaults = set()
            for plan, payload, members in self.specs:
                bridge = plan['bridge']
                self.run(['ip', 'link', 'add', bridge, 'type', 'bridge'])
                self.links.append(bridge)
                self.run(['ip', 'address', 'add', plan['gateway'] + '/29', 'brd',
                          str(ipaddress.IPv4Network(plan['subnet']).broadcast_address), 'dev', bridge])
                self.run(['ip', 'link', 'set', bridge, 'up'])
                for role, address in members:
                    serial += 1
                    local, peer = 'bzl' + str(serial), 'bzp' + str(serial)
                    self.link(local, peer, role)
                    self.run(['ip', 'link', 'set', local, 'master', bridge])
                    self.run(self.ns(role, ['ip', 'address', 'add', address + '/29', 'dev', peer]))
                    if role not in defaults:
                        self.run(self.ns(role, ['ip', 'route', 'add', 'default', 'via', plan['gateway']]))
                        defaults.add(role)
            for role in roles:
                self.spawn(self.ns(role, [sys.executable, '-c', SERVER, self.args.run_id]))
        self.spawn(self.ns('target', [sys.executable, '-c', SERVER, self.args.run_id]))
        self.spawn([sys.executable, '-c', SERVER, self.args.run_id])

    def dc(self, argv, **kwargs):
        self.guard()
        if (not self.socket or not self.daemon or self.daemon.poll() is not None
                or inode(self.daemon.pid) != self.router):
            raise RuntimeError('Private nested Docker daemon unavailable or namespace changed')
        return self.run(['docker', '--config', str(Path(self.socket).parent / 'cli'),
                         '--host', 'unix://' + self.socket, *argv],
                        env={k: v for k, v in os.environ.items() if not k.startswith('DOCKER_')}, **kwargs)

    def setup_docker(self):
        self.guard()
        base = Path(self.args.lab_dir)
        if not base.is_absolute() or base.is_symlink() or not base.name.startswith('bezr-ollama-'):
            raise RuntimeError('Private outer-owned daemon workspace required')
        self.socket = str(base / 'docker.sock')
        (base / 'daemon.json').write_text('{}\n')
        self.daemon = self.spawn(daemon_argv(base, self.args.run_id))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                self.dc(['info', '--format', '{{.ID}}'], timeout=2)
                break
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                if self.daemon.poll() is not None:
                    raise RuntimeError('Private nested dockerd failed to start')
                time.sleep(.2)
        else:
            raise RuntimeError('Private nested dockerd startup timed out')
        self.dc(['image', 'load', '--input', self.args.image_archive], timeout=120)
        observed = strict_json(self.dc(['image', 'inspect', self.args.probe_image]))
        if len(observed) != 1 or observed[0].get('Id') != self.args.probe_image:
            raise RuntimeError('Loaded image does not match explicit immutable image ID')
        memberships = {}
        for plan, payload, members in self.specs:
            network_id = self.dc(network_argv(payload)).strip()
            self.networks.append(network_id)
            observed = strict_json(self.dc(['network', 'inspect', network_id]))
            if type(observed) is not list or len(observed) != 1:
                raise RuntimeError('Docker network ID readback mismatch')
            verify_network_readback(observed[0], network_id, payload)
            for role, address in members:
                memberships.setdefault(role, []).append((network_id, plan, address))
        for role, attachments in sorted(memberships.items()):
            network_id, plan, address = attachments[0]
            container = self.dc(['create', '--pull=never', '--network', network_id,
                '--ip', address, '--name', 'bezr-' + role,
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                '--pids-limit', '64', '--memory', '128m', '--entrypoint', 'python3',
                self.args.probe_image, '-c', SERVER, self.args.run_id]).strip()
            self.containers.append(container)
            for other_id, other_plan, other_address in attachments[1:]:
                self.dc(['network', 'connect', '--ip', other_address, other_id, container])
            self.dc(['start', container])
            data = strict_json(self.dc(['inspect', container]))[0]
            endpoints = data['NetworkSettings']['Networks']
            if (data['State']['Running'] is not True or
                    set(endpoints) != {p['name'] for _, p, _ in attachments}):
                raise RuntimeError('Live container membership readback failed')
            for expected_id, expected_plan, expected_address in attachments:
                endpoint = endpoints[expected_plan['name']]
                if endpoint['NetworkID'] != expected_id or endpoint['IPAddress'] != expected_address:
                    raise RuntimeError('Live container endpoint identity readback failed')
            pid = data['State']['Pid']
            if type(pid) is not int or pid <= 0 or inode(pid) in (self.router, self.caller):
                raise RuntimeError('Container namespace isolation proof failed')
            # Internal proxy networks intentionally lack external routes. Add a
            # lab-only route so denied sidecar probes have reachable controls;
            # this tests firewall enforcement, not absence of a default route.
            self.guard()
            if inode(pid) in (self.router, self.caller):
                raise RuntimeError('Container namespace changed before route mutation')
            self.run(['nsenter', '--target', str(pid), '--net', '--',
                      'ip', 'route', 'replace', 'default', 'via', plan['gateway']])

    def transaction(self, spec):
        role = spec['source']
        client = ['python3' if self.docker and role not in ('target',) else sys.executable,
                  '-c', CLIENT, spec['destination'], str(spec['port']), self.args.run_id,
                  self.args.endpoint if role == 'target' else '']
        if self.docker and role != 'target':
            text = self.dc(['exec', 'bezr-' + role, *client], timeout=6)
        else:
            text = self.run(self.ns(role, client), timeout=6)
        if text.strip() not in ('HTTP_OK', 'CONNECT_DENIED'):
            raise RuntimeError('Probe command did not produce valid transaction evidence')
        return text.strip() == 'HTTP_OK'

    def set_policy(self, enabled):
        self.guard()
        for adapter, rules in ((self.adapter, self.rules), (self.proxy_adapter, self.proxy_rules)):
            if enabled:
                adapter.replace(rules)
                if adapter.read() != rules:
                    raise RuntimeError('Canonical production policy readback failed: ' + adapter.table_name)
            else:
                # Narrowly disable just the two BEZR policies in this private
                # lab; never flush any family or change caller rules.
                adapter.remove()
                if adapter.read() is not None:
                    raise RuntimeError('Narrow positive-control policy removal failed')

    def flush_neighbors(self):
        """Do not let pre-enforcement positive controls hide cold-path ARP failures."""
        self.guard()
        flush = ['ip', '-4', 'neigh', 'flush', 'all']
        self.run(flush)
        for role in self.holders:
            self.run(self.ns(role, flush))
        if self.docker:
            for container in self.containers:
                observed = strict_json(self.dc(['inspect', container]))
                if (type(observed) is not list or len(observed) != 1
                        or observed[0].get('Id') != container
                        or observed[0].get('State', {}).get('Running') is not True):
                    raise RuntimeError('Captured container changed before cold-neighbor probe')
                pid = observed[0]['State'].get('Pid')
                if type(pid) is not int or pid <= 0 or inode(pid) in (self.router, self.caller):
                    raise RuntimeError('Cold-neighbor target namespace is not isolated')
                self.run(['nsenter', '--target', str(pid), '--net', '--', *flush])

    def exercise(self):
        report = new_report(self.config, CHECKS[int(self.docker)], self.args.run_id,
                            str(self.caller), str(self.router))
        self.set_policy(False)
        # Wait for actual HTTP listener readiness; no timeout can become a pass.
        for spec in self.probes:
            deadline = time.monotonic() + 5
            while not self.transaction(spec):
                if time.monotonic() >= deadline:
                    raise RuntimeError('Listening positive control unreachable: ' + spec['name'])
                time.sleep(.05)
        self.set_policy(True)
        report['policy_readback'] = True
        for spec in self.probes:
            # Reinstall/read exact canonical policy for EVERY probe. Controls
            # differ only by deleting our two owned tables in this private lab.
            self.set_policy(False)
            before = self.transaction(spec)
            self.set_policy(True)
            if spec['allow']:
                self.flush_neighbors()
            enforced = self.transaction(spec)
            self.set_policy(False)
            after = self.transaction(spec)
            if not before or not after or enforced is not spec['allow']:
                raise RuntimeError('Packet acceptance failed: ' + spec['name'])
            report['probes'].append(dict(name=spec['name'], spec=spec, before=before,
                                         enforced=enforced, after=after))
        self.set_policy(True)
        report['cold_neighbors'] = True
        return report

    def cleanup(self):
        self.guard()
        errors = []
        def attempt(action):
            try:
                action()
            except Exception as error:
                errors.append(type(error).__name__)
        attempt(lambda: self.set_policy(False))
        if self.daemon and self.daemon.poll() is None:
            for container in reversed(self.containers):
                attempt(lambda c=container: self.dc(['rm', '--force', c], timeout=15))
            for network in reversed(self.networks):
                attempt(lambda n=network: self.dc(['network', 'rm', n], timeout=15))
            def verify_daemon_empty():
                if self.dc(['container', 'ls', '--all', '--quiet']).strip():
                    raise RuntimeError('Owned containers remain after cleanup')
                names = self.dc(['network', 'ls', '--format', '{{.Name}}']).splitlines()
                owned_names = {payload['Name'] for _, payload, _ in self.specs}
                if owned_names.intersection(names):
                    raise RuntimeError('Owned networks remain after cleanup')
            attempt(verify_daemon_empty)
        for process in reversed(self.processes):
            attempt(lambda p=process: stop(p))
            if process.poll() is None:
                errors.append('process still alive')
        # Stop target namespaces first; their veth counterparts disappear.
        for link in reversed(self.links):
            current = strict_json(self.run(['ip', '-j', 'link', 'show']))
            if any(item['ifname'] == link for item in current):
                attempt(lambda name=link: self.run(['ip', 'link', 'delete', name]))
        if self.temp:
            attempt(self.temp.cleanup)
        if self.adapter.read() is not None or self.proxy_adapter.read() is not None:
            errors.append('policy still installed')
        remaining = strict_json(self.run(['ip', '-j', 'link', 'show']))
        if any(item['ifname'] != 'lo' for item in remaining):
            errors.append('owned network links remain')
        if errors:
            raise RuntimeError('Disposable lab cleanup failed; no report/receipt')


def main(argv=None, *, docker=False, _inside=False):
    parser = argparse.ArgumentParser(description=__doc__)
    arguments(parser, docker=docker)
    if _inside:
        parser.add_argument('--parent-netns-fd', type=int, required=True)
        parser.add_argument('--parent-mntns-fd', type=int, required=True)
        parser.add_argument('--parent-pidns-fd', type=int, required=True)
        parser.add_argument('--lab-dir', required=True)
    else:
        # Public CLIs cannot choose the internal execution branch at all.
        parser.set_defaults(parent_netns_fd=None, parent_mntns_fd=None,
                            parent_pidns_fd=None, lab_dir=None)
    args = parser.parse_args(argv)
    require_opt_in(parser, args)
    def interrupt(signum, frame):
        raise RuntimeError('Acceptance interrupted')
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        if args.run_id is None:
            import secrets
            args.run_id = secrets.token_hex(16)
        if re.fullmatch('[0-9a-f]{32}', args.run_id) is None:
            raise ValueError('Invalid run ID')
        config = config_from(args)
        policies = make_plan(config)[0]
        if args.interface in ('lo', 'bzrtarget', *(p.bridge for p in policies)):
            raise ValueError('Egress interface collides with disposable topology')
        prerequisites(args, docker=docker)
        internal_fds = (args.parent_netns_fd, args.parent_mntns_fd, args.parent_pidns_fd)
        if any(fd is not None for fd in internal_fds) and not all(fd is not None for fd in internal_fds):
            raise RuntimeError('Partial internal namespace descriptor bundle prohibited')
        if _inside and not all(fd is not None for fd in internal_fds):
            raise RuntimeError('Internal namespace descriptor bundle required')
        if not _inside:
            descriptors = {}
            try:
                for name in ('net', 'mnt', 'pid'):
                    descriptors[name] = os.open('/proc/self/ns/' + name, os.O_RDONLY)
                bootstrap = (
                    'import sys;sys.path.insert(0,sys.argv[1]);del sys.argv[1];'
                    'from scripts.ollama_route_linux import main;'
                    f'raise SystemExit(main(docker={docker!r},_inside=True))')
                child = [sys.executable, '-c', bootstrap, str(ROOT), '--agent-pool', args.agent_pool,
                         '--frontend-pool', args.frontend_pool, '--ollama-pool', args.ollama_pool,
                         '--endpoint', args.endpoint, '--interface', args.interface,
                         '--run-id', args.run_id, '--execute', '--confirm-disposable-host']
                for name, descriptor in descriptors.items():
                    child += ['--parent-' + name + 'ns-fd', str(descriptor)]
                if docker:
                    child += ['--image-archive', args.image_archive, '--probe-image', args.probe_image]
                # Outer-owned directory is removed even on child timeout or
                # handled signal. SIGKILL can leave an owned data-root; never a receipt.
                with tempfile.TemporaryDirectory(prefix='bezr-ollama-') as workspace:
                    child += ['--lab-dir', workspace]
                    output = command(['unshare', '--mount', '--net', '--pid', '--fork',
                        '--kill-child=SIGKILL', '--mount-proc', '--propagation', 'private', '--', *child],
                        timeout=600, pass_fds=tuple(descriptors.values()), start_new_session=False)
            finally:
                for descriptor in descriptors.values():
                    os.close(descriptor)
            report = validate_report(strict_json(output), config, CHECKS[int(docker)], args.run_id)
            # Child PID namespace has exited: even emergency teardown is complete.
            print(json.dumps(report, sort_keys=True))
            return 0
        lab = Lab(args, config, docker)
        report = None
        try:
            lab.setup()
            report = lab.exercise()
        finally:
            lab.cleanup()
        report['cleanup'] = True
        validate_report(report, config, CHECKS[int(docker)], args.run_id)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print('FAIL: ' + str(error).replace('\n', ' ')[:300], file=sys.stderr)
        return 1
