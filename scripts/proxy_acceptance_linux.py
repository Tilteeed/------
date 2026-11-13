"""Independent proxy-only lab using the existing private namespace/Docker transport."""
from copy import copy
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import ipaddress

from scripts import ollama_route_linux as transport
from scripts.ollama_route_acceptance import binding as route_binding, proxy_policy
from scripts import proxy_packet_acceptance as contract


class ProxyLab(transport.Lab):
    def __init__(self, args, config, docker):
        local_args = copy(args)
        # The inherited transport needs only a lab egress, not a real host NIC.
        pools = [ipaddress.IPv4Network(config[key]) for key in ('agent_network_pool', 'frontend_network_pool')]
        unused = next(pool for pool in map(ipaddress.IPv4Network,
                      ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
                      if not any(pool.overlaps(item) for item in pools))
        auxiliary = str(next(unused.subnets(new_prefix=24)))
        local_args.interface = 'bzrbase0'
        local_args.endpoint = str(unused.broadcast_address - 5)
        local_args.topology = 'routed'
        inherited = route_binding(config['agent_network_pool'], config['frontend_network_pool'],
                                  auxiliary, local_args.endpoint, local_args.interface,
                                  config['host_id_sha256'])
        super().__init__(local_args, inherited, docker)
        self.probes, self.addresses = contract.make_plan(config)
        self.args.endpoint = self.addresses['target']
        self.specs = contract.network_specs(config)
        self.proxy_rules = proxy_policy(config)
        self.proxy_binding = config

    def exercise(self):
        report = contract.new_report(self.proxy_binding, contract.CHECKS[int(self.docker)],
                                     self.args.run_id, str(self.caller), str(self.router))
        self.set_policy(False)
        for spec in self.probes:
            deadline = transport.time.monotonic() + 5
            while not self.transaction(spec):
                if transport.time.monotonic() >= deadline:
                    raise RuntimeError('Proxy listening positive control unreachable: ' + spec['name'])
                transport.time.sleep(.05)
        for spec in self.probes:
            self.set_policy(False)
            before = self.transaction(spec)
            self.set_policy(True)
            if spec['allow']:
                self.flush_neighbors()
            enforced = self.transaction(spec)
            self.set_policy(False)
            after = self.transaction(spec)
            if not before or not after or enforced is not spec['allow']:
                raise RuntimeError('Independent proxy packet failure: ' + spec['name'])
            report['probes'].append(dict(name=spec['name'], spec=spec, before=before,
                                         enforced=enforced, after=after))
        self.set_policy(True)
        report['policy_readback'] = True
        report['cold_neighbors'] = True
        return report

    def set_policy(self, enabled):
        self.guard()
        # Independent base evidence must not benefit from an Ollama deny table.
        if self.adapter.read() is not None:
            raise RuntimeError('Ollama policy present during independent proxy acceptance')
        if enabled:
            self.proxy_adapter.replace(self.proxy_rules)
            if self.proxy_adapter.read() != self.proxy_rules:
                raise RuntimeError('Independent proxy canonical readback failed')
        else:
            self.proxy_adapter.remove()
            if self.proxy_adapter.read() is not None:
                raise RuntimeError('Independent proxy positive-control removal failed')


def main(argv=None, *, docker=False, _inside=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-pool', required=True)
    parser.add_argument('--frontend-pool', required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--confirm-disposable-host', action='store_true')
    parser.add_argument('--run-id')
    if docker:
        parser.add_argument('--image-archive', required=True)
        parser.add_argument('--probe-image', required=True)
    if _inside:
        for name in ('net', 'mnt', 'pid'):
            parser.add_argument('--parent-' + name + 'ns-fd', type=int, required=True)
        parser.add_argument('--lab-dir', required=True)
    args = parser.parse_args(argv)
    transport.require_opt_in(parser, args)

    def interrupt(signum, frame):
        raise RuntimeError('Independent proxy acceptance interrupted')

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        args.run_id = args.run_id or secrets.token_hex(16)
        if re.fullmatch('[0-9a-f]{32}', args.run_id) is None:
            raise ValueError('Invalid proxy run ID')
        config = contract.binding(args.agent_pool, args.frontend_pool, transport.machine_id_sha256())
        transport.prerequisites(args, docker=docker)
        if not _inside:
            descriptors = {}
            try:
                for name in ('net', 'mnt', 'pid'):
                    descriptors[name] = os.open('/proc/self/ns/' + name, os.O_RDONLY)
                caller = str(os.fstat(descriptors['net']).st_ino)
                bootstrap = (
                    'import sys;sys.path.insert(0,sys.argv[1]);del sys.argv[1];'
                    'from scripts.proxy_acceptance_linux import main;'
                    f'raise SystemExit(main(docker={docker!r},_inside=True))')
                child = [sys.executable, '-c', bootstrap, str(transport.ROOT),
                         '--agent-pool', args.agent_pool, '--frontend-pool', args.frontend_pool,
                         '--run-id', args.run_id, '--execute', '--confirm-disposable-host']
                for name, descriptor in descriptors.items():
                    child += ['--parent-' + name + 'ns-fd', str(descriptor)]
                if docker:
                    child += ['--image-archive', args.image_archive, '--probe-image', args.probe_image]
                with transport.tempfile.TemporaryDirectory(prefix='bezr-ollama-proxy-') as workspace:
                    child += ['--lab-dir', workspace]
                    output = transport.command(['unshare', '--mount', '--net', '--pid', '--fork',
                        '--kill-child=SIGKILL', '--mount-proc', '--propagation', 'private', '--', *child],
                        timeout=600, pass_fds=tuple(descriptors.values()), start_new_session=False)
            finally:
                for descriptor in descriptors.values():
                    os.close(descriptor)
            report = contract.validate_report(transport.strict_json(output), config,
                                               contract.CHECKS[int(docker)], args.run_id)
            if (report['caller_netns_inode'] != caller
                    or transport.machine_id_sha256() != config['host_id_sha256']):
                raise RuntimeError('Proxy caller/host binding drift')
            print(json.dumps(report, sort_keys=True))
            return 0
        lab = ProxyLab(args, config, docker)
        try:
            lab.setup()
            report = lab.exercise()
        finally:
            lab.cleanup()
        report['cleanup'] = True
        contract.validate_report(report, config, contract.CHECKS[int(docker)], args.run_id)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print('FAIL: ' + str(error).replace('\n', ' ')[:300], file=sys.stderr)
        return 1
