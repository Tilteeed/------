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


_RULESET_FAMILIES = ('inet', 'bridge')
_RULESET_SECTIONS = frozenset(('table', 'chains', 'rules'))
_RULESET_CHAINS = frozenset(('input', 'output', 'forward'))
_RULESET_DIFFS = frozenset((
    'missing_field', 'extra_field', 'type_mismatch', 'value_mismatch', 'order_mismatch',
))
_RULESET_PATH_FIELDS = frozenset((
    'tables', 'semantics_validated', 'table', 'chains', 'rules', 'family', 'name',
    'comment', 'type', 'hook', 'prio', 'policy', 'chain', 'expr', 'match', 'left',
    'op', 'right', 'meta', 'key', 'payload', 'protocol', 'field', 'prefix',
    'accept', 'drop', 'reject', 'verdict', 'ct', 'state', 'mark', 'counter',
    'notrack', 'set', 'map', 'numgen', 'jhash', 'th', 'tcp', 'udp', 'icmp',
    'icmpv6', 'ether',
))
_MISSING = object()


class ProxyRulesetMismatch(RuntimeError):
    """Exact canonical readback failed; carries only allowlisted structural facts."""
    def __init__(self, difference):
        self.ruleset_diff = difference
        super().__init__('Independent proxy canonical readback failed')


def _fingerprint(value):
    """Type-aware, hashable representation used only to detect list reordering."""
    if type(value) is dict:
        return ('dict', tuple(sorted((key, _fingerprint(item)) for key, item in value.items())))
    if type(value) is list:
        return ('list', tuple(_fingerprint(item) for item in value))
    if value is None:
        return ('none',)
    if type(value) in (bool, int, float, str):
        return (type(value).__name__, value)
    return ('other', type(value).__name__)


def _is_subsequence(shorter, longer):
    cursor = 0
    for item in longer:
        if cursor < len(shorter) and _fingerprint(shorter[cursor]) == _fingerprint(item):
            cursor += 1
    return cursor == len(shorter)


def _first_unmatched_index(shorter, longer):
    cursor = 0
    for index, item in enumerate(longer):
        if cursor < len(shorter) and _fingerprint(shorter[cursor]) == _fingerprint(item):
            cursor += 1
        else:
            return index
    return len(longer)


def _first_structure_difference(expected, actual, path=()):
    if type(expected) is not type(actual):
        return path, 'type_mismatch'
    if type(expected) is dict:
        for key in expected:
            if key not in actual:
                return path + (key,), 'missing_field'
        for key in actual:
            if key not in expected:
                return path + (key,), 'extra_field'
        for key in expected:
            difference = _first_structure_difference(expected[key], actual[key], path + (key,))
            if difference is not None:
                return difference
        return None
    if type(expected) is list:
        if (len(expected) == len(actual)
                and sorted(_fingerprint(item) for item in expected)
                == sorted(_fingerprint(item) for item in actual)
                and any(_fingerprint(left) != _fingerprint(right)
                        for left, right in zip(expected, actual))):
            index = next(i for i, (left, right) in enumerate(zip(expected, actual))
                         if _fingerprint(left) != _fingerprint(right))
            return path + (index,), 'order_mismatch'
        if len(expected) < len(actual) and _is_subsequence(expected, actual):
            index = _first_unmatched_index(expected, actual)
            return path + (index,), 'extra_field'
        if len(actual) < len(expected) and _is_subsequence(actual, expected):
            index = _first_unmatched_index(actual, expected)
            return path + (index,), 'missing_field'
        for index, (left, right) in enumerate(zip(expected, actual)):
            difference = _first_structure_difference(left, right, path + (index,))
            if difference is not None:
                return difference
        if len(expected) != len(actual):
            difference = 'extra_field' if len(expected) < len(actual) else 'missing_field'
            return path + (min(len(expected), len(actual)),), difference
        return None
    if expected != actual:
        return path, 'value_mismatch'
    return None


def _safe_ruleset_diff_path(path):
    output = ''
    for item in path:
        if type(item) is int:
            output += '[' + str(max(0, min(item, 65535))) + ']'
        else:
            name = item if type(item) is str and item in _RULESET_PATH_FIELDS else 'other'
            output += ('.' if output else '') + name
    return output or 'table'


def _describe_ruleset_difference(family, expected, actual, difference):
    path, kind = difference
    section = path[0] if path and path[0] in _RULESET_SECTIONS else 'table'
    index = (path[1] if section == 'rules' and len(path) > 1
             and type(path[1]) is int else None)
    containers = (actual, expected) if kind == 'extra_field' else (expected, actual)
    chain = None
    if section == 'rules' and index is not None:
        for container in containers:
            rules = container.get('rules') if type(container) is dict else None
            if type(rules) is list and index < len(rules) and type(rules[index]) is dict:
                candidate = rules[index].get('chain')
                if type(candidate) is str and candidate in _RULESET_CHAINS:
                    chain = candidate
                    break
    elif section == 'chains' and len(path) > 1 and type(path[1]) is int:
        chain_index = path[1]
        for container in containers:
            chains = container.get('chains') if type(container) is dict else None
            if type(chains) is list and chain_index < len(chains) and type(chains[chain_index]) is dict:
                candidate = chains[chain_index].get('name')
                if type(candidate) is str and candidate in _RULESET_CHAINS:
                    chain = candidate
                    break
    return {
        'family': family,
        'section': section,
        'chain': chain,
        'rule_index': index,
        'field': _safe_ruleset_diff_path(path),
        'difference': kind if kind in _RULESET_DIFFS else 'value_mismatch',
    }


def first_ruleset_difference(expected, actual):
    """Return the first safe structural difference without changing either tree."""
    if type(expected) is not dict:
        return _describe_ruleset_difference('inet', {}, {}, (('tables',), 'type_mismatch'))
    if actual is None:
        return _describe_ruleset_difference('inet', {}, {}, (('table',), 'missing_field'))
    if type(actual) is not dict:
        return _describe_ruleset_difference('inet', {}, {}, (('tables',), 'type_mismatch'))
    expected_tables = expected.get('tables', _MISSING)
    actual_tables = actual.get('tables', _MISSING)
    if expected_tables is _MISSING or actual_tables is _MISSING:
        kind = 'missing_field' if actual_tables is _MISSING else 'extra_field'
        return _describe_ruleset_difference('inet', {}, {}, (('tables',), kind))
    if type(expected_tables) is not dict or type(actual_tables) is not dict:
        return _describe_ruleset_difference('inet', {}, {}, (('tables',), 'type_mismatch'))
    for family in _RULESET_FAMILIES:
        expected_family = expected_tables.get(family, _MISSING)
        actual_family = actual_tables.get(family, _MISSING)
        if expected_family is _MISSING or actual_family is _MISSING:
            if expected_family is not actual_family:
                kind = 'missing_field' if actual_family is _MISSING else 'extra_field'
                return _describe_ruleset_difference(
                    family, {}, {}, (('table',), kind))
            continue
        difference = _first_structure_difference(expected_family, actual_family)
        if difference is not None:
            return _describe_ruleset_difference(family, expected_family, actual_family, difference)
    difference = _first_structure_difference(expected, actual)
    if difference is not None:
        return _describe_ruleset_difference('inet', {}, {}, difference)
    # The caller only requests a diff after strict inequality; fail closed if
    # an unfamiliar structure reaches this diagnostic path.
    return _describe_ruleset_difference('inet', {}, {}, (('tables',), 'value_mismatch'))


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
            actual = self.proxy_adapter.read()
            if actual != self.proxy_rules:
                raise ProxyRulesetMismatch(first_ruleset_difference(self.proxy_rules, actual))
        else:
            self.proxy_adapter.remove()
            if self.proxy_adapter.read() is not None:
                raise RuntimeError('Independent proxy positive-control removal failed')

    def cleanup_policy_removals(self):
        # Independent proxy acceptance must never remove the Ollama policy.
        return (('remove_proxy_policy', self.proxy_adapter),)


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
