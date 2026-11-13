"""Stage 3 read-only fingerprints and dual *candidate* receipt orchestration.

This module does not expose a CLI or accept cached reports. Fingerprints are
machine-id/state-change evidence, not hardware attestation. No snapshot is ever
restored. The public entrypoint must supply its fixed live check/validator pair
and its busy-host approval before calling the permission-gated source.
"""
import copy
import hashlib
import json
import os
import re
import secrets
from pathlib import Path, PurePosixPath

from supervisor.firewall_acceptance import (
    _strict_object, _reject_json_constant, machine_id_sha256,
    build_firewall_acceptance_receipt, REQUIRED_CHECKS,
    _open_state_directory, validate_acceptance_state_path,
    write_firewall_acceptance_receipt, load_firewall_acceptance_receipt, RECEIPT_FILENAME,
)
from supervisor.ollama_firewall import (
    build_ollama_route_receipt, OLLAMA_ROUTE_REQUIRED_CHECKS,
    write_ollama_route_receipt, load_ollama_route_receipt, OLLAMA_ROUTE_RECEIPT_FILENAME,
)

CHECKS = REQUIRED_CHECKS + OLLAMA_ROUTE_REQUIRED_CHECKS
_SITE_KEYS = {'agent_network_pool', 'frontend_network_pool', 'ollama_network_pool',
              'ollama_endpoint_ip', 'egress_interface'}


def site_binding(site, host):
    """Exact current base+route policy/site binding; no imported host override."""
    if type(site) is not dict or set(site) != _SITE_KEYS:
        raise ValueError('Explicit exact site configuration required')
    base = build_firewall_acceptance_receipt(host, site['agent_network_pool'],
                    site['frontend_network_pool'], accepted_at_unix=1)
    route = build_ollama_route_receipt(host, site['agent_network_pool'],
                    site['frontend_network_pool'], site['ollama_network_pool'],
                    site['ollama_endpoint_ip'], site['egress_interface'], accepted_at_unix=1)
    return {name: {k: v for k, v in payload.items() if k not in ('checks', 'accepted_at_unix')}
            for name, payload in (('base', base), ('route', route))}


_SNAPSHOT_KEYS = {'nft', 'routes', 'interfaces', 'containers', 'networks', 'services'}


def _snapshot(value):
    if (type(value) is not dict or set(value) != _SNAPSHOT_KEYS
            or any(type(v) is not str or re.fullmatch('[0-9a-f]{64}', v) is None
                   for v in value.values())):
        raise ValueError('Complete digest-only production snapshot required')
    return dict(value)


def run_candidate_acceptance(site, *, source, store, check_runner, report_validator,
                             cleanup_verifier, allow_host_inspection=False,
                             busy_host_approved=False):
    """Run fixed live callbacks, then create a dual candidate (never activate it).

    check_runner(check, binding, run_id) must run the fixed real command and
    return a fresh envelope {check, binding, run_id, cleanup, passed, evidence}.
    report_validator(report, binding, check, run_id) MUST perform the real
    matrix validation (including controls/readback) and return literal True.
    cleanup_verifier() must independently prove all owned resources absent and
    return exactly {complete: True, resources_absent: True, checks: list(CHECKS)}.
    site is an exact five-key dictionary: agent_network_pool,
    frontend_network_pool, ollama_network_pool, ollama_endpoint_ip,
    egress_interface. binding contains current receipt-schema base and route
    payloads minus checks/time, sampled against the local machine-id digest.
    Returned before/after snapshots contain only the six component digests;
    raw snapshots/evidence/error text are never returned or persisted here.
    Site addresses are written only by the existing exact-binding receipt writers.
    These are internal Python dependencies, not user-selectable CLI adapters.
    """
    result = {'status': 'incomplete', 'phase': 'permission', 'checks': []}
    created = False
    try:
        if allow_host_inspection is not True or busy_host_approved is not True:
            raise ValueError('Explicit inspection permission and approval required')
        result['phase'] = 'preflight'
        host = machine_id_sha256()
        site = copy.deepcopy(site)
        binding = site_binding(site, host)
        store.preflight()
        options = dict(allow_host_inspection=True, busy_host_approved=True)
        result['before'] = _snapshot(source.capture(**options))
        result['host_id_sha256'] = host
        result['phase'] = 'checks'
        try:
            for check in CHECKS:
                run_id = secrets.token_hex(16)
                report = check_runner(check, copy.deepcopy(binding), run_id)
                if (type(report) is not dict
                        or set(report) != {'check', 'binding', 'run_id', 'cleanup', 'passed', 'evidence'}
                        or report['check'] != check or report['run_id'] != run_id
                        or report['cleanup'] is not True or report['passed'] is not True
                        or _digest(report['binding']) != _digest(binding)):
                    raise ValueError('Fresh bound successful check/cleanup evidence required')
                if report_validator(report, copy.deepcopy(binding), check, run_id) is not True:
                    raise ValueError('Real matrix validator rejected evidence')
                result['checks'].append(check)
        finally:
            proof = cleanup_verifier()
        result['phase'] = 'cleanup'
        if (type(proof) is not dict or set(proof) != {'complete', 'resources_absent', 'checks'}
                or proof['complete'] is not True or proof['resources_absent'] is not True
                or type(proof['checks']) is not list or proof['checks'] != list(CHECKS)):
            raise ValueError('Complete independently verified cleanup proof required')
        result['phase'] = 'snapshot'
        result['after'] = _snapshot(source.capture(**options))
        if machine_id_sha256() != host or _digest(result['before']) != _digest(result['after']):
            raise ValueError('Production state or local machine identity changed')
        result['phase'] = 'create'
        store.create()
        created = True
        result['phase'] = 'write_base'
        store.write_base(site, host)
        result['phase'] = 'write_route'
        store.write_route(site, host)
        result['phase'] = 'readback'
        if store.read_base(site) is not True or store.read_route(site) is not True:
            raise ValueError('Candidate loader readback rejected receipts')
        result['phase'] = 'complete'
        store.complete()
        result['status'] = 'complete'
    except Exception:
        if created:
            try:
                store.incomplete(result['phase'])
            except Exception:
                pass  # Existing incomplete diagnostic must not be deleted.
    return result


class RootCandidateStore:
    """New private root-controlled candidate directory, never production state.

    Immutable incomplete diagnostics survive partial writes. Only a fully
    validated pair earns candidate-ready.json; this is not activation evidence.
    Existing paths (including symlinks) are rejected, not reused or cleared.
    """
    def __init__(self, path):
        self.path = Path(path)
        self._identity = None
        self._base_readback = False
        self._route_readback = False

    def preflight(self):
        if os.path.lexists(self.path):
            raise ValueError('Candidate directory must be NEW')
        validate_acceptance_state_path(self.path)

    def create(self):
        self.preflight()
        if os.name != 'posix' or os.geteuid() != 0:
            raise ValueError('Root POSIX candidate writer required')
        os.mkdir(self.path, 0o700)  # Exclusive: never adopt a racing existing path.
        os.chown(self.path, 0, 0, follow_symlinks=False)
        fd = _open_state_directory(self.path)
        try:
            info = os.fstat(fd)
            self._identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)
        self._record('incomplete-create.json', {'status': 'incomplete', 'phase': 'create'})

    def _assert_owned(self):
        if self._identity is None:
            raise ValueError('Candidate directory was not created by this attempt')
        fd = _open_state_directory(self.path)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._identity:
                raise ValueError('Candidate directory identity changed')
        finally:
            os.close(fd)

    def _record(self, name, payload):
        self._assert_owned()
        directory = _open_state_directory(self.path)
        temporary = '.diagnostic-' + secrets.token_hex(16) + '.tmp'
        fd = None
        published = False
        try:
            if os.path.lexists(self.path / name):
                raise ValueError('Candidate diagnostic already exists')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW'),
                         0o600, dir_fd=directory)
            getattr(os, 'fchown')(fd, 0, 0)
            os.fchmod(fd, 0o600)
            raw = (json.dumps(payload, sort_keys=True) + '\n').encode('ascii')
            offset = 0
            while offset < len(raw):
                n = os.write(fd, raw[offset:])
                if n <= 0:
                    raise OSError('short diagnostic write')
                offset += n
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            published = True
            os.fsync(directory)
        except Exception:
            # Revoke only this attempt's just-published readiness marker; keep
            # incomplete records and any partial temporary as diagnostic evidence.
            if name == 'candidate-ready.json' and published:
                os.unlink(name, dir_fd=directory)
            raise
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)

    def write_base(self, site, host):
        self._assert_owned()
        if os.path.lexists(self.path / RECEIPT_FILENAME):
            raise ValueError('Refusing to overwrite candidate receipt')
        return write_firewall_acceptance_receipt(self.path, site['agent_network_pool'],
                    site['frontend_network_pool'], expected_host_id_sha256=host)

    def write_route(self, site, host):
        self._assert_owned()
        if os.path.lexists(self.path / OLLAMA_ROUTE_RECEIPT_FILENAME):
            raise ValueError('Refusing to overwrite candidate receipt')
        return write_ollama_route_receipt(self.path, site['agent_network_pool'],
                    site['frontend_network_pool'], site['ollama_network_pool'],
                    site['ollama_endpoint_ip'], site['egress_interface'], expected_host_id_sha256=host)

    def read_base(self, site):
        self._assert_owned()
        self._base_readback = load_firewall_acceptance_receipt(
            self.path, site['agent_network_pool'], site['frontend_network_pool']) is True
        return self._base_readback

    def read_route(self, site):
        self._assert_owned()
        self._route_readback = load_ollama_route_receipt(self.path, site['agent_network_pool'],
            site['frontend_network_pool'], site['ollama_network_pool'],
            site['ollama_endpoint_ip'], site['egress_interface']) is True
        return self._route_readback

    def complete(self):
        if not self._base_readback or not self._route_readback:
            raise ValueError('Both current-host loaders must pass before readiness')
        self._record('candidate-ready.json', {'status': 'candidate_ready', 'activation': False})

    def incomplete(self, phase):
        if phase not in ('create', 'write_base', 'write_route', 'readback', 'complete'):
            raise ValueError('Invalid diagnostic phase')
        self._record('incomplete-' + phase + '.json', {'status': 'incomplete', 'phase': phase})


READ_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent',
            'DOCKER_CONFIG': '/nonexistent', 'LANG': 'C', 'LC_ALL': 'C'}
_CONTAINER_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
    '"status":{{json .State.Status}},"pid":{{json .State.Pid}},'
    '"started_at":{{json .State.StartedAt}},"restart_count":{{json .RestartCount}},'
    '"networks":{ {{$first := true}}{{range $name, $net := .NetworkSettings.Networks}}'
    '{{if $first}}{{$first = false}}{{else}},{{end}}{{json $name}}:'
    '{"network_id":{{json $net.NetworkID}},"endpoint_id":{{json $net.EndpointID}},'
    '"gateway":{{json $net.Gateway}},"ip":{{json $net.IPAddress}},'
    '"prefix":{{json $net.IPPrefixLen}},"ipv6_gateway":{{json $net.IPv6Gateway}},'
    '"ipv6":{{json $net.GlobalIPv6Address}},"ipv6_prefix":{{json $net.GlobalIPv6PrefixLen}},'
    '"mac":{{json $net.MacAddress}},"aliases":{{json $net.Aliases}}}{{end}} }}')
_NETWORK_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},'
    '"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}},'
    '"ipam":{{json .IPAM.Config}},"containers":{{json .Containers}}}')
_SERVICE_FIELDS = ('MainPID', 'ExecMainStartTimestampMonotonic',
                   'ActiveEnterTimestampMonotonic', 'NRestarts', 'ActiveState', 'SubState')


def _json(text):
    if type(text) is not str or len(text.encode('utf-8')) > 262144:
        raise ValueError('Invalid bounded snapshot response')
    return json.loads(text, object_pairs_hook=_strict_object, parse_constant=_reject_json_constant)


class ProductionStateSource:
    """Permission-gated fixed read-only commands; no GPU/Ollama API calls.

    runner is the bounded command(argv, timeout=..., env=...) helper. Tests may
    inject a labelled synthetic transport; the public CLI must not expose this
    dependency as a report/adapter/skip flag.
    """
    def __init__(self, *, docker_socket, runner=None):
        if (type(docker_socket) is not str or not docker_socket.startswith('/')
                or docker_socket.startswith('//') or docker_socket == '/'
                or any(ord(char) < 33 or ord(char) > 126 for char in docker_socket)
                or '\\' in docker_socket
                or str(PurePosixPath(docker_socket)) != docker_socket
                or '..' in PurePosixPath(docker_socket).parts):
            raise ValueError('Explicit local UNIX Docker socket required')
        if runner is None:
            from scripts.ollama_route_acceptance import command
            runner = command
        self._runner = runner
        self._docker_prefix = ['/usr/bin/docker', '--host', 'unix://' + docker_socket,
                               '--config', '/nonexistent']

    def _read(self, argv):
        value = self._runner(argv, timeout=15, env=dict(READ_ENV))
        if type(value) is not str or len(value.encode('utf-8')) > 262144:
            raise ValueError('Invalid bounded snapshot response')
        return value

    def _docker(self, args):
        return self._read(self._docker_prefix + args)

    def _ids(self, args):
        values = self._docker(args).splitlines()
        if len(values) > 2048 or len(set(values)) != len(values) or any(
                re.fullmatch('[0-9a-f]{64}', value) is None for value in values):
            raise ValueError('Invalid Docker identity inventory')
        return sorted(values)

    def capture(self, *, allow_host_inspection=False, busy_host_approved=False):
        if allow_host_inspection is not True or busy_host_approved is not True:
            raise ValueError('Explicit host inspection permission and busy-host approval required')
        nft = _json(self._read(['/usr/sbin/nft', '-j', '-a', 'list', 'ruleset']))
        routes = [_json(self._read(['/usr/sbin/ip', '-j', family, 'route', 'show', 'table', 'all']))
                  for family in ('-4', '-6')]
        interfaces = _json(self._read(['/usr/sbin/ip', '-j', 'address', 'show']))
        containers = self._ids(['ps', '--all', '--quiet', '--no-trunc'])
        networks = self._ids(['network', 'ls', '--quiet', '--no-trunc'])
        container_state = [_json(self._docker(['container', 'inspect', '--format',
                           _CONTAINER_FORMAT, identity])) for identity in containers]
        network_state = [_json(self._docker(['network', 'inspect', '--format',
                         _NETWORK_FORMAT, identity])) for identity in networks]
        for identity, state in zip(containers, container_state):
            if (type(state) is not dict or set(state) != {
                    'id', 'name', 'image', 'status', 'pid', 'started_at', 'restart_count', 'networks'}
                    or state['id'] != identity
                    or any(type(state[k]) is not str for k in ('name', 'image', 'status', 'started_at'))
                    or any(type(state[k]) is not int or state[k] < 0 for k in ('pid', 'restart_count'))
                    or type(state['networks']) is not dict):
                raise ValueError('Invalid allowlisted container projection')
        for identity, state in zip(networks, network_state):
            if (type(state) is not dict or set(state) != {
                    'id', 'name', 'driver', 'internal', 'ipv6', 'ipam', 'containers'}
                    or state['id'] != identity
                    or any(type(state[k]) is not str for k in ('name', 'driver'))
                    or any(type(state[k]) is not bool for k in ('internal', 'ipv6'))
                    or (type(state['ipam']) not in (dict, list)
                        and not (state['driver'] in ('host', 'null') and state['ipam'] is None))
                    or (type(state['containers']) is not dict
                        and not (state['driver'] in ('host', 'null') and state['containers'] is None))):
                raise ValueError('Invalid allowlisted network projection')
        services = {}
        for unit in ('docker.service', 'ollama.service'):
            text = self._read(['/usr/bin/systemctl', 'show', unit,
                               '--property=' + ','.join(_SERVICE_FIELDS)])
            lines = [line.split('=', 1) for line in text.splitlines()]
            if (any(len(line) != 2 for line in lines) or len(lines) != len(_SERVICE_FIELDS)
                    or {line[0] for line in lines} != set(_SERVICE_FIELDS)):
                raise ValueError('Incomplete service lifecycle snapshot')
            services[unit] = dict(lines)
        if (containers != self._ids(['ps', '--all', '--quiet', '--no-trunc'])
                or networks != self._ids(['network', 'ls', '--quiet', '--no-trunc'])):
            raise ValueError('Docker inventory changed during snapshot')
        return {'nft': nft_fingerprint(nft), 'routes': _digest(routes),
                'interfaces': _digest(interfaces), 'containers': _digest(container_state),
                'networks': _digest(network_state), 'services': _digest(services)}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode('utf-8')).hexdigest()


def nft_fingerprint(document):
    """Ignore only recognized nft packet/byte runtime counter pairs.

    Preserve handles, ordering, quota limits/usage, unknown fields and unknown
    expression trees. In particular this is NOT a recursive key-name scrubber.
    An unfamiliar counter schema remains structural and therefore fails closed
    if it changes. The caller's document is never mutated.
    """
    if type(document) is not dict or type(document.get('nftables')) is not list:
        raise ValueError('Invalid nft snapshot')
    result = copy.deepcopy(document)
    for entry in result['nftables']:
        if type(entry) is not dict:
            raise ValueError('Invalid nft entry')
        if set(entry) == {'rule'} and type(entry['rule']) is dict:
            expressions = entry['rule'].get('expr', [])
            if type(expressions) is not list:
                raise ValueError('Invalid nft rule expressions')
            for expression in expressions:
                if type(expression) is dict and set(expression) == {'counter'}:
                    counter = expression['counter']
                    if (type(counter) is dict and set(counter) == {'packets', 'bytes'}
                            and all(type(v) is int and v >= 0 for v in counter.values())):
                        expression['counter'] = {}
        elif set(entry) == {'counter'} and type(entry['counter']) is dict:
            counter = entry['counter']
            if ({'family', 'table', 'name', 'packets', 'bytes'} <= set(counter)
                    <= {'family', 'table', 'name', 'packets', 'bytes', 'handle', 'comment'}
                    and counter['family'] in ('ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev')
                    and all(type(counter[k]) is str and counter[k] for k in ('table', 'name'))
                    and ('handle' not in counter or type(counter['handle']) is int
                         and counter['handle'] > 0)
                    and ('comment' not in counter or type(counter['comment']) is str)
                    and all(type(counter[k]) is int and counter[k] >= 0
                            for k in ('packets', 'bytes'))):
                del counter['packets']
                del counter['bytes']
    return _digest(result)
