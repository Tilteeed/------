"""Per-instance, fail-closed egress policy for direct native Ollama calls.

This policy permits only the managed Gateway address to reach one configured
RFC1918 Ollama address on TCP/11434. It is an L3/L4 restriction; it cannot
constrain HTTP paths or the model name in a request body.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Protocol

from .firewall_acceptance import (
    MAX_RECEIPT_BYTES, _POSIX_O_NOFOLLOW, _open_state_directory,
    _reject_json_constant, _strict_object, machine_id_sha256,
    validate_firewall_network_pools,
)

OLLAMA_PORT = 11434
TABLE_NAME = 'agent_ollama_v1'
TABLE_COMMENT = 'BEZR managed firewall agent_ollama_v1 v1'
OLLAMA_ROUTE_RECEIPT_FILENAME = 'ollama-route-acceptance.json'
OLLAMA_FIREWALL_POLICY_VERSION = 1
OLLAMA_ROUTE_REQUIRED_CHECKS = (
    'linux_ollama_route_check', 'linux_docker_ollama_route_acceptance')
INET_PRIORITY = -20
BRIDGE_PRIORITY = -220
MAX_POLICIES = 512
_MAX_RULESET_BYTES = 1_048_576
_PRIVATE = tuple(ipaddress.IPv4Network(value) for value in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
_INSTANCE = re.compile(r'[0-9a-f]{32}\Z')
_INTERFACE = re.compile(r'[A-Za-z0-9_.:-]{1,15}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_RECEIPT_KEYS = {
    'schema_version', 'host_id_sha256', 'policy_version',
    'agent_network_pool', 'frontend_network_pool', 'ollama_network_pool',
    'ollama_endpoint_ip', 'egress_interface', 'checks', 'accepted_at_unix',
}


class OllamaFirewallError(RuntimeError):
    """Safe fixed-message egress firewall policy failure."""


@dataclass(frozen=True, order=True)
class OllamaRoutePolicy:
    """One Gateway-only Docker bridge and its exact Ollama TCP destination."""
    instance_id: str
    subnet: str
    gateway: str
    gateway_ip: str
    ollama_ip: str
    egress_interface: str

    def __post_init__(self):
        if type(self.instance_id) is not str or _INSTANCE.fullmatch(self.instance_id) is None:
            raise ValueError('Invalid instance ID')
        try:
            network = ipaddress.IPv4Network(self.subnet, strict=True)
            gateway = ipaddress.IPv4Address(self.gateway)
            gateway_ip = ipaddress.IPv4Address(self.gateway_ip)
            ollama_ip = ipaddress.IPv4Address(self.ollama_ip)
        except (TypeError, ValueError):
            raise ValueError('Invalid Ollama route address') from None
        if (network.prefixlen != 29 or not any(network.subnet_of(pool) for pool in _PRIVATE)
                or gateway != network.network_address + 1
                or gateway_ip != network.network_address + 2
                or gateway_ip not in network or ollama_ip in network
                or not any(ollama_ip in pool for pool in _PRIVATE)
                or gateway == ollama_ip or gateway_ip == ollama_ip
                or str(network) != self.subnet or str(gateway) != self.gateway
                or str(gateway_ip) != self.gateway_ip or str(ollama_ip) != self.ollama_ip):
            raise ValueError('Invalid Ollama route network identity')
        if (type(self.egress_interface) is not str
                or _INTERFACE.fullmatch(self.egress_interface) is None):
            raise ValueError('Invalid Ollama egress interface')

    @property
    def network_name(self):
        return 'pa-ollama-' + self.instance_id

    @property
    def bridge(self):
        return 'bzo' + self.instance_id[:12]


def validate_ollama_route_inputs(pool_value, egress_interface, endpoint_ip, *, protected_pools=()):
    """Validate explicit site IPAM/interface inputs without selecting host defaults."""
    if type(pool_value) is not str or type(egress_interface) is not str:
        raise ValueError('Explicit Ollama network pool and egress interface are required')
    try:
        pool = ipaddress.IPv4Network(pool_value, strict=True)
        endpoint = ipaddress.IPv4Address(endpoint_ip)
    except (TypeError, ValueError):
        raise ValueError('Invalid Ollama network or endpoint address') from None
    if (str(pool) != pool_value or pool.prefixlen > 24
            or not any(pool.subnet_of(private) for private in _PRIVATE)
            or endpoint.version != 4 or str(endpoint) != endpoint_ip
            or not any(endpoint in private for private in _PRIVATE)
            or endpoint in pool
            or _INTERFACE.fullmatch(egress_interface) is None):
        raise ValueError('Invalid Ollama egress route settings')
    if type(protected_pools) is not tuple or len(protected_pools) > 16:
        raise ValueError('Invalid protected network pool inventory')
    for value in protected_pools:
        try:
            other = ipaddress.IPv4Network(value, strict=True)
        except (TypeError, ValueError):
            raise ValueError('Invalid protected network pool inventory') from None
        if (str(other) != value or not any(other.subnet_of(private) for private in _PRIVATE)
                or other.overlaps(pool) or endpoint in other):
            raise ValueError('Ollama route must be disjoint from protected network pools')
    return str(pool), egress_interface


def build_ollama_route_receipt(host_id_sha256, agent_pool, frontend_pool,
                               ollama_network_pool, endpoint_ip, egress_interface,
                               *, accepted_at_unix=None):
    """Build an exact host-bound receipt after route-specific Linux/Docker checks pass."""
    if type(host_id_sha256) is not str or _DIGEST.fullmatch(host_id_sha256) is None:
        raise ValueError('Invalid host fingerprint')
    agent_pool, frontend_pool = validate_firewall_network_pools(agent_pool, frontend_pool)
    ollama_network_pool, egress_interface = validate_ollama_route_inputs(
        ollama_network_pool, egress_interface, endpoint_ip,
        protected_pools=(agent_pool, frontend_pool))
    accepted_at_unix = int(time.time()) if accepted_at_unix is None else accepted_at_unix
    if type(accepted_at_unix) is not int or accepted_at_unix <= 0:
        raise ValueError('Invalid route acceptance time')
    return {
        'schema_version': 1,
        'host_id_sha256': host_id_sha256,
        'policy_version': OLLAMA_FIREWALL_POLICY_VERSION,
        'agent_network_pool': agent_pool,
        'frontend_network_pool': frontend_pool,
        'ollama_network_pool': ollama_network_pool,
        'ollama_endpoint_ip': endpoint_ip,
        'egress_interface': egress_interface,
        'checks': list(OLLAMA_ROUTE_REQUIRED_CHECKS),
        'accepted_at_unix': accepted_at_unix,
    }


def ollama_route_receipt_matches(receipt, host_id_sha256, agent_pool, frontend_pool,
                                 ollama_network_pool, endpoint_ip, egress_interface):
    """Bind route readiness to this host, tested endpoint/interface and all IPAM pools."""
    try:
        if type(receipt) is not dict or set(receipt) != _RECEIPT_KEYS:
            return False
        if (type(receipt.get('schema_version')) is not int or receipt['schema_version'] != 1
                or type(receipt.get('policy_version')) is not int
                or receipt['policy_version'] != OLLAMA_FIREWALL_POLICY_VERSION
                or type(receipt.get('accepted_at_unix')) is not int
                or receipt['accepted_at_unix'] <= 0
                or type(receipt.get('checks')) is not list
                or receipt['checks'] != list(OLLAMA_ROUTE_REQUIRED_CHECKS)):
            return False
        expected = build_ollama_route_receipt(
            host_id_sha256, agent_pool, frontend_pool, ollama_network_pool,
            endpoint_ip, egress_interface,
            accepted_at_unix=receipt['accepted_at_unix'])
        return receipt == expected
    except (KeyError, TypeError, ValueError):
        return False


def _read_route_receipt(directory_fd):
    flags = os.O_RDONLY | _POSIX_O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    descriptor = os.open(OLLAMA_ROUTE_RECEIPT_FILENAME, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > MAX_RECEIPT_BYTES):
            raise ValueError('Unsafe Ollama route receipt')
        blob = os.read(descriptor, MAX_RECEIPT_BYTES + 1)
        if len(blob) != info.st_size or len(blob) > MAX_RECEIPT_BYTES:
            raise ValueError('Invalid Ollama route receipt size')
    finally:
        os.close(descriptor)
    return json.loads(blob.decode('utf-8'), object_pairs_hook=_strict_object,
                      parse_constant=_reject_json_constant)


def load_ollama_route_receipt(state_dir, agent_pool, frontend_pool,
                              ollama_network_pool, endpoint_ip, egress_interface,
                              *, machine_id_path='/etc/machine-id'):
    """Return true only for a root-owned receipt matching current host and route config."""
    directory_fd = None
    try:
        host_digest = machine_id_sha256(machine_id_path)
        directory_fd = _open_state_directory(state_dir)
        receipt = _read_route_receipt(directory_fd)
        return ollama_route_receipt_matches(
            receipt, host_digest, agent_pool, frontend_pool,
            ollama_network_pool, endpoint_ip, egress_interface)
    except (OSError, RuntimeError, UnicodeDecodeError, ValueError, TypeError,
            json.JSONDecodeError):
        return False
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def write_ollama_route_receipt(state_dir, agent_pool, frontend_pool,
                               ollama_network_pool, endpoint_ip, egress_interface,
                               *, machine_id_path='/etc/machine-id',
                               expected_host_id_sha256=None):
    """Atomically record the route receipt; callers must run both acceptance checks first."""
    host_digest = machine_id_sha256(machine_id_path)
    if expected_host_id_sha256 is not None and host_digest != expected_host_id_sha256:
        raise ValueError('Host identity changed during route acceptance')
    receipt = build_ollama_route_receipt(
        host_digest, agent_pool, frontend_pool, ollama_network_pool,
        endpoint_ip, egress_interface)
    payload = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    directory_fd = _open_state_directory(state_dir, create=True)
    temporary = '.ollama-route-acceptance-' + secrets.token_hex(8) + '.tmp'
    file_fd = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _POSIX_O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
        file_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        fchown = getattr(os, 'fchown', None)
        fchmod = getattr(os, 'fchmod', None)
        if not callable(fchown) or not callable(fchmod):
            raise ValueError('Safe Ollama route receipt ownership is unavailable')
        fchown(file_fd, 0, 0)
        fchmod(file_fd, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(file_fd, payload[offset:])
            if written <= 0:
                raise OSError('short route receipt write')
            offset += written
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        os.replace(temporary, OLLAMA_ROUTE_RECEIPT_FILENAME,
                   src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
    return receipt


def validate_ollama_routes(routes):
    """Require unique, disjoint per-instance route bridges and subnets."""
    result = tuple(routes)
    if not result or any(not isinstance(item, OllamaRoutePolicy) for item in result):
        raise ValueError('Explicit Ollama route policies are required')
    if len(result) > MAX_POLICIES:
        raise ValueError('Ollama route policy exceeds the bounded ruleset limit')
    if len({item.instance_id for item in result}) != len(result):
        raise ValueError('Duplicate Ollama route instance')
    if len({item.bridge for item in result}) != len(result):
        raise ValueError('Duplicate Ollama route bridge')
    networks = [ipaddress.IPv4Network(item.subnet) for item in result]
    if any(left.overlaps(right) for index, left in enumerate(networks)
           for right in networks[index + 1:]):
        raise ValueError('Ollama route networks overlap')
    return tuple(sorted(result, key=lambda item: item.instance_id))


def _match(left, right):
    return {'match': {'left': left, 'op': '==', 'right': right}}


def _meta(key):
    return {'meta': {'key': key}}


def _ip(field):
    return {'payload': {'protocol': 'ip', 'field': field}}


def _tcp(field):
    return {'payload': {'protocol': 'tcp', 'field': field}}


def _ct(key):
    return {'ct': {'key': key}}


def _rule(family, chain, matches, verdict, comment):
    return {'family': family, 'table': TABLE_NAME, 'chain': chain,
            'expr': [*matches, {verdict: None}], 'comment': comment}


def expected_ollama_ruleset(routes):
    """Return canonical nft manifest; every allow precedes its subnet/interface drops."""
    policies = validate_ollama_routes(routes)
    tables = {}
    for family, hooks, priority in (
        ('inet', ('input', 'output', 'forward'), INET_PRIORITY),
        ('bridge', ('input', 'output', 'forward'), BRIDGE_PRIORITY),
    ):
        chains = sorted(({
            'family': family, 'table': TABLE_NAME, 'name': hook,
            'type': 'filter', 'hook': hook, 'prio': priority,
            'policy': 'accept',
            'comment': f'BEZR agent_ollama_v1 {family} {hook} v1',
        } for hook in hooks), key=lambda item: item['name'])
        rules = []
        if family == 'inet':
            for item in policies:
                comment = f'BEZR {item.instance_id} ollama'
                # Host-local Ollama endpoint (input/output); exact target and port only.
                rules.append(_rule(family, 'input', [
                    _match(_meta('iifname'), item.bridge),
                    _match(_ip('saddr'), item.gateway_ip),
                    _match(_ip('daddr'), item.ollama_ip),
                    _match(_tcp('dport'), OLLAMA_PORT),
                ], 'accept', comment + ' host request'))
                rules.append(_rule(family, 'output', [
                    _match(_meta('oifname'), item.bridge),
                    _match(_ip('saddr'), item.ollama_ip),
                    _match(_ip('daddr'), item.gateway_ip),
                    _match(_tcp('sport'), OLLAMA_PORT),
                    _match(_ct('state'), 'established'),
                ], 'accept', comment + ' host established return'))
                # Routed endpoint: only the selected Gateway IP, route interface,
                # Ollama IP and TCP service port; replies must be established.
                rules.append(_rule(family, 'forward', [
                    _match(_meta('iifname'), item.bridge),
                    _match(_meta('oifname'), item.egress_interface),
                    _match(_ip('saddr'), item.gateway_ip),
                    _match(_ip('daddr'), item.ollama_ip),
                    _match(_tcp('dport'), OLLAMA_PORT),
                ], 'accept', comment + ' outbound'))
                rules.append(_rule(family, 'forward', [
                    _match(_meta('iifname'), item.egress_interface),
                    _match(_meta('oifname'), item.bridge),
                    _match(_ip('saddr'), item.ollama_ip),
                    _match(_ip('daddr'), item.gateway_ip),
                    _match(_tcp('sport'), OLLAMA_PORT),
                    _match(_ct('state'), 'established'),
                ], 'accept', comment + ' established return'))
            for item in policies:
                subnet = item.subnet
                for chain in ('input', 'output'):
                    for field, direction in (('saddr', 'source'), ('daddr', 'destination')):
                        rules.append(_rule(family, chain, [
                            _match(_ip(field), subnet)], 'drop',
                            f'BEZR {item.instance_id} ollama {chain} {direction} deny'))
                for side, direction in (('iifname', 'ingress'), ('oifname', 'egress')):
                    rules.append(_rule(family, 'forward', [
                        _match(_meta(side), item.bridge)], 'drop',
                        f'BEZR {item.instance_id} ollama forward {direction} deny'))
                for field, direction in (('saddr', 'source'), ('daddr', 'destination')):
                    rules.append(_rule(family, 'forward', [
                        _match(_ip(field), subnet)], 'drop',
                        f'BEZR {item.instance_id} ollama forward {direction} deny'))
        else:
            for item in policies:
                comment = f'BEZR {item.instance_id} ollama'
                rules.append(_rule(family, 'input', [
                    _match(_meta('ibrname'), item.bridge),
                    _match(_ip('saddr'), item.gateway_ip),
                    _match(_ip('daddr'), item.ollama_ip),
                    _match(_tcp('dport'), OLLAMA_PORT),
                ], 'accept', comment + ' bridge input request'))
                rules.append(_rule(family, 'output', [
                    _match(_meta('obrname'), item.bridge),
                    _match(_ip('saddr'), item.ollama_ip),
                    _match(_ip('daddr'), item.gateway_ip),
                    _match(_tcp('sport'), OLLAMA_PORT),
                    _match(_ct('state'), 'established'),
                ], 'accept', comment + ' bridge output return'))
            for item in policies:
                rules.append(_rule(family, 'input', [
                    _match(_meta('ibrname'), item.bridge)], 'drop',
                    f'BEZR {item.instance_id} ollama bridge input deny'))
                rules.append(_rule(family, 'output', [
                    _match(_meta('obrname'), item.bridge)], 'drop',
                    f'BEZR {item.instance_id} ollama bridge egress deny'))
                for side, direction in (('ibrname', 'ingress'), ('obrname', 'egress')):
                    rules.append(_rule(family, 'forward', [
                        _match(_meta(side), item.bridge)], 'drop',
                        f'BEZR {item.instance_id} ollama bridge forward {direction} deny'))
        tables[family] = {
            'table': {'family': family, 'name': TABLE_NAME, 'comment': TABLE_COMMENT},
            'chains': chains,
            'rules': rules,
        }
    return {'tables': tables, 'semantics_validated': False}


class RulesetAdapter(Protocol):
    def read(self) -> object: ...
    def replace(self, ruleset: object) -> None: ...
    def remove(self) -> None: ...


class OllamaFirewallManager:
    """Receipt-gated manager for the separate Ollama egress table."""
    def __init__(self, adapter: RulesetAdapter, *, semantics_validated=False):
        self.adapter = adapter
        self.semantics_validated = semantics_validated is True

    @property
    def can_apply(self):
        return self.semantics_validated

    def ready(self, routes):
        if not self.semantics_validated:
            return False
        try:
            policies = tuple(routes)
            if not policies:
                return self.adapter.read() is None
            return self.adapter.read() == expected_ollama_ruleset(policies)
        except Exception:
            return False

    def apply(self, routes):
        if not self.semantics_validated:
            raise OllamaFirewallError('Ollama firewall semantics are not validated')
        policies = tuple(routes)
        if not policies:
            self.adapter.remove()
            if self.adapter.read() is not None:
                raise OllamaFirewallError('Ollama firewall cleanup read-back failed')
            return None
        desired = expected_ollama_ruleset(policies)
        try:
            self.adapter.replace(desired)
            if self.adapter.read() != desired:
                raise OllamaFirewallError('Ollama firewall read-back verification failed')
        except OllamaFirewallError:
            raise
        except Exception:
            raise OllamaFirewallError('Ollama firewall update failed') from None
        return desired
