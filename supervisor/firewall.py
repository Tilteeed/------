"""Fail-closed policy model for agent_proxy_v1.

This module never invokes nft or changes host state. A deployment must supply
site-specific, non-overlapping /29 pools and an adapter implementing the
read/replace/read-back contract below. Until nft JSON semantics are validated
on the target, readiness deliberately remains false.
"""
from dataclasses import dataclass
import ipaddress
import json
import os
import re
import subprocess
from typing import Callable, Protocol

from .probes import run_command

TABLE_NAME = 'agent_proxy_v1'
PROFILE = 'agent_proxy_v1'
TABLE_COMMENT = 'BEZR managed firewall agent_proxy_v1 v1'
NFTABLES_SEMANTICS_VALIDATED = False
INET_PRIORITY = -10
BRIDGE_PRIORITY = -210
MAX_POLICIES = 512
MAX_RULESET_BYTES = 1_048_576
_BRIDGE = re.compile(r'bza[0-9a-f]{12}\Z')
_FWBRIDGE = re.compile(r'bzf[0-9a-f]{12}\Z')
_INSTANCE = re.compile(r'[0-9a-f]{32}\Z')


class FirewallError(RuntimeError):
    """Safe fixed-message firewall policy error."""


@dataclass(frozen=True, order=True)
class EndpointPair:
    """Allowed IPv4 endpoints; direction is bidirectional for this pair only."""
    left: str
    right: str

    def __post_init__(self):
        left, right = _ipv4(self.left), _ipv4(self.right)
        if left == right:
            raise ValueError('Endpoint pair must contain distinct addresses')
        object.__setattr__(self, 'left', left)
        object.__setattr__(self, 'right', right)


@dataclass(frozen=True)
class NetworkPolicy:
    instance_id: str
    agent_subnet: str
    frontend_subnet: str
    agent_bridge: str
    frontend_bridge: str
    agent_pair: EndpointPair
    frontend_pair: EndpointPair

    def __post_init__(self):
        if not isinstance(self.instance_id, str) or not re.fullmatch(r'[0-9a-f]{32}', self.instance_id):
            raise ValueError('Invalid instance ID')
        networks = []
        for value in (self.agent_subnet, self.frontend_subnet):
            try:
                network = ipaddress.ip_network(value, strict=True)
            except (ValueError, TypeError):
                raise ValueError('Each isolated network must be an IPv4 /29') from None
            if network.version != 4 or network.prefixlen != 29:
                raise ValueError('Each isolated network must be an IPv4 /29')
            networks.append(network)
        if networks[0].overlaps(networks[1]):
            raise ValueError('Agent and frontend networks must not overlap')
        if self.agent_bridge != 'bza' + self.instance_id[:12] or not _BRIDGE.fullmatch(self.agent_bridge):
            raise ValueError('Invalid agent bridge name')
        if self.frontend_bridge != 'bzf' + self.instance_id[:12] or not _FWBRIDGE.fullmatch(self.frontend_bridge):
            raise ValueError('Invalid frontend bridge name')
        for network, pair in zip(networks, (self.agent_pair, self.frontend_pair)):
            if not isinstance(pair, EndpointPair):
                raise ValueError('Invalid endpoint pair')
            expected = {str(network.network_address + 2), str(network.network_address + 3)}
            if {pair.left, pair.right} != expected:
                raise ValueError('Endpoint pair does not match the fixed per-role addresses')


def _ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise ValueError('Endpoint must be IPv4') from None
    if address.version != 4:
        raise ValueError('Endpoint must be IPv4')
    return str(address)


def validate_networks(networks):
    """Require explicit, unique per-instance pairs with globally disjoint /29s."""
    result = tuple(networks)
    if not result or any(not isinstance(item, NetworkPolicy) for item in result):
        raise ValueError('Explicit network policies are required')
    if len(result) > MAX_POLICIES:
        raise ValueError('Proxy policy exceeds the bounded ruleset limit')
    if len({n.instance_id for n in result}) != len(result):
        raise ValueError('Duplicate instance network')
    bridges = [bridge for item in result
               for bridge in (item.agent_bridge, item.frontend_bridge)]
    if len(set(bridges)) != len(bridges):
        raise ValueError('Duplicate bridge')
    subnets = [ipaddress.IPv4Network(subnet) for item in result
               for subnet in (item.agent_subnet, item.frontend_subnet)]
    if any(left.overlaps(right) for index, left in enumerate(subnets)
           for right in subnets[index + 1:]):
        raise ValueError('Network allocations overlap')
    return tuple(sorted(result, key=lambda item: item.instance_id))


def _match(left, right):
    return {'match': {'left': left, 'op': '==', 'right': right}}


def _meta(key):
    return {'meta': {'key': key}}


def _payload(protocol, field):
    return {'payload': {'protocol': protocol, 'field': field}}


def _policy_rule(family, chain, matches, verdict, comment):
    return {'family': family, 'table': TABLE_NAME, 'chain': chain,
            'expr': [*matches, {verdict: None}], 'comment': comment}


def expected_ruleset(networks):
    """Return the canonical ruleset manifest mirrored by nft JSON read-back."""
    policies = validate_networks(networks)
    tables = {}
    for family, hooks, priority in (
        ('inet', ('input', 'output', 'forward'), INET_PRIORITY),
        ('bridge', ('input', 'output', 'forward'), BRIDGE_PRIORITY),
    ):
        chains = sorted(({
            'family': family, 'table': TABLE_NAME, 'name': hook,
            'type': 'filter', 'hook': hook, 'prio': priority,
            'policy': 'accept', 'comment': f'BEZR {PROFILE} {family} {hook} v1',
        } for hook in hooks), key=lambda item: item['name'])
        rules = []
        if family == 'inet':
            for policy in policies:
                for role, subnet in (('agent', policy.agent_subnet),
                                     ('frontend', policy.frontend_subnet)):
                    for field, direction in (('saddr', 'source'), ('daddr', 'destination')):
                        rules.append(_policy_rule(family, 'input', [
                            _match(_payload('ip', field), subnet)], 'drop',
                            f'BEZR {policy.instance_id} input {role} {direction}'))
                        rules.append(_policy_rule(family, 'output', [
                            _match(_payload('ip', field), subnet)], 'drop',
                            f'BEZR {policy.instance_id} output {role} {direction}'))
            for policy in policies:
                for role, bridge, pair in (
                    ('agent', policy.agent_bridge, policy.agent_pair),
                    ('frontend', policy.frontend_bridge, policy.frontend_pair),
                ):
                    for source, destination in ((pair.left, pair.right), (pair.right, pair.left)):
                        rules.append(_policy_rule(family, 'forward', [
                            _match(_meta('iifname'), bridge),
                            _match(_meta('oifname'), bridge),
                            _match(_payload('ip', 'saddr'), source),
                            _match(_payload('ip', 'daddr'), destination),
                        ], 'accept', f'BEZR {policy.instance_id} routed {role} {source}>{destination}'))
            for policy in policies:
                for role, subnet in (('agent', policy.agent_subnet),
                                     ('frontend', policy.frontend_subnet)):
                    for field, direction in (('saddr', 'source'), ('daddr', 'destination')):
                        rules.append(_policy_rule(family, 'forward', [
                            _match(_payload('ip', field), subnet)], 'drop',
                            f'BEZR {policy.instance_id} routed {role} {direction}'))
        else:
            for policy in policies:
                for role, bridge in (('agent', policy.agent_bridge),
                                     ('frontend', policy.frontend_bridge)):
                    rules.append(_policy_rule(family, 'input', [
                        _match(_meta('ibrname'), bridge)], 'drop',
                        f'BEZR {policy.instance_id} bridge-host input {role}'))
                    rules.append(_policy_rule(family, 'output', [
                        _match(_meta('obrname'), bridge)], 'drop',
                        f'BEZR {policy.instance_id} bridge-host output {role}'))
                    # ARP peer discovery is required for static IPv4 endpoints.
                    rules.append(_policy_rule(family, 'forward', [
                        _match(_meta('ibrname'), bridge),
                        _match(_meta('obrname'), bridge),
                        _match(_payload('ether', 'type'), 'arp'),
                    ], 'accept', f'BEZR {policy.instance_id} same-bridge arp {role}'))
                for role, bridge, pair in (
                    ('agent', policy.agent_bridge, policy.agent_pair),
                    ('frontend', policy.frontend_bridge, policy.frontend_pair),
                ):
                    for source, destination in ((pair.left, pair.right), (pair.right, pair.left)):
                        rules.append(_policy_rule(family, 'forward', [
                            _match(_meta('ibrname'), bridge),
                            _match(_meta('obrname'), bridge),
                            _match(_payload('ip', 'saddr'), source),
                            _match(_payload('ip', 'daddr'), destination),
                        ], 'accept', f'BEZR {policy.instance_id} bridge {role} {source}>{destination}'))
                for role, bridge in (('agent', policy.agent_bridge),
                                     ('frontend', policy.frontend_bridge)):
                    rules.append(_policy_rule(family, 'forward', [
                        _match(_meta('ibrname'), bridge)], 'drop',
                        f'BEZR {policy.instance_id} bridge ingress {role}'))
                    rules.append(_policy_rule(family, 'forward', [
                        _match(_meta('obrname'), bridge)], 'drop',
                        f'BEZR {policy.instance_id} bridge egress {role}'))
        rules.sort(key=lambda item: item['chain'])
        tables[family] = {
            'table': {'family': family, 'name': TABLE_NAME, 'comment': TABLE_COMMENT},
            'chains': chains, 'rules': rules,
        }
    return {'tables': tables, 'semantics_validated': False}


class RulesetAdapter(Protocol):
    """Adapter talks to an external ruleset store; writes are always verified."""
    def read(self) -> object: ...
    def replace(self, ruleset: object) -> None: ...
    def remove(self) -> None: ...


class NftablesAdapter:
    """Atomic, table-scoped nft CLI adapter with exact JSON read-back."""
    def __init__(self, *, nft_binary='nft', runner: Callable | None = None,
                 batch_runner: Callable | None = None):
        if type(nft_binary) is not str or not nft_binary or len(nft_binary) > 256:
            raise ValueError('Invalid nft executable')
        self.nft_binary = nft_binary
        self.runner = runner or run_command
        self.batch_runner = batch_runner or self._run_batch

    def _read_text(self, argv):
        try:
            output = self.runner(list(argv))
            if type(output) is bytes:
                output = output.decode('utf-8')
            if type(output) is not str or len(output.encode('utf-8')) > 65536:
                raise ValueError
            return output
        except Exception:
            raise FirewallError('nftables read failed') from None

    def _family_table(self, family):
        text = self._read_text((self.nft_binary, '-a', '-j', 'list', 'tables', family))
        try:
            items = json.loads(text)['nftables']
            if type(items) is not list or len(items) > 4096:
                raise ValueError
            found = [item['table'] for item in items if type(item) is dict
                     and type(item.get('table')) is dict
                     and item['table'].get('family') == family
                     and item['table'].get('name') == TABLE_NAME]
            if len(found) > 1:
                raise ValueError
            if not found:
                return None
            listed_handle = found[0].get('handle')
            if type(listed_handle) is not int or listed_handle <= 0:
                raise ValueError
            detail = self._read_text((self.nft_binary, '-a', '-j', 'list', 'table', family, TABLE_NAME))
            manifest, handle = self._normalise_table(detail, family)
            if handle != listed_handle:
                raise ValueError
            return {'handle': handle, 'manifest': manifest}
        except FirewallError:
            raise
        except Exception:
            raise FirewallError('nftables table inventory is invalid') from None

    @staticmethod
    def _without_handle(value):
        return {key: item for key, item in value.items() if key not in {'handle', 'index'}}

    @staticmethod
    def _normalise_prefix(right):
        if type(right) is not dict or set(right) != {'prefix'}:
            raise ValueError
        prefix = right['prefix']
        if type(prefix) is not dict or set(prefix) != {'addr', 'len'}:
            raise ValueError
        address, prefixlen = prefix['addr'], prefix['len']
        if (type(address) is not str or type(prefixlen) is not int
                or not 0 <= prefixlen <= 32):
            raise ValueError
        network = ipaddress.IPv4Network(f'{address}/{prefixlen}', strict=True)
        if str(network.network_address) != address:
            raise ValueError
        return str(network)

    @classmethod
    def _normalise_rule(cls, rule):
        if type(rule) is not dict or type(rule.get('expr')) is not list:
            return rule
        address_lvalues = (
            {'payload': {'protocol': 'ip', 'field': 'saddr'}},
            {'payload': {'protocol': 'ip', 'field': 'daddr'}},
        )
        for expression in rule['expr']:
            if type(expression) is not dict or set(expression) != {'match'}:
                continue
            match = expression['match']
            if (type(match) is not dict or set(match) != {'left', 'op', 'right'}
                    or match['left'] not in address_lvalues):
                continue
            right = match['right']
            if type(right) is dict and 'prefix' in right:
                match['right'] = cls._normalise_prefix(right)
        return rule

    def _normalise_table(self, text, family):
        try:
            items = json.loads(text)['nftables']
            if type(items) is not list or len(items) > 65536:
                raise ValueError
            table, handle, chains, rules = None, None, [], []
            for item in items:
                if type(item) is not dict or len(item) != 1:
                    continue
                kind, value = next(iter(item.items()))
                if kind == 'metainfo':
                    continue
                if type(value) is not dict:
                    raise ValueError
                if kind == 'table' and value.get('family') == family and value.get('name') == TABLE_NAME:
                    if table is not None:
                        raise ValueError
                    handle, table = value.get('handle'), self._without_handle(value)
                elif value.get('family') == family and value.get('table') == TABLE_NAME:
                    if kind == 'chain':
                        chains.append(self._without_handle(value))
                    elif kind == 'rule':
                        rules.append(self._normalise_rule(self._without_handle(value)))
                    else:
                        raise ValueError
            if type(handle) is not int or handle <= 0 or table is None:
                raise ValueError
            manifest = {'tables': {family: {
                'table': table, 'chains': sorted(chains, key=lambda item: item.get('name', '')),
                'rules': sorted(rules, key=lambda item: item.get('chain', '')),
            }}, 'semantics_validated': False}
            return manifest, handle
        except Exception:
            raise FirewallError('nftables ruleset read-back is invalid') from None

    def read(self):
        tables = {}
        for family in ('inet', 'bridge'):
            current = self._family_table(family)
            if current is not None:
                tables[family] = current['manifest']['tables'][family]
        return {'tables': tables, 'semantics_validated': False} if tables else None

    @staticmethod
    def _render_lvalue(value):
        if type(value) is not dict or len(value) != 1:
            raise ValueError
        key, item = next(iter(value.items()))
        if key == 'meta' and type(item) is dict and set(item) == {'key'}:
            if item['key'] not in {'iifname', 'oifname', 'ibrname', 'obrname'}:
                raise ValueError
            return 'meta ' + item['key']
        if key == 'payload' and type(item) is dict and set(item) == {'protocol', 'field'}:
            if item['protocol'] == 'ip' and item['field'] in {'saddr', 'daddr'}:
                return 'ip ' + item['field']
            if item['protocol'] == 'ether' and item['field'] == 'type':
                return 'ether type'
        raise ValueError

    @classmethod
    def _render_expr(cls, expression):
        if type(expression) is not dict or len(expression) != 1:
            raise ValueError
        key, value = next(iter(expression.items()))
        if key == 'match' and type(value) is dict and set(value) == {'left', 'op', 'right'}:
            right = value['right']
            if value['op'] != '==' or type(right) is not str:
                raise ValueError
            if right != 'arp':
                try:
                    if str(ipaddress.IPv4Network(right, strict=True)) != right:
                        raise ValueError
                except (TypeError, ValueError):
                    try:
                        if str(ipaddress.IPv4Address(right)) != right:
                            raise ValueError
                    except (TypeError, ValueError):
                        if re.fullmatch(r'bz[af][0-9a-f]{12}', right) is None:
                            raise ValueError
            return f'{cls._render_lvalue(value["left"])} == {right}'
        if key in {'accept', 'drop'} and value is None:
            return key
        raise ValueError

    @classmethod
    def _render_batch(cls, ruleset, inventory):
        lines = []
        for family in ('inet', 'bridge'):
            old = inventory.get(family)
            if old is not None:
                lines.append(f'delete table {family} handle {old["handle"]}')
            table = ruleset['tables'][family]
            if table['table'] != {'family': family, 'name': TABLE_NAME, 'comment': TABLE_COMMENT}:
                raise ValueError
            lines.append(f'create table {family} {TABLE_NAME} {{ comment "{TABLE_COMMENT}"; }}')
            for chain in table['chains']:
                if (chain.get('family') != family or chain.get('table') != TABLE_NAME
                        or chain.get('type') != 'filter' or chain.get('policy') != 'accept'
                        or chain.get('hook') != chain.get('name')
                        or chain.get('name') not in {'input', 'output', 'forward'}
                        or type(chain.get('prio')) is not int
                        or re.fullmatch(r'BEZR [A-Za-z0-9 _-]+', chain.get('comment', '')) is None):
                    raise ValueError
                lines.append(f'add chain {family} {TABLE_NAME} {chain["name"]} {{ '
                             f'type filter hook {chain["hook"]} priority {chain["prio"]}; '
                             f'policy accept; comment "{chain["comment"]}"; }}')
            for rule in table['rules']:
                if (rule.get('family') != family or rule.get('table') != TABLE_NAME
                        or rule.get('chain') not in {'input', 'output', 'forward'}
                        or re.fullmatch(r'BEZR [A-Za-z0-9 .:>_-]+', rule.get('comment', '')) is None
                        or type(rule.get('expr')) is not list or not rule['expr']):
                    raise ValueError
                expr = ' '.join(cls._render_expr(item) for item in rule['expr'])
                lines.append(f'add rule {family} {TABLE_NAME} {rule["chain"]} {expr} '
                             f'comment "{rule["comment"]}"')
        batch = '\n'.join(lines) + '\n'
        if len(batch.encode('utf-8')) > MAX_RULESET_BYTES:
            raise ValueError
        return batch

    def replace(self, ruleset):
        try:
            if (type(ruleset) is not dict or set(ruleset) != {'tables', 'semantics_validated'}
                    or ruleset.get('semantics_validated') is not False
                    or type(ruleset.get('tables')) is not dict
                    or set(ruleset['tables']) != {'inet', 'bridge'}):
                raise ValueError
            inventory = {family: self._family_table(family) for family in ('inet', 'bridge')}
            for family, old in inventory.items():
                if old is not None:
                    table = old['manifest']['tables'][family]['table']
                    if table.get('comment') != TABLE_COMMENT:
                        raise FirewallError('Refusing to replace an unowned nftables table')
            self.batch_runner([self.nft_binary, '-f', '-'], self._render_batch(ruleset, inventory))
        except FirewallError:
            raise
        except Exception:
            raise FirewallError('nftables batch preparation failed') from None

    def remove(self):
        inventory = {family: self._family_table(family) for family in ('inet', 'bridge')}
        lines = []
        for family, old in inventory.items():
            if old is None:
                continue
            table = old['manifest']['tables'][family]['table']
            if table.get('comment') != TABLE_COMMENT:
                raise FirewallError('Refusing to remove an unowned nftables table')
            lines.append(f'delete table {family} handle {old["handle"]}')
        if lines:
            self.batch_runner([self.nft_binary, '-f', '-'], '\n'.join(lines) + '\n')

    @staticmethod
    def _run_batch(argv, batch):
        if type(batch) is not str or len(batch.encode('utf-8')) > MAX_RULESET_BYTES:
            raise FirewallError('nftables batch exceeds the safety limit')
        process = None
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       shell=False, env={**os.environ, 'LC_ALL': 'C'})
            process.communicate(batch.encode('utf-8'), timeout=10)
        except subprocess.TimeoutExpired:
            if process is not None:
                process.kill()
                try:
                    process.communicate(timeout=1)
                except Exception:
                    pass
            raise FirewallError('nftables batch timed out') from None
        except OSError:
            raise FirewallError('nftables executable is unavailable') from None
        if process.returncode != 0:
            raise FirewallError('nftables rejected the managed ruleset')


class FirewallManager:
    def __init__(self, adapter: RulesetAdapter, *, semantics_validated=False):
        self.adapter = adapter
        # This is a code-level acceptance gate, not a user-editable config value.
        self.semantics_validated = semantics_validated is True

    @property
    def can_apply(self):
        return self.semantics_validated

    def ready(self, networks):
        if not self.semantics_validated:
            return False
        try:
            return self.adapter.read() == expected_ruleset(networks)
        except Exception:
            return False

    def _write_verified(self, desired):
        self.adapter.replace(desired)
        if self.adapter.read() != desired:
            raise FirewallError('Firewall ruleset read-back verification failed')

    def apply(self, networks):
        if not self.semantics_validated:
            raise FirewallError('nftables semantics are not validated')
        policies = validate_networks(networks) if networks else ()
        if not policies:
            self.adapter.remove()
            if self.adapter.read() is not None:
                raise FirewallError('Firewall cleanup read-back verification failed')
            return None
        desired = expected_ruleset(policies)
        self._write_verified(desired)
        return desired

    def register(self, network, current=()):
        if not isinstance(network, NetworkPolicy):
            raise ValueError('Invalid network policy')
        return self.apply((*tuple(current), network))

    def unregister(self, instance_id, current=()):
        if type(instance_id) is not str or _INSTANCE.fullmatch(instance_id) is None:
            raise ValueError('Invalid instance ID')
        return self.apply(tuple(item for item in current if item.instance_id != instance_id))
