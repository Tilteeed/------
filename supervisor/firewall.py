"""Fail-closed policy model for agent_proxy_v1.

This module never invokes nft or changes host state. A deployment must supply
site-specific, non-overlapping /29 pools and an adapter implementing the
read/replace/read-back contract below. Until nft JSON semantics are validated
on the target, readiness deliberately remains false.
"""
from dataclasses import dataclass
import ipaddress
import re
from typing import Protocol

TABLE_FAMILY = 'bridge'
TABLE_NAME = 'agent_proxy_v1'
PROFILE = 'agent_proxy_v1'
_BRIDGE = re.compile(r'bza[0-9a-f]{12}\Z')
_FWBRIDGE = re.compile(r'bzf[0-9a-f]{12}\Z')


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
    """Require explicit site allocations, unique bridges and disjoint /29s."""
    result = tuple(networks)
    if not result or any(not isinstance(item, NetworkPolicy) for item in result):
        raise ValueError('Explicit network policies are required')
    if len({n.instance_id for n in result}) != len(result):
        raise ValueError('Duplicate instance network')
    if len({b for n in result for b in (n.agent_bridge, n.frontend_bridge)}) != 2 * len(result):
        raise ValueError('Duplicate bridge')
    nets = [ipaddress.ip_network(subnet) for n in result
            for subnet in (n.agent_subnet, n.frontend_subnet)]
    if any(a.overlaps(b) for i, a in enumerate(nets) for b in nets[i + 1:]):
        raise ValueError('Network allocations overlap')
    return tuple(sorted(result, key=lambda n: n.instance_id))


def expected_ruleset(networks):
    """Canonical policy model; readiness stays disabled pending kernel validation."""
    networks = validate_networks(networks)
    subnets = sorted(subnet for n in networks
                     for subnet in (n.agent_subnet, n.frontend_subnet))
    endpoint_pairs = []
    bridge_endpoint_pairs = []
    bridge_subnet_pairs = []
    for network in networks:
        for bridge, pair in ((network.agent_bridge, network.agent_pair),
                             (network.frontend_bridge, network.frontend_pair)):
            for source, destination in ((pair.left, pair.right), (pair.right, pair.left)):
                endpoint_pairs.append([source, destination])
                bridge_endpoint_pairs.append([bridge, source, destination])
                bridge_subnet_pairs.append([bridge, bridge, source, destination])
    bridges = sorted(b for n in networks for b in (n.agent_bridge, n.frontend_bridge))
    inet = {
        'family': 'inet', 'name': TABLE_NAME,
        'sets': {'managed_subnets4': subnets,
                 'allowed_endpoint_pairs4': sorted(endpoint_pairs)},
        'chains': {
            'input': {'hook': 'input', 'priority': -10, 'policy': 'accept',
                      'rules': [{'match': 'source-in-managed-subnet', 'verdict': 'drop'}]},
            'output': {'hook': 'output', 'priority': -10, 'policy': 'accept',
                       'rules': [{'match': 'destination-in-managed-subnet', 'verdict': 'drop'}]},
            'forward': {'hook': 'forward', 'priority': -10, 'policy': 'accept',
                        'rules': [
                            {'match': 'exact-allowed-endpoint-pair', 'verdict': 'accept'},
                            {'match': 'source-in-managed-subnet', 'verdict': 'drop'},
                            {'match': 'destination-in-managed-subnet', 'verdict': 'drop'},
                        ]},
        },
    }
    bridge = {
        'family': 'bridge', 'name': TABLE_NAME,
        'sets': {'managed_bridges': bridges,
                 'allowed_bridge_endpoint_pairs': sorted(bridge_endpoint_pairs),
                 'allowed_bridge_subnet_pairs': sorted(bridge_subnet_pairs)},
        'chains': {
            'input': {'hook': 'input', 'priority': -10, 'policy': 'accept',
                      'rules': [{'match': 'input-bridge-managed', 'verdict': 'drop'}]},
            'output': {'hook': 'output', 'priority': -10, 'policy': 'accept',
                       'rules': [{'match': 'output-bridge-managed', 'verdict': 'drop'}]},
            'forward': {'hook': 'forward', 'priority': -10, 'policy': 'accept',
                        'rules': [
                            {'match': 'exact-endpoint-pair-on-same-managed-bridge', 'verdict': 'accept'},
                            {'match': 'input-bridge-managed', 'verdict': 'drop'},
                            {'match': 'output-bridge-managed', 'verdict': 'drop'},
                        ]},
        },
    }
    return {'tables': {'inet': inet, 'bridge': bridge},
            'semantics_validated': False}


class RulesetAdapter(Protocol):
    """Adapter talks to an external ruleset store; writes are always verified."""
    def read(self) -> object: ...
    def replace(self, ruleset: object) -> None: ...
    def remove(self) -> None: ...


class FirewallManager:
    def __init__(self, adapter: RulesetAdapter, *, semantics_validated=False):
        self.adapter = adapter
        # Keep gate off until exact target nft representation has been proven.
        self.semantics_validated = semantics_validated is True

    def ready(self, networks):
        try:
            expected = expected_ruleset(networks)
            observed = self.adapter.read()
            return self.semantics_validated and observed == expected
        except Exception:
            return False

    def _write_verified(self, desired):
        self.adapter.replace(desired)
        if self.adapter.read() != desired:
            raise FirewallError('Firewall ruleset read-back verification failed')

    def register(self, network, current=()):
        """Atomically publish one complete desired table and verify exact read-back."""
        if not isinstance(network, NetworkPolicy):
            raise ValueError('Invalid network policy')
        desired = expected_ruleset((*tuple(current), network))
        self._write_verified(desired)
        return desired

    def unregister(self, instance_id, current=()):
        if not isinstance(instance_id, str) or not re.fullmatch(r'[0-9a-f]{32}', instance_id):
            raise ValueError('Invalid instance ID')
        remaining = tuple(n for n in current if n.instance_id != instance_id)
        desired = expected_ruleset(remaining) if remaining else None
        if desired is None:
            self.adapter.remove()
            if self.adapter.read() is not None:
                raise FirewallError('Firewall cleanup read-back verification failed')
        else:
            self._write_verified(desired)
        return desired
