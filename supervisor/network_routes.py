"""Read-only, bounded IPv4 route and interface inventory for proxy IPAM."""
from dataclasses import dataclass
import ipaddress
import json

from .probes import ProbeFailure, run_command

MAX_NETWORKS = 4096
MAX_OUTPUT_BYTES = 65536
ROUTE_TIMEOUT_SECONDS = 5
_DEFAULT_DESTINATIONS = {'default', 'all', 'local', 'broadcast', 'multicast',
                         'unreachable', 'prohibit', 'blackhole', 'throw'}


class HostRouteInventoryError(RuntimeError):
    """Safe fixed-message failure while collecting host route inventory."""


def _interface_name(value):
    if (type(value) is not str or not 1 <= len(value) <= 255
            or any(ord(char) <= 32 or ord(char) == 127 for char in value)):
        raise ValueError
    return value


def _optional_text(value, *, allow_integer=False):
    if value is None:
        return None
    if type(value) is str and len(value) <= 64 and not any(
            ord(char) <= 32 or ord(char) == 127 for char in value):
        return value
    if allow_integer and type(value) is int and 0 <= value <= 255:
        return str(value)
    raise ValueError


@dataclass(frozen=True, order=True)
class IPv4Route:
    network: str
    interface: str | None = None
    route_type: str | None = None
    protocol: str | None = None
    scope: str | None = None
    prefsrc: str | None = None

    def __post_init__(self):
        if type(self.network) is not str:
            raise ValueError('Host route network must be text')
        network = ipaddress.ip_network(self.network, strict=True)
        if network.version != 4 or network.prefixlen == 0:
            raise ValueError('Host route must be a non-default IPv4 network')
        object.__setattr__(self, 'network', str(network))
        if self.interface is not None:
            object.__setattr__(self, 'interface', _interface_name(self.interface))
        for field in ('route_type', 'protocol', 'scope'):
            object.__setattr__(self, field, _optional_text(
                getattr(self, field), allow_integer=field == 'protocol'))
        if self.prefsrc is not None:
            if type(self.prefsrc) is not str:
                raise ValueError('Route preferred source must be IPv4 text')
            address = ipaddress.ip_address(self.prefsrc)
            if address.version != 4:
                raise ValueError('Route preferred source must be IPv4')
            object.__setattr__(self, 'prefsrc', str(address))


@dataclass(frozen=True, order=True)
class IPv4InterfaceAddress:
    ifname: str
    local: str
    prefixlen: int

    def __post_init__(self):
        object.__setattr__(self, 'ifname', _interface_name(self.ifname))
        if type(self.local) is not str:
            raise ValueError('Interface address must be IPv4 text')
        address = ipaddress.ip_address(self.local)
        if (address.version != 4 or type(self.prefixlen) is not int
                or not 0 <= self.prefixlen <= 32):
            raise ValueError('Invalid IPv4 interface address')
        object.__setattr__(self, 'local', str(address))

    @property
    def network(self):
        return str(ipaddress.ip_network(f'{self.local}/{self.prefixlen}', strict=False))


@dataclass(frozen=True)
class HostIPv4Inventory:
    routes: tuple[IPv4Route, ...]
    addresses: tuple[IPv4InterfaceAddress, ...]

    def __post_init__(self):
        if (type(self.routes) is not tuple or type(self.addresses) is not tuple
                or len(self.routes) > MAX_NETWORKS or len(self.addresses) > MAX_NETWORKS
                or any(not isinstance(item, IPv4Route) for item in self.routes)
                or any(not isinstance(item, IPv4InterfaceAddress) for item in self.addresses)):
            raise ValueError('Invalid host IPv4 inventory')
        if len({entry.network for entry in (*self.routes, *self.addresses)}) > MAX_NETWORKS:
            raise ValueError('Host IPv4 inventory exceeds the safety limit')

    @property
    def networks(self):
        values = {entry.network for entry in self.routes}
        values.update(entry.network for entry in self.addresses)
        return tuple(str(network) for network in sorted(
            (ipaddress.IPv4Network(value) for value in values),
            key=lambda item: (int(item.network_address), item.prefixlen)))


def _json_rows(value):
    if type(value) is bytes:
        try:
            value = value.decode('utf-8')
        except UnicodeError:
            raise ValueError from None
    if type(value) is str:
        try:
            value = json.loads(value)
        except (ValueError, UnicodeError):
            raise ValueError from None
    if type(value) is not list or len(value) > MAX_NETWORKS:
        raise ValueError
    return value


def _network_from_route_destination(destination):
    if destination is None or destination in _DEFAULT_DESTINATIONS:
        return None
    if type(destination) is not str or not destination:
        raise ValueError
    value = destination if '/' in destination else destination + '/32'
    network = ipaddress.ip_network(value, strict=False)
    if network.version != 4:
        raise ValueError
    return network


def parse_ipv4_networks(route_rows, address_rows):
    """Parse ``ip -j -4 route`` and ``ip -j -4 address`` with ownership metadata."""
    try:
        routes = _json_rows(route_rows)
        interfaces = _json_rows(address_rows)
        parsed_routes = []
        parsed_addresses = []
        networks = set()
        for row in routes:
            if type(row) is not dict:
                raise ValueError
            network = _network_from_route_destination(row.get('dst'))
            if network is None:
                continue
            route = IPv4Route(
                str(network), row.get('dev'), row.get('type'),
                _optional_text(row.get('protocol'), allow_integer=True),
                row.get('scope'), row.get('prefsrc'))
            parsed_routes.append(route)
            networks.add(route.network)
            if len(networks) > MAX_NETWORKS:
                raise ValueError
        for interface in interfaces:
            if type(interface) is not dict:
                raise ValueError
            ifname = interface.get('ifname')
            addresses = interface.get('addr_info', [])
            if type(addresses) is not list:
                raise ValueError
            for entry in addresses:
                if type(entry) is not dict:
                    raise ValueError
                if entry.get('family') != 'inet':
                    continue
                local, prefix = entry.get('local'), entry.get('prefixlen')
                if (type(ifname) is not str or type(local) is not str
                        or type(prefix) is not int or not 0 <= prefix <= 32):
                    raise ValueError
                address = IPv4InterfaceAddress(ifname, local, prefix)
                parsed_addresses.append(address)
                networks.add(address.network)
                if len(networks) > MAX_NETWORKS:
                    raise ValueError
        route_key = lambda route: (route.network, route.interface or '',
                                   route.route_type or '', route.protocol or '',
                                   route.scope or '', route.prefsrc or '')
        return HostIPv4Inventory(
            tuple(sorted(parsed_routes, key=route_key)), tuple(sorted(parsed_addresses)))
    except (ValueError, TypeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        raise HostRouteInventoryError('IPv4 route inventory is invalid') from None


def read_host_ipv4_networks(runner=run_command):
    """Read current non-default routes and interface prefixes without mutation."""
    try:
        routes = runner(['ip', '-j', '-4', 'route', 'show', 'table', 'all'],
                        timeout=ROUTE_TIMEOUT_SECONDS, max_output_bytes=MAX_OUTPUT_BYTES)
        addresses = runner(['ip', '-j', '-4', 'address', 'show'],
                           timeout=ROUTE_TIMEOUT_SECONDS, max_output_bytes=MAX_OUTPUT_BYTES)
        return parse_ipv4_networks(routes, addresses)
    except (ProbeFailure, OSError, HostRouteInventoryError):
        raise HostRouteInventoryError('IPv4 route inventory is unavailable') from None
    except Exception:
        raise HostRouteInventoryError('IPv4 route inventory is unavailable') from None
