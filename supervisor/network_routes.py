"""Read-only, bounded IPv4 route and interface inventory for proxy IPAM."""
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
    """Parse ``ip -j -4 route`` and ``ip -j -4 address`` into canonical networks."""
    try:
        routes = _json_rows(route_rows)
        interfaces = _json_rows(address_rows)
        networks = set()
        for row in routes:
            if type(row) is not dict:
                raise ValueError
            network = _network_from_route_destination(row.get('dst'))
            if network is not None and network.prefixlen != 0:
                networks.add(network)
        for interface in interfaces:
            if type(interface) is not dict:
                raise ValueError
            addresses = interface.get('addr_info', [])
            if type(addresses) is not list:
                raise ValueError
            for entry in addresses:
                if type(entry) is not dict:
                    raise ValueError
                if entry.get('family') != 'inet':
                    continue
                local, prefix = entry.get('local'), entry.get('prefixlen')
                if type(local) is not str or type(prefix) is not int or not 0 <= prefix <= 32:
                    raise ValueError
                network = ipaddress.ip_network(f'{local}/{prefix}', strict=False)
                if network.version != 4:
                    raise ValueError
                networks.add(network)
                if len(networks) > MAX_NETWORKS:
                    raise ValueError
        return tuple(str(network) for network in sorted(
            networks, key=lambda item: (int(item.network_address), item.prefixlen)))
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
