"""Render an optional, lab-scoped dnsmasq snippet; never install or enable it."""
from __future__ import annotations

import argparse
import ipaddress
import re
import subprocess
import sys


_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_INTERFACE = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z")


def _unicast_ip(value: str, *, label: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if type(value) is not str or not value or any(char in value for char in "\r\n\x00"):
        raise ValueError(f"Invalid {label}")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"Invalid {label}") from None
    if (address.is_unspecified or address.is_loopback or address.is_multicast
            or address.is_link_local
            or (isinstance(address, ipaddress.IPv4Address)
                and address == ipaddress.IPv4Address('255.255.255.255'))):
        raise ValueError(f"Invalid {label}")
    return address


def _domain(value: str) -> str:
    if type(value) is not str or len(value) > 253 or "\x00" in value:
        raise ValueError("Invalid agent domain")
    labels = value.split(".")
    if len(labels) < 2 or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("Invalid agent domain")
    return value


def _validate_interface(interface: str) -> str:
    if (type(interface) is not str or interface in {"lo", "lo0"}
            or _INTERFACE.fullmatch(interface) is None):
        raise ValueError("A non-loopback lab interface is required")
    return interface


def validate_interface_address(interface: str, listen_address: str) -> None:
    """Require the requested DNS listener IPv4 to be assigned to the selected Linux NIC."""
    interface = _validate_interface(interface)
    expected = _unicast_ip(listen_address, label="DNS listen address")
    if expected.version != 4:
        raise ValueError("dnsmasq listen address must be IPv4")
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "address", "show", "dev", interface],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="ascii", timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Could not verify DNS listen address on the selected interface") from None
    for line in result.stdout.splitlines():
        fields = line.split()
        for index, field in enumerate(fields[:-1]):
            if field == "inet":
                try:
                    assigned = ipaddress.IPv4Interface(fields[index + 1]).ip
                except ValueError:
                    continue
                if assigned == expected:
                    return
    raise ValueError("DNS listen address is not assigned to the selected interface")


def render_dnsmasq_config(*, domain: str, proxy_ip: str, listen_address: str,
                          interface: str, upstream_servers: tuple[str, ...] | list[str]) -> str:
    """Return a DNS-only wildcard config bound to one explicitly trusted interface."""
    domain = _domain(domain)
    proxy = _unicast_ip(proxy_ip, label="proxy IPv4 address")
    listener = _unicast_ip(listen_address, label="DNS listen address")
    if proxy.version != 4 or listener.version != 4:
        raise ValueError("Agent proxy and dnsmasq listen addresses must be IPv4")
    _validate_interface(interface)
    if type(upstream_servers) not in (tuple, list) or not upstream_servers:
        raise ValueError("At least one explicit upstream DNS server is required")

    upstreams = []
    for value in upstream_servers:
        address = _unicast_ip(value, label="upstream DNS server")
        if str(address) not in upstreams:
            upstreams.append(str(address))
    if not upstreams:
        raise ValueError("At least one explicit upstream DNS server is required")

    lines = [
        "# Optional lab-only DNS; review before manually installing.",
        "# This renderer does not install, enable, restart, or configure DNS clients.",
        f"interface={interface}",
        f"listen-address={listener}",
        "bind-interfaces",
        "except-interface=lo",
        f"no-dhcp-interface={interface}",
        "no-resolv",
        *[f"server={server}" for server in upstreams],
        f"address=/{domain}/{proxy}",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True,
                        help="configured AGENT_CONTROL_UI_DOMAIN suffix")
    parser.add_argument("--proxy-ip", required=True,
                        help="IPv4 address of the HTTPS reverse proxy")
    parser.add_argument("--listen-address", required=True,
                        help="IPv4 address assigned to the trusted lab interface")
    parser.add_argument("--interface", required=True,
                        help="trusted lab NIC; loopback is rejected")
    parser.add_argument("--upstream", action="append", required=True,
                        help="upstream resolver IP; may be repeated")
    args = parser.parse_args(argv)
    try:
        rendered = render_dnsmasq_config(
            domain=args.domain, proxy_ip=args.proxy_ip,
            listen_address=args.listen_address, interface=args.interface,
            upstream_servers=args.upstream,
        )
        validate_interface_address(args.interface, args.listen_address)
        sys.stdout.write(rendered)
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
