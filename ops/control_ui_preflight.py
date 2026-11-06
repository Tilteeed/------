"""Check agent-domain DNS/TLS and the safe 415 handoff diagnostic; no ticket is sent."""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit


_INSTANCE_ID = re.compile(r"[0-9a-f]{32}\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class ControlUiPreflightError(ValueError):
    """A DNS, TLS, Origin, or forwarding preflight failed."""


def _validate_domain(domain: str) -> str:
    if type(domain) is not str or len(domain) > 253:
        raise ControlUiPreflightError("Invalid agent domain")
    labels = domain.split(".")
    if len(labels) < 2 or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise ControlUiPreflightError("Invalid agent domain")
    return domain


def _validate_origin(origin: str) -> tuple[str, int]:
    if type(origin) is not str or not origin:
        raise ControlUiPreflightError("Invalid application origin")
    try:
        parts = urlsplit(origin)
        port = parts.port
    except ValueError:
        raise ControlUiPreflightError("Invalid application origin") from None
    host = parts.hostname
    if (parts.scheme != "https" or host is None or not host.isascii()
            or not host.islower() or parts.username is not None or parts.password is not None
            or parts.path or parts.query or parts.fragment):
        raise ControlUiPreflightError("Application origin must be a canonical HTTPS origin")
    labels = host.split(".")
    if len(labels) < 2 or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise ControlUiPreflightError("Application origin must be a canonical HTTPS origin")
    if port == 443:
        raise ControlUiPreflightError("Application origin must omit the default HTTPS port")
    canonical = "https://" + host + (f":{port}" if port is not None else "")
    if origin != canonical:
        raise ControlUiPreflightError("Application origin must be a canonical HTTPS origin")
    return host, port or 443


def _validate_proxy_ips(proxy_ips: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if type(proxy_ips) not in (tuple, list) or not proxy_ips:
        raise ControlUiPreflightError("At least one expected proxy IPv4 address is required")
    result = []
    for value in proxy_ips:
        try:
            address = ipaddress.IPv4Address(value)
        except (ValueError, TypeError):
            raise ControlUiPreflightError("Invalid expected proxy IPv4 address") from None
        if (str(address) != value or address.is_unspecified or address.is_loopback
                or address.is_multicast or address.is_link_local
                or address == ipaddress.IPv4Address('255.255.255.255')
                or str(address) in result):
            raise ControlUiPreflightError("Invalid expected proxy IPv4 address")
        result.append(str(address))
    return tuple(result)


def _https_handoff_status(host: str, proxy_ip: str, app_origin: str, timeout: float) -> int:
    """Connect to the verified IP while preserving hostname SNI and certificate checks."""
    context = ssl.create_default_context()
    raw_socket = tls_socket = connection = None
    try:
        raw_socket = socket.create_connection((proxy_ip, 443), timeout=timeout)
        tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
        raw_socket = None
        connection = http.client.HTTPSConnection(
            host, 443, context=context, timeout=timeout)
        connection.sock = tls_socket
        tls_socket = None
        connection.request(
            "POST", "/_bezr/enter", body=b"preflight",
            headers={
                "Origin": app_origin,
                "Content-Type": "text/plain",
                # Poison both headers; the handoff route checks effective HTTPS,
                # while X-Forwarded-For is validated by the authenticated proxy path.
                "X-Forwarded-For": "198.51.100.254",
                "X-Forwarded-Proto": "http",
            },
        )
        response = connection.getresponse()
        status = response.status
        response.close()
        return status
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        raise ControlUiPreflightError("HTTPS handoff diagnostic failed") from None
    finally:
        if connection is not None:
            connection.close()
        if tls_socket is not None:
            tls_socket.close()
        if raw_socket is not None:
            raw_socket.close()


def preflight_control_ui(*, instance_id: str, domain: str, proxy_ips: tuple[str, ...] | list[str],
                         app_origin: str, timeout: float = 5.0) -> dict:
    """Resolve the browser-side A record, verify TLS, then expect an unauthenticated 415.

    The POST body is a fixed diagnostic string with an intentionally invalid content type.
    No ticket, cookie, account credential, or session is sent or read.
    """
    if type(instance_id) is not str or _INSTANCE_ID.fullmatch(instance_id) is None:
        raise ControlUiPreflightError("Invalid agent instance ID")
    domain = _validate_domain(domain)
    expected_ips = _validate_proxy_ips(proxy_ips)
    _validate_origin(app_origin)
    if type(timeout) not in (int, float) or not 0 < timeout <= 30:
        raise ControlUiPreflightError("Invalid preflight timeout")

    host = f"{instance_id}.{domain}"
    try:
        rows = socket.getaddrinfo(host, 443, family=socket.AF_INET,
                                  type=socket.SOCK_STREAM)
        observed_ips = {str(ipaddress.IPv4Address(row[4][0])) for row in rows}
    except (OSError, ValueError, IndexError, TypeError):
        raise ControlUiPreflightError("Agent DNS lookup failed") from None
    if not observed_ips or observed_ips != set(expected_ips):
        raise ControlUiPreflightError("Agent DNS A records do not match the expected HTTPS proxy IPs")

    statuses = []
    for proxy_ip in expected_ips:
        status = _https_handoff_status(host, proxy_ip, app_origin, timeout)
        if status != 415:
            raise ControlUiPreflightError(
                f"Handoff diagnostic returned HTTP {status}; expected HTTP 415")
        statuses.append(status)
    return {"dns_ips": tuple(sorted(observed_ips)), "handoff_status": statuses[0]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-id", required=True,
                        help="exact 32-character lowercase instance ID")
    parser.add_argument("--domain", required=True,
                        help="configured AGENT_CONTROL_UI_DOMAIN suffix")
    parser.add_argument("--proxy-ip", action="append", required=True,
                        help="expected Nginx IPv4 address; repeat for multiple A records")
    parser.add_argument("--app-origin", required=True,
                        help="canonical HTTPS origin of the BEZR /agent page")
    args = parser.parse_args(argv)
    try:
        preflight_control_ui(
            instance_id=args.instance_id, domain=args.domain,
            proxy_ips=args.proxy_ip, app_origin=args.app_origin)
    except ControlUiPreflightError as error:
        parser.error(str(error))
    print("Agent DNS A records: PASS")
    print("TLS, exact Origin, and forwarded HTTPS diagnostic (415 expected): PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
