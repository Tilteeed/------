#!/usr/bin/env python3
"""Live HTTPS/API isolation checks for two synthetic BEZR test users.

Requires an explicitly disposable test deployment. Tokens are read from the
process environment, never printed or written. This does not replace browser,
Control UI WebSocket, or Docker packet-isolation checks.
"""
import argparse
import asyncio
import http.cookies
import os
import re
import ssl
import sys
from urllib.parse import urlsplit

import aiohttp


def _origin(value, name):
    if type(value) is not str or len(value) > 300:
        raise ValueError(name + ' is invalid')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.netloc != parsed.hostname
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError(name + ' must be a bare HTTPS origin')
    return value.rstrip('/')


def _instance_origin(value, domain):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.netloc != parsed.hostname
            or not parsed.hostname or parsed.path or parsed.query or parsed.fragment
            or re.fullmatch(r'[0-9a-f]{32}\.' + re.escape(domain), parsed.hostname) is None):
        raise ValueError('Control UI status returned an invalid per-instance origin')
    return value.rstrip('/')


def _bearer(token):
    if type(token) is not str or not 20 <= len(token) <= 16384 or any(ord(c) < 33 for c in token):
        raise ValueError('A valid session token is required in the environment')
    return {'Authorization': 'Bearer ' + token}


def _control_cookie(response):
    values = response.headers.getall('Set-Cookie', [])
    if len(values) != 1:
        raise RuntimeError('Handoff did not return exactly one session cookie')
    cookie = http.cookies.SimpleCookie()
    cookie.load(values[0])
    morsel = cookie.get('__Host-bezr-control-ui')
    attributes = {part.strip().lower() for part in values[0].split(';')[1:]}
    if (morsel is None or not morsel.value or 'secure' not in attributes
            or 'httponly' not in attributes or 'path=/' not in attributes
            or 'samesite=lax' not in attributes
            or any(part.startswith('domain=') for part in attributes)):
        raise RuntimeError('Handoff cookie attributes are not host-only and secure')
    return morsel.value


async def _json(session, method, url, *, headers, payload=None):
    async with session.request(method, url, headers=headers, json=payload,
                               allow_redirects=False) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError('Authenticated Control UI API request failed')
        try:
            return await response.json(content_type=None)
        except Exception:
            raise RuntimeError('Control UI API returned invalid JSON') from None


async def _handoff(session, app_origin, instance_origin, token, name):
    launch = await _json(
        session, 'POST', app_origin + '/api/v1/agent-platform/me/control-ui/launch',
        headers={**_bearer(token), 'Origin': app_origin}, payload={})
    if (type(launch) is not dict or launch.get('origin') != instance_origin
            or type(launch.get('launch_ticket')) is not str):
        raise RuntimeError(name + ' launch ticket was not bound to the owner instance')
    async with session.post(
            instance_origin + '/_bezr/enter',
            headers={'Origin': app_origin},
            data={'ticket': launch['launch_ticket']}, allow_redirects=False) as response:
        if response.status != 303 or response.headers.get('Location') != '/':
            raise RuntimeError(name + ' one-time browser handoff failed')
        return _control_cookie(response)


async def _run(args):
    app_origin = _origin(args.app_origin, 'BEZR origin')
    domain = args.control_ui_domain
    if (type(domain) is not str or len(domain) > 253
            or re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*', domain) is None):
        raise ValueError('Control UI domain is invalid')
    tokens = {
        'Alice': os.environ.get('BEZR_TEST_ALICE_TOKEN'),
        'Bob': os.environ.get('BEZR_TEST_BOB_TOKEN'),
    }
    headers = {name: _bearer(token) for name, token in tokens.items()}
    ssl_context = ssl.create_default_context(cafile=args.cafile)
    timeout = aiohttp.ClientTimeout(total=30, connect=5, sock_read=20)
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector,
                                     trust_env=False, cookie_jar=aiohttp.CookieJar(unsafe=False)) as session:
        statuses = {}
        for name in ('Alice', 'Bob'):
            data = await _json(
                session, 'GET', app_origin + '/api/v1/agent-platform/me/control-ui/status',
                headers=headers[name])
            if type(data) is not dict or data.get('available') is not True:
                raise RuntimeError(name + ' Control UI is unavailable')
            statuses[name] = _instance_origin(data.get('origin'), domain)
        if statuses['Alice'] == statuses['Bob']:
            raise RuntimeError('Two test users unexpectedly resolve to the same Control UI origin')

        pairing_requests = {}
        for name in ('Alice', 'Bob'):
            listing = await _json(
                session, 'GET', app_origin + '/api/v1/agent-platform/me/control-ui/pairing',
                headers=headers[name])
            if type(listing) is not dict or type(listing.get('requests')) is not list:
                raise RuntimeError(name + ' pairing list is invalid')
            text = str(listing)
            if any(secret in text for secret in ('proxy_token', 'gateway_token', 'sidecar_token')):
                raise RuntimeError('Pairing response exposed an internal credential')
            pairing_requests[name] = listing['requests']
        alice_devices = {item.get('device_id') for item in pairing_requests['Alice']
                         if type(item) is dict}
        bob_devices = {item.get('device_id') for item in pairing_requests['Bob']
                       if type(item) is dict}
        if alice_devices & bob_devices:
            raise RuntimeError('Two users received the same pending browser device')

        cookies = {}
        for name in ('Alice', 'Bob'):
            cookies[name] = await _handoff(
                session, app_origin, statuses[name], tokens[name], name)

        # A valid Bob session cookie must not authorize Alice's host, even if a
        # client manually sends the host-only cookie to that different hostname.
        async with session.get(statuses['Alice'] + '/', headers={
                'Cookie': '__Host-bezr-control-ui=' + cookies['Bob'],
                'Origin': statuses['Alice']}, allow_redirects=False) as response:
            if response.status != 404:
                raise RuntimeError('Bob session unexpectedly reached Alice Control UI host')

        # The full Admin HTTP RPC route and Sidecar's private pairing RPC must
        # never be available through the browser-facing host relay.
        for path in ('/api/v1/admin/rpc', '/_bezr/pairing-rpc'):
            async with session.post(statuses['Alice'] + path, headers={
                    'Cookie': '__Host-bezr-control-ui=' + cookies['Alice'],
                    'Origin': statuses['Alice'],
                    'Content-Type': 'application/json'},
                    data='{"method":"device.pair.list","params":{}}',
                    allow_redirects=False) as response:
                if response.status != 404:
                    raise RuntimeError('Private pairing/Admin RPC path escaped the Access Proxy deny rule')

    print('PASS: two test users resolve to distinct origins; owner session handoff is host-bound.')
    print('PASS: cross-user host access and browser access to private pairing/Admin RPC routes are denied.')
    print('PASS: no internal Sidecar/Gateway credential appeared in pairing responses.')
    print('MANUAL: complete native Control UI device request/approval/reconnect and WSS 101 in separate browser profiles.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-origin', required=True, help='Bare HTTPS origin of the disposable BEZR deployment')
    parser.add_argument('--control-ui-domain', required=True, help='Dedicated per-instance test hostname suffix')
    parser.add_argument('--cafile', help='Optional PEM CA file for the disposable test TLS certificate')
    parser.add_argument('--execute', action='store_true', help='Send authenticated requests to the live test deployment')
    parser.add_argument('--confirm-disposable-test-users', action='store_true',
                        help='Confirm both accounts and the target deployment contain only test data')
    args = parser.parse_args()
    if not args.execute or not args.confirm_disposable_test_users:
        parser.error('Live calls require --execute --confirm-disposable-test-users')
    if sys.platform == 'win32':
        parser.error('Run this acceptance script from the approved Linux test environment')
    try:
        asyncio.run(_run(args))
    except Exception:
        # Deliberately omit exception details: request objects and URLs can contain credentials.
        print('FAIL: live Control UI two-user acceptance did not pass; see local test-service logs.',
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
