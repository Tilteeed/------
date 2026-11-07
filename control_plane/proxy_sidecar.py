"""Per-instance HTTP/WebSocket relay; never accepts a client-selected upstream.

The process binds only to its frontend-network IPv4 address. The Gateway lives
on a separate per-instance internal bridge and trusts this sidecar's exact
agent-network IPv4 address. A private bearer authenticates the BEZR web process.
"""
from dataclasses import dataclass
import hmac
import http.client
import ipaddress
import json
import os
import re
import stat
import sys
from urllib.parse import urlsplit, unquote

MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_WS_MESSAGE_BYTES = 16 * 1024 * 1024
SIDECAR_PORT = 18790
GATEWAY_PORT = 18789
CONTROL_UI_OPERATOR_SCOPES = (
    'operator.read', 'operator.write', 'operator.approvals',
    'operator.questions', 'operator.pairing',
)
_CONTROL_UI_SCOPES_HEADER = ','.join(CONTROL_UI_OPERATOR_SCOPES)
SIDECAR_TOKEN_FILE = '/run/secrets/bezr-proxy-token'
_TOKEN_FILE_ENV = 'BEZR_SIDECAR_PROXY_TOKEN_FILE'
_OWNER_RE = re.compile(r"[^\x00-\x20\x7f]{1,256}\Z")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{40,64}\Z")
_ORIGIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}\Z")
_PAIRING_ID_RE = re.compile(r'[A-Za-z0-9_-]{16,128}\Z')
_PAIRING_DEVICE_RE = re.compile(r'[A-Za-z0-9_-]{16,128}\Z')
_PAIRING_SCOPE_RE = re.compile(r'[a-z][a-z0-9._-]{0,63}\Z')
_PAIRING_RPC_PATH = '/_bezr/pairing-rpc'
_ADMIN_RPC_PATH = '/api/v1/admin/rpc'
_PAIRING_SCOPES = frozenset(CONTROL_UI_OPERATOR_SCOPES)
_MAX_PAIRING_REQUESTS = 64
_MAX_PAIRING_BODY = 8192
_MAX_PAIRING_RPC_RESPONSE = 65536
_ALLOWED_REQUEST_HEADERS = {
    'accept', 'accept-encoding', 'accept-language', 'cache-control',
    'content-type', 'if-match', 'if-modified-since', 'if-none-match',
    'if-range', 'pragma', 'range', 'user-agent',
}
_ALLOWED_RESPONSE_HEADERS = {
    'accept-ranges', 'content-disposition', 'content-encoding', 'content-language',
    'content-length', 'content-range', 'content-type', 'etag', 'last-modified',
}


class SidecarConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SidecarConfig:
    owner_id: str
    public_origin: str
    public_host: str
    gateway_ip: str
    listen_ip: str
    proxy_token: str


def _private_ipv4(value, field):
    if type(value) is not str:
        raise SidecarConfigError('Invalid sidecar network address')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise SidecarConfigError('Invalid sidecar network address') from None
    if (address.version != 4 or not address.is_private or address.is_loopback
            or address.is_link_local or address.is_multicast or address.is_unspecified
            or str(address) != value):
        raise SidecarConfigError('Invalid sidecar network address')
    return str(address)


def _client_ip(value):
    if type(value) is not str or len(value) > 64:
        raise ValueError('Invalid client address')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('Invalid client address') from None
    if (address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified or str(address) != value):
        raise ValueError('Invalid client address')
    return str(address)


def _public_origin(value):
    if type(value) is not str or len(value) > 300:
        raise SidecarConfigError('Invalid Control UI origin')
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        raise SidecarConfigError('Invalid Control UI origin') from None
    labels = hostname.split('.') if hostname else []
    if (parsed.scheme != 'https' or not hostname or parsed.netloc != hostname
            or parsed.path or parsed.query or parsed.fragment
            or len(labels) < 2 or re.fullmatch(r'[0-9a-f]{32}', labels[0]) is None
            or any(_ORIGIN_LABEL.fullmatch(label) is None for label in labels[1:])):
        raise SidecarConfigError('Invalid Control UI origin')
    return hostname


def validate_sidecar_config(data):
    expected = {'owner_id', 'public_origin', 'gateway_ip', 'listen_ip', 'proxy_token'}
    if type(data) is not dict or set(data) != expected:
        raise SidecarConfigError('Invalid sidecar configuration')
    owner_id = data['owner_id']
    if type(owner_id) is not str or _OWNER_RE.fullmatch(owner_id) is None:
        raise SidecarConfigError('Invalid sidecar owner')
    public_host = _public_origin(data['public_origin'])
    gateway_ip = _private_ipv4(data['gateway_ip'], 'gateway_ip')
    listen_ip = _private_ipv4(data['listen_ip'], 'listen_ip')
    if gateway_ip == listen_ip:
        raise SidecarConfigError('Sidecar and Gateway addresses must differ')
    token = data['proxy_token']
    if type(token) is not str or _TOKEN_RE.fullmatch(token) is None:
        raise SidecarConfigError('Invalid sidecar credential')
    return SidecarConfig(owner_id, data['public_origin'], public_host,
                         gateway_ip, listen_ip, token)


def _header_values(headers, name):
    wanted = name.lower()
    return [value for key, value in headers.items() if str(key).lower() == wanted]


def authorize_internal_request(headers, config, *, require_client_ip=True):
    authorization = _header_values(headers, 'authorization')
    host_values = _header_values(headers, 'x-bezr-host')
    origin_values = _header_values(headers, 'x-bezr-origin')
    client_values = _header_values(headers, 'x-bezr-client-ip')
    if (len(authorization) != 1 or len(host_values) != 1 or len(origin_values) != 1
            or len(client_values) != (1 if require_client_ip else 0)):
        return False
    prefix = 'Bearer '
    value = authorization[0]
    if type(value) is not str or not value.startswith(prefix):
        return False
    supplied = value[len(prefix):]
    if require_client_ip:
        try:
            client_ip = _client_ip(client_values[0])
        except ValueError:
            return False
        if client_ip != client_values[0]:
            return False
    return (hmac.compare_digest(supplied, config.proxy_token)
            and host_values[0] == config.public_host
            and origin_values[0] == config.public_origin)


def build_gateway_headers(incoming, *, owner_id, public_origin, client_ip):
    """Keep a small HTTP header allowlist; regenerate all trust-bearing headers."""
    client_ip = _client_ip(client_ip)
    output = {}
    for key, value in incoming.items():
        name = str(key).lower()
        if name in _ALLOWED_REQUEST_HEADERS and type(value) is str and len(value) <= 8192:
            output[name] = value
    host = urlsplit(public_origin).hostname
    output['origin'] = public_origin
    output['x-forwarded-user'] = owner_id
    output['x-forwarded-for'] = client_ip
    output['x-forwarded-proto'] = 'https'
    output['x-forwarded-host'] = host
    output['x-openclaw-scopes'] = _CONTROL_UI_SCOPES_HEADER
    return output


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON fields')
        result[key] = value
    return result


def _pairing_path(value):
    try:
        path = urlsplit(value).path
    except (TypeError, ValueError):
        return None
    for _ in range(5):
        decoded = unquote(path)
        if decoded == path:
            return path
        path = decoded
    return path if '%' not in path else None


def _safe_label(value, fallback, limit=96):
    if type(value) is not str:
        return fallback
    value = ''.join(char for char in value if ord(char) >= 32 and ord(char) != 127)
    return value[:limit] or fallback


def _pairing_request_view(item, expected_origin):
    if type(item) is not dict:
        raise ValueError('Invalid pairing request')
    request_id = item.get('requestId')
    device_id = item.get('deviceId')
    if (type(request_id) is not str or _PAIRING_ID_RE.fullmatch(request_id) is None
            or type(device_id) is not str or _PAIRING_DEVICE_RE.fullmatch(device_id) is None):
        raise ValueError('Invalid pairing request identity')
    roles = item.get('roles')
    if roles is None and type(item.get('role')) is str:
        roles = [item['role']]
    if (type(roles) is not list or not roles or len(roles) > 4
            or any(type(role) is not str or len(role) > 64 for role in roles)):
        role_list = []
    else:
        role_list = list(roles)
    role = ','.join(role_list) if role_list else 'unknown'
    scopes = item.get('scopes')
    scope_list_valid = (type(scopes) is list and len(scopes) <= 16
                        and all(type(scope) is str and _PAIRING_SCOPE_RE.fullmatch(scope)
                                for scope in scopes)
                        and len(set(scopes)) == len(scopes))
    scope_list = sorted(scopes) if type(scopes) is list and scope_list_valid else []
    silent = item.get('silent', False)
    if role_list != ['operator']:
        reason = 'unsupported_role'
    elif not scope_list_valid or not scope_list or not set(scope_list).issubset(_PAIRING_SCOPES):
        reason = 'unsupported_scope'
    elif item.get('clientId') != 'openclaw-control-ui':
        reason = 'not_control_ui'
    elif item.get('browserOrigin') != expected_origin:
        reason = 'origin_mismatch'
    elif type(silent) is not bool:
        reason = 'invalid_request'
    elif silent:
        reason = 'silent_request'
    else:
        reason = None
    timestamp = item.get('ts')
    if type(timestamp) is not int or timestamp < 0:
        timestamp = None
    return {
        'request_id': request_id,
        'device_id': device_id,
        'role': role,
        'scopes': scope_list,
        'client_id': _safe_label(item.get('clientId'), 'unknown-client', 64),
        'display_name': _safe_label(item.get('displayName'), 'OpenClaw Control UI'),
        'platform': _safe_label(item.get('platform'), 'unknown', 64),
        'created_at_ms': timestamp,
        'approvable': reason is None,
        'reason': reason,
    }


def _approval_matches(view, body):
    return (view['approvable'] is True
            and body.get('expectedDeviceId') == view['device_id']
            and body.get('expectedRole') == view['role']
            and body.get('expectedScopes') == view['scopes']
            and body.get('expectedClientId') == view['client_id'])


def normalize_target_path(value):
    if type(value) is not str or not value.startswith('/') or len(value) > 8192:
        raise ValueError('Invalid upstream path')
    try:
        value.encode('ascii')
        parsed = urlsplit(value)
    except (UnicodeError, ValueError):
        raise ValueError('Invalid upstream path') from None
    if (parsed.scheme or parsed.netloc or value.startswith('//') or '\\' in value
            or '\x00' in value or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('Invalid upstream path')
    decoded = unquote(parsed.path)
    if ('\\' in decoded or '\x00' in decoded
            or any(segment in {'.', '..'} for segment in decoded.split('/'))):
        raise ValueError('Invalid upstream path')
    return value


def _safe_response_headers(headers, public_origin):
    result = {}
    for key, value in headers.items():
        name = str(key).lower()
        if name not in _ALLOWED_RESPONSE_HEADERS or type(value) is not str:
            continue
        if name == 'content-length' and (not value.isascii() or not value.isdecimal()):
            continue
        if name == 'content-disposition' and any(ord(char) < 32 or ord(char) == 127 for char in value):
            continue
        result[name] = value
    location = headers.get('Location') or headers.get('location')
    if location:
        if location.startswith('/') and not location.startswith('//'):
            result['location'] = location
        else:
            parsed = urlsplit(location)
            if (parsed.scheme == 'https' and parsed.netloc == urlsplit(public_origin).netloc
                    and not parsed.username and not parsed.password):
                result['location'] = location
            else:
                raise ValueError('Upstream redirect left the agent origin')
    result['Cache-Control'] = 'no-store'
    result['Referrer-Policy'] = 'no-referrer'
    result['X-Content-Type-Options'] = 'nosniff'
    return result


def _create_app(config):
    import aiohttp
    from aiohttp import web

    app = web.Application(client_max_size=MAX_REQUEST_BYTES)
    timeout = aiohttp.ClientTimeout(total=60, connect=5, sock_read=30)
    gateway_base = f'http://{config.gateway_ip}:{GATEWAY_PORT}'

    async def gateway_admin_rpc(method, params, client_ip):
        headers = build_gateway_headers({'content-type': 'application/json'},
                                        owner_id=config.owner_id,
                                        public_origin=config.public_origin,
                                        client_ip=client_ip)
        try:
            async with aiohttp.ClientSession(
                    timeout=timeout, trust_env=False, auto_decompress=False) as session:
                async with session.post(
                        gateway_base + _ADMIN_RPC_PATH, headers=headers,
                        json={'method': method, 'params': params},
                        allow_redirects=False) as response:
                    raw = await response.content.read(_MAX_PAIRING_RPC_RESPONSE + 1)
                    if len(raw) > _MAX_PAIRING_RPC_RESPONSE:
                        raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'})
                    if method == 'device.pair.approve' and response.status in {400, 404, 409}:
                        raise web.HTTPConflict(headers={'Cache-Control': 'no-store'})
                    if response.status != 200:
                        raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'})
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'}) from None
        try:
            envelope = json.loads(raw, object_pairs_hook=_unique_json_object)
        except (ValueError, UnicodeError, RecursionError):
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'}) from None
        if (type(envelope) is not dict or envelope.get('ok') is not True
                or type(envelope.get('payload')) is not dict):
            error = envelope.get('error') if type(envelope) is dict else None
            code = error.get('code') if type(error) is dict else None
            if method == 'device.pair.approve' and code in {
                    'not_found', 'request_not_found', 'device_pairing_request_not_found'}:
                raise web.HTTPConflict(headers={'Cache-Control': 'no-store'})
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'})
        return envelope['payload']

    async def list_pairings(client_ip):
        payload = await gateway_admin_rpc('device.pair.list', {}, client_ip)
        pending = payload.get('pending')
        paired = payload.get('paired')
        if (type(pending) is not list or len(pending) > _MAX_PAIRING_REQUESTS
                or type(paired) is not list or len(paired) > _MAX_PAIRING_REQUESTS * 4):
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'})
        try:
            views = [_pairing_request_view(item, config.public_origin) for item in pending]
        except (TypeError, ValueError):
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'}) from None
        return views, pending, paired

    async def pairing_rpc(request, client_ip):
        if request.method != 'POST' or request.rel_url.query_string:
            raise web.HTTPNotFound(headers={'Cache-Control': 'no-store'})
        raw = await request.read()
        if len(raw) > _MAX_PAIRING_BODY:
            raise web.HTTPRequestEntityTooLarge(_MAX_PAIRING_BODY, len(raw))
        try:
            body = json.loads(raw, object_pairs_hook=_unique_json_object)
        except (ValueError, UnicodeError, RecursionError):
            raise web.HTTPBadRequest(headers={'Cache-Control': 'no-store'}) from None
        if type(body) is not dict:
            raise web.HTTPBadRequest(headers={'Cache-Control': 'no-store'})
        if body == {'action': 'list'}:
            views, _pending, _paired = await list_pairings(client_ip)
            return web.json_response({'requests': views}, headers={'Cache-Control': 'no-store'})
        expected = {'action', 'requestId', 'expectedDeviceId', 'expectedRole',
                    'expectedScopes', 'expectedClientId'}
        if set(body) != expected or body.get('action') != 'approve':
            raise web.HTTPBadRequest(headers={'Cache-Control': 'no-store'})
        if (type(body['requestId']) is not str
                or _PAIRING_ID_RE.fullmatch(body['requestId']) is None
                or type(body['expectedDeviceId']) is not str
                or _PAIRING_DEVICE_RE.fullmatch(body['expectedDeviceId']) is None
                or body['expectedRole'] != 'operator'
                or type(body['expectedClientId']) is not str
                or body['expectedClientId'] != 'openclaw-control-ui'
                or type(body['expectedScopes']) is not list
                or len(body['expectedScopes']) > len(_PAIRING_SCOPES)
                or any(type(scope) is not str or scope not in _PAIRING_SCOPES
                       for scope in body['expectedScopes'])
                or body['expectedScopes'] != sorted(set(body['expectedScopes']))):
            raise web.HTTPBadRequest(headers={'Cache-Control': 'no-store'})
        views, pending, _paired = await list_pairings(client_ip)
        matches = [view for view in views if view['request_id'] == body['requestId']]
        if len(matches) != 1 or not _approval_matches(matches[0], body):
            raise web.HTTPConflict(headers={'Cache-Control': 'no-store'})
        request_view = matches[0]
        try:
            await gateway_admin_rpc('device.pair.approve',
                                    {'requestId': request_view['request_id']}, client_ip)
        except web.HTTPConflict:
            raise
        views_after, pending_after, paired_after = await list_pairings(client_ip)
        if any(view['request_id'] == request_view['request_id'] for view in views_after):
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'})
        device = next((item for item in paired_after
                       if type(item) is dict and item.get('deviceId') == request_view['device_id']), None)
        roles = device.get('roles') if type(device) is dict else None
        if roles is None and type(device) is dict and type(device.get('role')) is str:
            roles = [device['role']]
        paired_scopes = device.get('scopes') if type(device) is dict else None
        if (type(device) is not dict or roles != ['operator']
                or type(paired_scopes) is not list
                or sorted(paired_scopes) != request_view['scopes']):
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'})
        return web.json_response({
            'approved': True, 'device_id': request_view['device_id'],
            'scopes': request_view['scopes'],
        }, headers={'Cache-Control': 'no-store'})

    def check_request(request):
        if not authorize_internal_request(request.headers, config):
            raise web.HTTPNotFound(headers={'Cache-Control': 'no-store'})
        if request.method not in {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}:
            raise web.HTTPMethodNotAllowed(request.method, {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'})
        origin_values = request.headers.getall('Origin', [])
        if origin_values != [config.public_origin]:
            raise web.HTTPForbidden(headers={'Cache-Control': 'no-store'})
        return normalize_target_path(request.rel_url.raw_path_qs), _client_ip(
            request.headers.get('X-Bezr-Client-IP'))

    async def health(request):
        if not authorize_internal_request(request.headers, config, require_client_ip=False):
            raise web.HTTPNotFound(headers={'Cache-Control': 'no-store'})
        return web.Response(status=204, headers={'Cache-Control': 'no-store'})

    async def proxy_http(request):
        path, client_ip = check_request(request)
        decoded_path = _pairing_path(path)
        if decoded_path == _PAIRING_RPC_PATH:
            return await pairing_rpc(request, client_ip)
        if decoded_path is None:
            raise web.HTTPNotFound(headers={'Cache-Control': 'no-store'})
        normalized_path = decoded_path.rstrip('/')
        if (normalized_path == _ADMIN_RPC_PATH
                or normalized_path.startswith(_ADMIN_RPC_PATH + '/')
                or normalized_path == _PAIRING_RPC_PATH
                or normalized_path.startswith(_PAIRING_RPC_PATH + '/')):
            raise web.HTTPNotFound(headers={'Cache-Control': 'no-store'})
        if request.headers.get('Upgrade', '').lower() == 'websocket':
            return await proxy_websocket(request, path, client_ip)
        body = await request.read()
        if len(body) > MAX_REQUEST_BYTES:
            raise web.HTTPRequestEntityTooLarge(MAX_REQUEST_BYTES, len(body))
        headers = build_gateway_headers(request.headers, owner_id=config.owner_id,
                                        public_origin=config.public_origin, client_ip=client_ip)
        url = gateway_base + path
        try:
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False,
                                             auto_decompress=False) as session:
                async with session.request(request.method, url, headers=headers, data=body,
                                           allow_redirects=False) as upstream:
                    response_buffer = bytearray()
                    async for chunk in upstream.content.iter_chunked(65536):
                        if len(response_buffer) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'})
                        response_buffer.extend(chunk)
                    response_body = bytes(response_buffer)
                    response_headers = _safe_response_headers(upstream.headers, config.public_origin)
                    return web.Response(status=upstream.status, body=response_body,
                                        headers=response_headers)
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'}) from None

    async def proxy_websocket(request, path, client_ip):
        requested = []
        for item in request.headers.getall('Sec-WebSocket-Protocol', []):
            requested.extend(part.strip() for part in item.split(',') if part.strip())
        if len(requested) > 16 or any(_HEADER_TOKEN.fullmatch(item) is None for item in requested):
            raise web.HTTPBadRequest(headers={'Cache-Control': 'no-store'})
        headers = build_gateway_headers(request.headers, owner_id=config.owner_id,
                                        public_origin=config.public_origin, client_ip=client_ip)
        try:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, connect=5),
                                            trust_env=False, auto_decompress=False)
            try:
                upstream = await session.ws_connect(
                    gateway_base + path, headers=headers, protocols=requested,
                    heartbeat=None, max_msg_size=MAX_WS_MESSAGE_BYTES, compress=0,
                )
            except Exception:
                await session.close()
                raise
            selected_protocols = [upstream.protocol] if upstream.protocol else ()
            client = web.WebSocketResponse(protocols=selected_protocols,
                                           max_msg_size=MAX_WS_MESSAGE_BYTES,
                                           autoping=True, autoclose=True, compress=False)
            await client.prepare(request)

            async def relay(source, destination):
                async for message in source:
                    if message.type == aiohttp.WSMsgType.TEXT:
                        await destination.send_str(message.data)
                    elif message.type == aiohttp.WSMsgType.BINARY:
                        await destination.send_bytes(message.data)
                    elif message.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                                          aiohttp.WSMsgType.ERROR}:
                        break

            import asyncio
            tasks = {asyncio.create_task(relay(client, upstream)),
                     asyncio.create_task(relay(upstream, client))}
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            finally:
                await client.close()
                await upstream.close()
                await session.close()
            return client
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPBadGateway(headers={'Cache-Control': 'no-store'}) from None

    app.router.add_get('/_bezr/health', health)
    app.router.add_route('*', '/{path:.*}', proxy_http)
    app.router.add_route('*', '/', proxy_http)
    return app


def _read_proxy_token_file(path):
    if type(path) is not str or path != SIDECAR_TOKEN_FILE:
        raise SidecarConfigError('Invalid sidecar credential file')
    nofollow = getattr(os, 'O_NOFOLLOW', None)
    if type(nofollow) is not int:
        raise SidecarConfigError('Secure sidecar credential file access is unavailable')
    flags = os.O_RDONLY | nofollow | getattr(os, 'O_CLOEXEC', 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        get_euid = getattr(os, 'geteuid', None)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or not callable(get_euid)
                or info.st_uid != get_euid() or not 40 <= info.st_size <= 64):
            raise SidecarConfigError('Invalid sidecar credential file')
        raw = os.read(descriptor, 65)
        if len(raw) != info.st_size:
            raise SidecarConfigError('Invalid sidecar credential file')
    except SidecarConfigError:
        raise
    except OSError:
        raise SidecarConfigError('Invalid sidecar credential file') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        token = raw.decode('ascii')
    except UnicodeError:
        raise SidecarConfigError('Invalid sidecar credential file') from None
    if _TOKEN_RE.fullmatch(token) is None:
        raise SidecarConfigError('Invalid sidecar credential file')
    return token


def _environment_config():
    if 'BEZR_SIDECAR_PROXY_TOKEN' in os.environ:
        raise SidecarConfigError('Proxy credential must not be an environment value')
    token_path = os.environ.get(_TOKEN_FILE_ENV)
    values = {
        'owner_id': os.environ.get('BEZR_SIDECAR_OWNER_ID'),
        'public_origin': os.environ.get('BEZR_SIDECAR_PUBLIC_ORIGIN'),
        'gateway_ip': os.environ.get('BEZR_SIDECAR_GATEWAY_IP'),
        'listen_ip': os.environ.get('BEZR_SIDECAR_LISTEN_IP'),
        'proxy_token': _read_proxy_token_file(token_path),
    }
    return validate_sidecar_config(values)


def _healthcheck(config):
    connection = None
    headers = {
        'Authorization': 'Bearer ' + config.proxy_token,
        'Host': config.public_host,
        'X-Bezr-Host': config.public_host,
        'X-Bezr-Origin': config.public_origin,
    }
    try:
        connection = http.client.HTTPConnection(config.listen_ip, SIDECAR_PORT, timeout=3)
        connection.request('GET', '/_bezr/health', headers=headers)
        response = connection.getresponse()
        return response.status == 204
    except Exception:
        return False
    finally:
        if connection is not None:
            connection.close()


def main():
    if sys.argv[1:] == ['--healthcheck']:
        try:
            config = _environment_config()
            healthy = _healthcheck(config)
        except Exception:
            healthy = False
        if not healthy:
            print('Sidecar healthcheck failed', file=sys.stderr)
            return 1
        return 0
    config = _environment_config()
    from aiohttp import web
    app = _create_app(config)
    web.run_app(app, host=config.listen_ip, port=SIDECAR_PORT,
                print=None, access_log=None, handle_signals=True)


def _entrypoint():
    raise SystemExit(main())


if __name__ == '__main__':
    _entrypoint()
