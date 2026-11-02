"""Owner-scoped Control UI handoff and authenticated HTTP/WebSocket proxy.

Every proxied request revalidates its host-bound BEZR session, owner/runtime
binding, and server-resolved sidecar target. The per-agent relay is implemented
in :mod:`control_plane.proxy_sidecar`; it never accepts a client-selected target.
"""
import asyncio
import inspect
import ipaddress
import math
import re
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, FastAPI, HTTPException, Request, WebSocket
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from .store import InvalidControlUiTicket

_COOKIE_NAME = '__Host-bezr-control-ui'
_TICKET_RE = re.compile(r'[A-Za-z0-9_-]{40,64}\Z')
_LABEL_RE = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def _configured_origin(public_origin, control_ui_domain):
    if (type(control_ui_domain) is not str or not control_ui_domain
            or any(_LABEL_RE.fullmatch(label) is None for label in control_ui_domain.split('.'))
            or len(control_ui_domain) > 253):
        return None
    if type(public_origin) is not str or len(public_origin) > 300:
        return None
    try:
        parsed = urlsplit(public_origin)
        hostname = parsed.hostname
    except ValueError:
        return None
    if (parsed.scheme != 'https' or not hostname or parsed.netloc != hostname
            or parsed.path or parsed.query or parsed.fragment):
        return None
    return public_origin


def _headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def _handoff_error(status, detail):
    return HTTPException(status, detail, headers={
        'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
    })


def create_handoff_router(store, *, public_origin, control_ui_domain, proxy_ready=False):
    """Create a handoff route; disabled unless origins are trusted HTTPS and proxy is mounted."""
    if type(proxy_ready) is not bool:
        raise ValueError('Control UI proxy readiness must be an explicit boolean')
    router = APIRouter(include_in_schema=False)
    app_origin = _configured_origin(public_origin, control_ui_domain) or ''
    domain = control_ui_domain if type(control_ui_domain) is str else ''
    domain_enabled = (proxy_ready and bool(app_origin and domain) and len(domain) <= 253
                      and all(_LABEL_RE.fullmatch(label) for label in domain.split('.')))

    def request_binding(request):
        host = request.headers.get('host', '')
        if (not domain_enabled or request.url.scheme != 'https'
                or type(host) is not str or len(host) > 300 or host != host.lower()):
            raise _handoff_error(404, 'Not found')
        instance_match = re.fullmatch(r'([0-9a-f]{32})\.' + re.escape(domain), host)
        if instance_match is None:
            raise _handoff_error(404, 'Not found')
        return host, instance_match.group(1)

    @router.post('/_bezr/enter')
    async def redeem_ticket(request: Request):
        host, _instance_id = request_binding(request)
        audience = 'https://' + host
        origin_values = request.headers.getlist('origin')
        if origin_values != [app_origin]:
            raise _handoff_error(403, 'Cross-origin ticket exchange is forbidden')
        content_type = request.headers.get('content-type', '').split(';', 1)[0].strip().lower()
        if content_type != 'application/x-www-form-urlencoded':
            raise _handoff_error(415, 'application/x-www-form-urlencoded required')
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 4096:
                raise _handoff_error(413, 'Request body too large')
            body.extend(chunk)
        try:
            fields = parse_qsl(body.decode('ascii'), keep_blank_values=True,
                               strict_parsing=True, max_num_fields=2)
        except (ValueError, UnicodeError):
            raise _handoff_error(400, 'Invalid form body') from None
        if len(fields) != 1 or fields[0][0] != 'ticket':
            raise _handoff_error(400, 'One launch ticket is required')
        ticket = fields[0][1]
        if type(ticket) is not str or _TICKET_RE.fullmatch(ticket) is None:
            raise _handoff_error(404, 'Not found')
        try:
            session = await run_in_threadpool(
                store.redeem_control_ui_ticket, ticket, audience=audience)
        except InvalidControlUiTicket:
            raise _handoff_error(404, 'Not found') from None
        response = Response(status_code=303, headers={'Location': '/'})
        response.set_cookie(_COOKIE_NAME, session['session_id'], max_age=3600,
                            path='/', secure=True, httponly=True, samesite='lax')
        return _headers(response)

    return router


_SIDECAR_PORT = 18790
_SIDECAR_TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{40,64}\Z')
_SESSION_RE = re.compile(r'[A-Za-z0-9_-]{40,64}\Z')
_PROXY_REQUEST_HEADERS = {
    'accept', 'accept-encoding', 'accept-language', 'cache-control',
    'content-type', 'if-match', 'if-modified-since', 'if-none-match',
    'if-range', 'pragma', 'range', 'user-agent',
}
_PROXY_RESPONSE_HEADERS = {
    'accept-ranges', 'content-disposition', 'content-encoding', 'content-language',
    'content-length', 'content-range', 'content-type', 'etag', 'last-modified',
}
_PROXY_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}
_MAX_PROXY_BODY = 16 * 1024 * 1024
_MAX_PROXY_RESPONSE = 32 * 1024 * 1024


def _scope_header_values(scope, name):
    key = name.lower().encode('ascii')
    return [value.decode('latin-1') for header, value in scope.get('headers', [])
            if header.lower() == key]


def _host_binding(scope, domain):
    hosts = _scope_header_values(scope, 'host')
    expected_scheme = 'wss' if scope.get('type') == 'websocket' else 'https'
    if len(hosts) != 1 or scope.get('scheme') != expected_scheme:
        return None
    host = hosts[0]
    if type(host) is not str or host != host.lower() or len(host) > 300:
        return None
    match = re.fullmatch(r'([0-9a-f]{32})\.' + re.escape(domain), host)
    if match is None:
        return None
    return host, match.group(1), 'https://' + host


def _session_cookie(scope):
    cookie_headers = _scope_header_values(scope, 'cookie')
    if len(cookie_headers) != 1:
        return None
    found = []
    for part in cookie_headers[0].split(';'):
        key, separator, value = part.strip().partition('=')
        if key == _COOKIE_NAME and separator:
            found.append(value)
    if len(found) != 1 or _SESSION_RE.fullmatch(found[0]) is None:
        return None
    return found[0]


def _request_client_ip(scope):
    client = scope.get('client')
    if (type(client) not in (tuple, list) or len(client) < 1
            or type(client[0]) is not str):
        raise HTTPException(403, 'Forbidden', headers={'Cache-Control': 'no-store'})
    try:
        address = ipaddress.ip_address(client[0])
    except ValueError:
        raise HTTPException(403, 'Forbidden', headers={'Cache-Control': 'no-store'}) from None
    if (address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified):
        raise HTTPException(403, 'Forbidden', headers={'Cache-Control': 'no-store'})
    return str(address)


def validate_proxy_target(target):
    if type(target) is not dict or set(target) != {'ip', 'port', 'proxy_token'}:
        return None
    ip, port, token = target['ip'], target['port'], target['proxy_token']
    try:
        parsed = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None
    if (parsed.version != 4 or not parsed.is_private or parsed.is_loopback
            or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified
            or str(parsed) != ip or type(port) is not int or port != _SIDECAR_PORT
            or type(token) is not str or _SIDECAR_TOKEN_RE.fullmatch(token) is None):
        return None
    return {'ip': str(parsed), 'port': port, 'proxy_token': token}


def _sidecar_headers(request_headers, *, host, origin, target, client_ip):
    output = {}
    for key, value in request_headers.items():
        name = str(key).lower()
        if name in _PROXY_REQUEST_HEADERS and type(value) is str and len(value) <= 8192:
            output[name] = value
    # These values are constructed after the BEZR session/owner check. No
    # browser-supplied Authorization, Cookie or forwarded identity is relayed.
    output.update({
        'authorization': 'Bearer ' + target['proxy_token'],
        'origin': origin,
        'x-bezr-host': host,
        'x-bezr-origin': origin,
        'x-bezr-client-ip': client_ip,
    })
    return output


def _safe_proxy_response_headers(headers, *, origin):
    output = {}
    for key, value in headers.items():
        name = str(key).lower()
        if name not in _PROXY_RESPONSE_HEADERS or type(value) is not str:
            continue
        if name == 'content-length' and not value.isdecimal():
            continue
        output[name] = value
    location = headers.get('location') or headers.get('Location')
    if location:
        if location.startswith('/') and not location.startswith('//'):
            output['location'] = location
        else:
            try:
                parsed = urlsplit(location)
            except ValueError:
                raise ValueError('Invalid upstream redirect') from None
            if (parsed.scheme == 'https' and parsed.netloc == urlsplit(origin).netloc
                    and not parsed.username and not parsed.password):
                output['location'] = location
            else:
                raise ValueError('Upstream redirect left the agent origin')
    output.update({'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                   'X-Content-Type-Options': 'nosniff'})
    return output


def _proxy_path(scope):
    raw_path = scope.get('raw_path') or scope.get('path', '/').encode('utf-8')
    try:
        path = raw_path.decode('ascii')
        query = scope.get('query_string', b'').decode('ascii')
    except UnicodeError:
        return None
    combined = path + (('?' + query) if query else '')
    if (not path.startswith('/') or path.startswith('//') or len(combined) > 8192
            or '\\' in combined or '\x00' in combined
            or any(ord(char) < 32 or ord(char) == 127 for char in combined)):
        return None
    return combined


class AiohttpSidecarTransport:
    """HTTP/WS transport to one supervisor-resolved, private sidecar target."""
    async def request(self, target, method, path, headers, body):
        import aiohttp
        url = f"http://{target['ip']}:{target['port']}{path}"
        timeout = aiohttp.ClientTimeout(total=60, connect=5, sock_read=30)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False,
                                         auto_decompress=False) as session:
            async with session.request(method, url, headers=headers, data=body,
                                       allow_redirects=False) as response:
                content = await response.content.read(_MAX_PROXY_RESPONSE + 1)
                if len(content) > _MAX_PROXY_RESPONSE:
                    raise ValueError('Proxy response limit exceeded')
                return response.status, dict(response.headers), content

    @asynccontextmanager
    async def websocket(self, target, path, headers, protocols):
        import aiohttp
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=None, connect=5), trust_env=False)
        try:
            upstream = await session.ws_connect(
                f"http://{target['ip']}:{target['port']}{path}", headers=headers,
                protocols=protocols, heartbeat=None, max_msg_size=_MAX_PROXY_BODY,
                compress=0,
            )
            try:
                yield upstream
            finally:
                await upstream.close()
        finally:
            await session.close()


class ControlUiHostMiddleware:
    """Dispatch only the exact per-instance HTTPS host family to its proxy app."""
    def __init__(self, app, *, proxy_app, control_ui_domain):
        self.app = app
        self.proxy_app = proxy_app
        self.domain = control_ui_domain
        if (type(self.domain) is not str or not self.domain or len(self.domain) > 253
                or any(_LABEL_RE.fullmatch(label) is None for label in self.domain.split('.'))):
            raise ValueError('Invalid Control UI host domain')

    async def __call__(self, scope, receive, send):
        if scope.get('type') in {'http', 'websocket'}:
            host_values = _scope_header_values(scope, 'host')
            if len(host_values) == 1:
                host = host_values[0]
                if host.endswith('.' + self.domain):
                    if re.fullmatch(r'[0-9a-f]{32}\.' + re.escape(self.domain), host):
                        await self.proxy_app(scope, receive, send)
                    else:
                        response = Response(status_code=404, headers={'Cache-Control': 'no-store'})
                        await response(scope, receive, send)
                    return
        await self.app(scope, receive, send)


def create_control_ui_access_proxy(store, runtime, *, public_origin, control_ui_domain,
                                   target_resolver, transport=None, proxy_ready=False,
                                   ws_session_recheck_seconds: float = 15.0):
    """Create the per-instance host app; all requests revalidate session and live binding."""
    if type(proxy_ready) is not bool:
        raise ValueError('Proxy readiness must be a boolean')
    if (type(ws_session_recheck_seconds) not in (int, float)
            or not math.isfinite(ws_session_recheck_seconds)
            or not 0 < ws_session_recheck_seconds <= 30):
        raise ValueError('WebSocket session recheck interval must be in (0, 30] seconds')
    if not proxy_ready or runtime is None or not callable(target_resolver):
        ready = False
    else:
        ready = True
    router = APIRouter(include_in_schema=False)
    router.include_router(create_handoff_router(
        store, public_origin=public_origin, control_ui_domain=control_ui_domain,
        proxy_ready=ready))
    origin_configured = _configured_origin(public_origin, control_ui_domain)
    domain = control_ui_domain if type(control_ui_domain) is str else ''
    if transport is None:
        transport = AiohttpSidecarTransport()

    async def authorize(scope, method, *, websocket=False):
        binding = _host_binding(scope, domain)
        if not ready or binding is None or origin_configured is None:
            raise HTTPException(404, 'Not found', headers={'Cache-Control': 'no-store'})
        host, instance_id, audience = binding
        origins = _scope_header_values(scope, 'origin')
        if (websocket and origins != [audience]) or (origins and origins != [audience]):
            raise HTTPException(403, 'Forbidden', headers={'Cache-Control': 'no-store'})
        fetch_site = _scope_header_values(scope, 'sec-fetch-site')
        if len(fetch_site) > 1 or (fetch_site and fetch_site[0].lower() == 'cross-site'):
            raise HTTPException(403, 'Forbidden', headers={'Cache-Control': 'no-store'})
        if method not in {'GET', 'HEAD', 'OPTIONS'} and origins != [audience]:
            raise HTTPException(403, 'Forbidden', headers={'Cache-Control': 'no-store'})
        session_id = _session_cookie(scope)
        if session_id is None:
            raise HTTPException(404, 'Not found', headers={'Cache-Control': 'no-store'})
        try:
            session = await run_in_threadpool(
                store.validate_control_ui_session, session_id, audience=audience)
        except Exception:
            session = None
        if (type(session) is not dict or session.get('instance_id') != instance_id
                or type(session.get('owner_id')) is not str):
            raise HTTPException(404, 'Not found', headers={'Cache-Control': 'no-store'})
        owner_id = session['owner_id']
        client_ip = _request_client_ip(scope)
        try:
            observed = await run_in_threadpool(runtime.get, owner_id)
            info = observed.get('runtime') if type(observed) is dict else None
            if type(info) is not dict:
                raise HTTPException(404, 'Not found', headers={'Cache-Control': 'no-store'})
            if (info.get('state') != 'running' or info.get('gateway') != 'ready'
                    or info.get('network_profile') != 'agent_proxy_v1'
                    or info.get('instance_id') != instance_id):
                raise HTTPException(404, 'Not found', headers={'Cache-Control': 'no-store'})
            target = await run_in_threadpool(target_resolver, owner_id, instance_id)
            if inspect.isawaitable(target):
                target = await target
            target = validate_proxy_target(target)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, 'Proxy unavailable', headers={'Cache-Control': 'no-store'}) from None
        if target is None:
            raise HTTPException(404, 'Not found', headers={'Cache-Control': 'no-store'})
        return {'host': host, 'instance_id': instance_id, 'origin': audience,
                'owner_id': owner_id, 'session_id': session_id,
                'client_ip': client_ip, 'target': target}

    async def http_proxy(request: Request, _path=''):
        if request.method not in _PROXY_METHODS:
            raise HTTPException(405, 'Method not allowed', headers={'Cache-Control': 'no-store'})
        context = await authorize(request.scope, request.method)
        path = _proxy_path(request.scope)
        if path is None:
            raise HTTPException(400, 'Invalid path', headers={'Cache-Control': 'no-store'})
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > _MAX_PROXY_BODY:
                raise HTTPException(413, 'Request too large', headers={'Cache-Control': 'no-store'})
            body.extend(chunk)
        headers = _sidecar_headers(request.headers, host=context['host'],
                                   origin=context['origin'], target=context['target'],
                                   client_ip=context['client_ip'])
        try:
            status, response_headers, content = await transport.request(
                context['target'], request.method, path, headers, bytes(body))
            if (type(status) is not int or not 100 <= status <= 599
                    or type(response_headers) is not dict or type(content) is not bytes
                    or len(content) > _MAX_PROXY_RESPONSE):
                raise ValueError('Invalid sidecar response')
            safe_headers = _safe_proxy_response_headers(response_headers, origin=context['origin'])
        except Exception:
            raise HTTPException(502, 'Control UI upstream unavailable',
                                headers={'Cache-Control': 'no-store'}) from None
        return Response(content, status_code=status, headers=safe_headers)

    router.add_api_route('/', http_proxy, methods=sorted(_PROXY_METHODS), include_in_schema=False)
    router.add_api_route('/{path:path}', http_proxy, methods=sorted(_PROXY_METHODS), include_in_schema=False)

    async def ws_proxy(websocket: WebSocket, _path=''):
        try:
            context = await authorize(websocket.scope, 'GET', websocket=True)
            path = _proxy_path(websocket.scope)
            if path is None:
                raise HTTPException(400, 'Invalid path')
            requested = []
            for value in websocket.headers.getlist('sec-websocket-protocol'):
                requested.extend(part.strip() for part in value.split(',') if part.strip())
            if len(requested) > 16 or any(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", p) is None for p in requested):
                raise HTTPException(400, 'Invalid WebSocket protocol')
            headers = _sidecar_headers(websocket.headers, host=context['host'],
                                       origin=context['origin'], target=context['target'],
                                       client_ip=context['client_ip'])
            async with transport.websocket(context['target'], path, headers, requested) as upstream:
                protocol = upstream.protocol if type(upstream.protocol) is str else None
                await websocket.accept(subprotocol=protocol)

                async def client_to_upstream():
                    while True:
                        message = await websocket.receive()
                        if message['type'] == 'websocket.disconnect':
                            return
                        if message.get('text') is not None:
                            await upstream.send_str(message['text'])
                        elif message.get('bytes') is not None:
                            await upstream.send_bytes(message['bytes'])

                async def upstream_to_client():
                    import aiohttp
                    async for message in upstream:
                        if message.type == aiohttp.WSMsgType.TEXT:
                            await websocket.send_text(message.data)
                        elif message.type == aiohttp.WSMsgType.BINARY:
                            await websocket.send_bytes(message.data)
                        elif message.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                                              aiohttp.WSMsgType.ERROR}:
                            return

                async def monitor_session():
                    while True:
                        await asyncio.sleep(ws_session_recheck_seconds)
                        try:
                            await authorize(websocket.scope, 'GET', websocket=True)
                        except Exception:
                            await websocket.close(code=4401, reason='Session revoked')
                            await upstream.close()
                            return

                tasks = {asyncio.create_task(client_to_upstream()),
                         asyncio.create_task(upstream_to_client()),
                         asyncio.create_task(monitor_session())}
                try:
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        task.result()
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                finally:
                    try:
                        await websocket.close()
                    except RuntimeError:
                        pass
                    try:
                        await upstream.close()
                    except RuntimeError:
                        pass
        except HTTPException:
            try:
                await websocket.close(code=4404, reason='Not found')
            except RuntimeError:
                pass
        except Exception:
            try:
                await websocket.close(code=1011, reason='Proxy unavailable')
            except RuntimeError:
                pass

    router.add_api_websocket_route('/', ws_proxy, name='control-ui-ws-root')
    router.add_api_websocket_route('/{path:path}', ws_proxy, name='control-ui-ws-path')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(router)
    app.state.proxy_ready = ready
    return app
