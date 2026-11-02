"""One-time form-POST browser handoff for the owner-scoped Control UI origin.

The HTTP/WS reverse-proxy routes are not implemented here. This module only
redeems a launch ticket and sets the host-only session cookie; it never accepts
an upstream target.
"""
import re
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, HTTPException, Request
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
