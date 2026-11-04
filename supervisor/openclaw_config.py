"""OpenClaw config builders for retained token and per-agent proxy profiles."""
import ipaddress
import re
from urllib.parse import urlsplit


_OWNER_RE = re.compile(r"[^\x00-\x20\x7f]{1,256}\Z")
_INSTANCE_RE = re.compile(r'[0-9a-f]{32}\Z')
_LABEL_RE = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def _validate_proxy_origin(value, instance_id):
    if type(value) is not str or len(value) > 300:
        raise ValueError('Invalid Control UI origin')
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        raise ValueError('Invalid Control UI origin') from None
    labels = hostname.split('.') if hostname else []
    if (parsed.scheme != 'https' or not hostname or parsed.netloc != hostname
            or parsed.path or parsed.query or parsed.fragment or not labels
            or labels[0] != instance_id or len(labels) < 2
            or any(_LABEL_RE.fullmatch(label) is None for label in labels)):
        raise ValueError('Invalid Control UI origin')
    return value


def _validate_proxy_ip(value):
    if type(value) is not str:
        raise ValueError('Invalid trusted proxy address')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('Invalid trusted proxy address') from None
    if (address.version != 4 or not address.is_private or address.is_loopback
            or address.is_link_local or address.is_multicast or address.is_unspecified
            or str(address) != value):
        raise ValueError('Invalid trusted proxy address')
    return str(address)


def build_gateway_config(instance):
    """Build only a supported auth profile; never mix proxy auth with a token."""
    if type(instance) is not dict:
        raise ValueError('Invalid Gateway instance')
    profile = instance.get('network_profile', 'legacy_none')
    token = instance.get('gateway_token')
    if type(token) is not str or not 1 <= len(token) <= 4096:
        raise ValueError('Invalid Gateway credential')
    gateway: dict[str, object] = {'mode': 'local', 'bind': 'lan'}
    if profile in {'legacy_none', 'agent_internal_v1'}:
        gateway.update({
            'auth': {'mode': 'token', 'token': token},
            'controlUi': {'allowedOrigins': [
                'http://localhost:18789', 'http://127.0.0.1:18789']},
        })
        return {'gateway': gateway}
    if profile != 'agent_proxy_v1':
        raise ValueError('Unsupported Gateway network profile')
    instance_id = instance.get('id')
    owner_id = instance.get('actor')
    if type(instance_id) is not str or _INSTANCE_RE.fullmatch(instance_id) is None:
        raise ValueError('Invalid Gateway instance identity')
    if type(owner_id) is not str or _OWNER_RE.fullmatch(owner_id) is None:
        raise ValueError('Invalid Gateway owner identity')
    sidecar_ip = _validate_proxy_ip(instance.get('sidecar_ip'))
    origin = _validate_proxy_origin(instance.get('control_ui_origin'), instance_id)
    gateway.update({
        'publicOrigin': origin,
        'trustedProxies': [sidecar_ip],
        'controlUi': {'allowedOrigins': [origin]},
        'auth': {
            'mode': 'trusted-proxy',
            'identityScopes': {
                owner_id: ['operator.read', 'operator.write',
                           'operator.approvals', 'operator.questions',
                           'operator.pairing'],
            },
            'trustedProxy': {
                'userHeader': 'x-forwarded-user',
                'requiredHeaders': ['x-forwarded-proto', 'x-forwarded-host'],
                'allowUsers': [owner_id],
                'deviceAutoApprove': {'enabled': False},
            },
        },
    })
    return {
        'gateway': gateway,
        'plugins': {'entries': {'admin-http-rpc': {'enabled': True}}},
    }
