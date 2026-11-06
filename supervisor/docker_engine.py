"""Fail-closed Linux Docker Engine v1.45 client (stdlib only).

No Docker SDK, image pulls, agent-visible Docker socket or published agent ports.
Proxy IPAM uses bounded, read-only iproute2 probes. Production firewall activation is
injected from a host-bound acceptance receipt; direct/default construction stays
fail-closed. Legacy spec v1 remains the default and keeps NetworkMode=none.
"""
from dataclasses import asdict
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import stat
import time
from typing import Callable
from urllib.parse import quote, urlencode, urlsplit

from .config import AgentLimits
from .firewall import (
    EndpointPair, FirewallManager, NftablesAdapter, NetworkPolicy, validate_networks,
)
from .network_routes import HostIPv4Inventory, read_host_ipv4_networks


class DockerEngineError(RuntimeError):
    """Public errors contain fixed messages only; never daemon bodies or secrets."""
    code = 'docker_operation_failed'



class _HTTPError(DockerEngineError):
    def __init__(self, status):
        self.status = status
        super().__init__('Docker Engine rejected the operation')


class _BoundedSocket(socket.socket):
    """Bound headers+body and the entire exchange, including slow-drip reads."""
    def __init__(self, deadline):
        super().__init__(getattr(socket, 'AF_UNIX'), socket.SOCK_STREAM)
        self.deadline = deadline
        self.remaining = 65536

    def _timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.settimeout(remaining)

    def recv_into(self, buffer, nbytes=0, flags=0):
        self._timeout()
        # One extra byte detects oversized responses rather than truncating JSON.
        size = min(nbytes or memoryview(buffer).nbytes, self.remaining + 1)
        received = super().recv_into(buffer, size, flags)
        self.remaining -= received
        if self.remaining < 0:
            raise DockerEngineError('Docker Engine response exceeds the size limit')
        return received

    def sendall(self, data, flags=0):
        self._timeout()
        return super().sendall(data, flags)


class DockerEngine:
    API_VERSION = 'v1.45'
    TIMEOUT = 15.0
    MANAGED_LABEL = 'io.personal-agent.supervisor.managed'
    INSTANCE_LABEL = 'io.personal-agent.supervisor.instance'
    CONFIG_LABEL = 'io.personal-agent.supervisor.config-sha256'
    SPEC_LABEL = 'io.personal-agent.supervisor.spec'
    NETWORK_SCHEMA_LABEL = 'io.personal-agent.supervisor.network-spec'
    NETWORK_SCHEMA = 'internal-bridge-v1'
    NETWORK_PROFILE_LEGACY = 'legacy_none'
    NETWORK_PROFILE_PRIVATE = 'agent_internal_v1'
    NETWORK_PROFILE_PROXY = 'agent_proxy_v1'
    CONTROL_PLANE_LABEL = 'io.personal-agent.platform.control-plane'
    SIDECAR_ROLE_LABEL = 'io.personal-agent.supervisor.component'
    SIDECAR_ROLE = 'control-ui-proxy-v1'
    SIDECAR_SPEC_LABEL = 'io.personal-agent.supervisor.control-ui-spec'
    SIDECAR_CONFIG_LABEL = 'io.personal-agent.supervisor.control-ui-config-sha256'
    SIDECAR_RAM_BYTES = 128 * 1024 * 1024
    SIDECAR_CPU_NANO = 100_000_000
    SIDECAR_PIDS_LIMIT = 32
    SIDECAR_PORT = 18790
    SIDECAR_SAFE_IMAGE_ENV = frozenset({
        'PATH', 'PYTHONPATH', 'PYTHONUNBUFFERED', 'PYTHONDONTWRITEBYTECODE',
        'HOME', 'STATIC_DIR', 'LANG',
    })
    PROXY_TOKEN_FILE_HOST = '.control-ui-proxy-token'
    PROXY_TOKEN_FILE_CONTAINER = '/run/secrets/bezr-proxy-token'
    _SIDECAR_TOKEN = re.compile(r'[A-Za-z0-9_-]{40,64}\Z')

    _CONFIG_ONLY_CONTAINER_STATES = frozenset({'created', 'exited', 'dead'})
    _LIVE_NOT_READY_CONTAINER_STATES = frozenset({'paused', 'restarting'})
    _INSTANCE = re.compile(r'[0-9a-f]{32}\Z')
    _OBJECT = re.compile(r'[0-9a-f]{64}\Z')
    _IMAGE = re.compile(r'(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64})\Z')
    _ENV = {
        'HOME': '/home/node',
        'TMPDIR': '/tmp',
        'XDG_CACHE_HOME': '/tmp/cache',
        'OPENCLAW_HOME': '/home/node',
        'OPENCLAW_STATE_DIR': '/home/node/.openclaw',
        'OPENCLAW_CONFIG_PATH': '/home/node/.openclaw/openclaw.json',
        'OPENCLAW_CONFIG_DIR': '/home/node/.openclaw',
        'OPENCLAW_WORKSPACE_DIR': '/home/node/.openclaw/workspace',
        'OPENCLAW_GATEWAY_PORT': '18789',
        'OPENCLAW_DISABLE_BONJOUR': '1',
    }
    _CMD = ['node', 'dist/index.js', 'gateway', '--bind', 'lan', '--port', '18789']
    _HEALTH = {'Test': ['CMD', 'node', 'dist/docker-healthcheck.js'],
               'Interval': 30000000000, 'Timeout': 5000000000,
               'Retries': 5, 'StartPeriod': 30000000000, 'StartInterval': 5000000000}

    def __init__(self, image, engine_socket='/var/run/docker.sock', *,
                 agent_network_pool=None, frontend_network_pool=None,
                 firewall=None, host_route_provider: Callable[[], HostIPv4Inventory] | None = None):
        if not isinstance(image, str) or not self._IMAGE.fullmatch(image):
            raise ValueError('An explicit immutable Docker image digest is required')
        if (not isinstance(engine_socket, str) or not engine_socket.startswith('/')
                or '\x00' in engine_socket or len(engine_socket) > 4096):
            raise ValueError('An explicit Unix socket path is required')
        self.image = image
        self.engine_socket = engine_socket
        if (agent_network_pool is None) != (frontend_network_pool is None):
            raise ValueError('Both explicit proxy network pools are required together')
        if agent_network_pool is not None:
            agent_pool = self._proxy_pool(agent_network_pool)
            frontend_pool = self._proxy_pool(frontend_network_pool)
            if agent_pool.overlaps(frontend_pool):
                raise ValueError('Agent and frontend network pools must not overlap')
            self.agent_network_pool = str(agent_pool)
            self.frontend_network_pool = str(frontend_pool)
        else:
            self.agent_network_pool = None
            self.frontend_network_pool = None
        self.firewall = (firewall if firewall is not None else FirewallManager(
            NftablesAdapter(), semantics_validated=False))
        if host_route_provider is not None and not callable(host_route_provider):
            raise ValueError('Host route provider must be callable')
        self.host_route_provider = host_route_provider or read_host_ipv4_networks
        # Preserve Moby's default-deny sandbox and close quota-inheritance setters.
        # Dropped capabilities alone do not prevent an owner clearing PROJINHERIT.
        with Path(__file__).with_name('seccomp.json').open('rb') as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            raise ValueError('Invalid bundled seccomp policy')
        policy = json.loads(raw)
        if policy.get('defaultAction') != 'SCMP_ACT_ERRNO' or not isinstance(policy.get('syscalls'), list):
            raise ValueError('Default-deny seccomp policy required')
        self.seccomp = self._json(policy)

    @staticmethod
    def _json(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)

    @classmethod
    def _hash(cls, value):
        return hashlib.sha256(cls._json(value).encode('utf-8')).hexdigest()

    @classmethod
    def _instance(cls, instance_id):
        if not isinstance(instance_id, str) or not cls._INSTANCE.fullmatch(instance_id):
            raise ValueError('Instance ID must be exactly 32 lowercase hexadecimal characters')
        return instance_id

    @classmethod
    def _object(cls, object_id):
        if not isinstance(object_id, str) or not cls._OBJECT.fullmatch(object_id):
            raise DockerEngineError('Docker Engine returned an invalid object identity')
        return object_id

    @staticmethod
    def _container_status(observed):
        state = observed.get('State') if type(observed) is dict else None
        status = state.get('Status') if type(state) is dict else None
        if type(status) is not str or not status:
            raise ValueError('Docker container lifecycle state is unavailable')
        return status

    def _verify_proxy_endpoint(self, observed, network_name, network_id, ipv4):
        status = self._container_status(observed)
        settings = observed.get('NetworkSettings')
        networks = settings.get('Networks') if type(settings) is dict else None
        attached = networks.get(network_name) if type(networks) is dict else None
        if type(attached) is not dict:
            raise ValueError('Expected Docker network endpoint is unavailable')
        ipam = attached.get('IPAMConfig')
        configured_ip = ipam.get('IPv4Address') if type(ipam) is dict else None
        observed_network_id = attached.get('NetworkID')
        observed_ip = attached.get('IPAddress')
        if status == 'running' or status in self._LIVE_NOT_READY_CONTAINER_STATES:
            if (type(ipam) is not dict or configured_ip != ipv4
                    or observed_network_id != network_id or observed_ip != ipv4):
                raise ValueError('Live Docker network endpoint does not match policy')
        elif status in self._CONFIG_ONLY_CONTAINER_STATES:
            if (configured_ip != ipv4
                    or observed_network_id not in (None, '', network_id)
                    or observed_ip not in (None, '', ipv4)):
                raise ValueError('Created Docker network configuration does not match policy')
        else:
            raise ValueError('Docker container lifecycle state is not safe to verify')
        return status

    def _request(self, method, path, payload=None, *, ok=(200,)):
        """One bounded request. Deliberately no API negotiation or automatic pull."""
        connection = None
        stream = None
        try:
            data = None if payload is None else self._json(payload).encode('utf-8')
            if data is not None and len(data) > 65536:
                raise DockerEngineError('Docker Engine request exceeds the size limit')
            if not hasattr(socket, 'AF_UNIX'):
                raise DockerEngineError('Docker Engine Unix socket is unavailable')
            stream = _BoundedSocket(time.monotonic() + self.TIMEOUT)
            stream._timeout()
            stream.connect(self.engine_socket)
            connection = http.client.HTTPConnection('localhost', timeout=self.TIMEOUT)
            connection.sock = stream
            connection.request(method, '/' + self.API_VERSION + path, body=data,
                               headers={'Content-Type': 'application/json', 'Connection': 'close'})
            response = connection.getresponse()
            body = response.read(65537)
            if len(body) > 65536:
                raise DockerEngineError('Docker Engine response exceeds the size limit')
            if response.status not in ok:
                raise _HTTPError(response.status)
            if not body:
                return None
            return json.loads(body)
        except DockerEngineError:
            raise
        except (OSError, ValueError, http.client.HTTPException, RecursionError):
            raise DockerEngineError('Docker Engine communication failed') from None
        finally:
            if connection is not None:
                connection.close()
            if stream is not None:
                stream.close()

    @classmethod
    def _labels(cls, instance_id):
        return {cls.MANAGED_LABEL: 'true', cls.INSTANCE_LABEL: instance_id}

    @classmethod
    def _network_name(cls, instance_id):
        return 'pa-net-' + cls._instance(instance_id)

    @classmethod
    def _network_labels(cls, instance_id):
        return {**cls._labels(instance_id), cls.NETWORK_SCHEMA_LABEL: cls.NETWORK_SCHEMA}

    @classmethod
    def _network_payload(cls, instance_id):
        instance_id = cls._instance(instance_id)
        return {
            'Name': cls._network_name(instance_id),
            'Driver': 'bridge',
            'Internal': True,
            'Attachable': False,
            'EnableIPv6': False,
            'Labels': cls._network_labels(instance_id),
        }

    @staticmethod
    def _proxy_pool(value):
        if type(value) is not str:
            raise ValueError('An explicit IPv4 network pool is required')
        try:
            pool = ipaddress.IPv4Network(value, strict=True)
        except (ValueError, ipaddress.NetmaskValueError):
            raise ValueError('Invalid IPv4 network pool') from None
        private = tuple(ipaddress.IPv4Network(item) for item in (
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
        if pool.prefixlen > 24 or not any(pool.subnet_of(item) for item in private):
            raise ValueError('Network pool must be an RFC1918 IPv4 supernet with /29 capacity')
        return pool

    @classmethod
    def _proxy_network_plan(cls, instance_id, *, agent_network_pool,
                            frontend_network_pool, occupied_subnets=(), host_routes=()):
        """Choose isolated /29s and deterministic endpoint IPs from admin pools."""
        instance_id = cls._instance(instance_id)
        agent_pool = cls._proxy_pool(agent_network_pool)
        frontend_pool = cls._proxy_pool(frontend_network_pool)
        if agent_pool.overlaps(frontend_pool):
            raise ValueError('Agent and frontend network pools must not overlap')
        try:
            routes = tuple(ipaddress.IPv4Network(value, strict=True) for value in host_routes)
        except (ValueError, TypeError):
            raise ValueError('Invalid host route inventory') from None
        if len(routes) > 4096:
            raise ValueError('Host route inventory exceeds the safety limit')
        occupied = tuple(ipaddress.IPv4Network(value, strict=True)
                         for value in occupied_subnets)
        if len(occupied) > 4096:
            raise ValueError('Docker network inventory exceeds the safety limit')
        occupied = (*occupied, *(route for route in routes if route.prefixlen > 0))

        def allocate(pool):
            for candidate in pool.subnets(new_prefix=29):
                if not any(candidate.overlaps(other) for other in occupied):
                    return candidate
            raise DockerEngineError('No free per-agent subnet remains in the configured pool')

        agent_net = allocate(agent_pool)
        frontend_net = allocate(frontend_pool)

        def ip(network, offset):
            return str(network.network_address + offset)

        return {
            'agent': {
                'name': 'pa-agent-' + instance_id,
                'bridge': 'bza' + instance_id[:12],
                'subnet': str(agent_net),
                'gateway': ip(agent_net, 1),
                'sidecar_ip': ip(agent_net, 2),
                'gateway_ip': ip(agent_net, 3),
            },
            'frontend': {
                'name': 'pa-front-' + instance_id,
                'bridge': 'bzf' + instance_id[:12],
                'subnet': str(frontend_net),
                'gateway': ip(frontend_net, 1),
                'web_ip': ip(frontend_net, 2),
                'sidecar_ip': ip(frontend_net, 3),
            },
        }

    @classmethod
    def _proxy_network_payload(cls, instance_id, network, *, role):
        instance_id = cls._instance(instance_id)
        if role not in {'agent', 'frontend'} or type(network) is not dict:
            raise ValueError('Invalid proxy network role or plan')
        expected_keys = ({'name', 'bridge', 'subnet', 'gateway', 'sidecar_ip', 'gateway_ip'}
                         if role == 'agent' else
                         {'name', 'bridge', 'subnet', 'gateway', 'web_ip', 'sidecar_ip'})
        if set(network) != expected_keys:
            raise ValueError('Invalid proxy network plan')
        name = ('pa-agent-' if role == 'agent' else 'pa-front-') + instance_id
        bridge = ('bza' if role == 'agent' else 'bzf') + instance_id[:12]
        try:
            subnet = ipaddress.IPv4Network(network['subnet'], strict=True)
        except (ValueError, TypeError):
            raise ValueError('Invalid proxy network subnet') from None
        if subnet.prefixlen != 29:
            raise ValueError('Proxy networks must use /29 subnets')
        host = subnet.network_address
        expected = {
            'name': name, 'bridge': bridge, 'subnet': str(subnet),
            'gateway': str(host + 1),
            'sidecar_ip': str(host + (2 if role == 'agent' else 3)),
        }
        expected['gateway_ip' if role == 'agent' else 'web_ip'] = str(host + 3 if role == 'agent' else host + 2)
        if network != expected:
            raise ValueError('Proxy network plan identity or fixed IP mismatch')
        return {
            'Name': name, 'Driver': 'bridge', 'Internal': True,
            'Attachable': False, 'EnableIPv6': False,
            'IPAM': {'Driver': 'default', 'Config': [
                {'Subnet': str(subnet), 'Gateway': str(host + 1)}]},
            'Options': {
                'com.docker.network.bridge.name': bridge,
                'com.docker.network.bridge.enable_ip_masquerade': 'false',
                'com.docker.network.bridge.enable_icc': 'true',
            },
            'Labels': {
                **cls._labels(instance_id),
                cls.NETWORK_SCHEMA_LABEL: cls.NETWORK_PROFILE_PROXY + ':' + role,
            },
        }

    @classmethod
    def _proxy_network_from_observation(cls, instance_id, role, observed, pool):
        instance_id = cls._instance(instance_id)
        if role not in {'agent', 'frontend'} or type(observed) is not dict:
            raise DockerEngineError('Invalid proxy network observation')
        try:
            ipam = observed['IPAM']
            configs = ipam['Config']
            if (type(ipam) is not dict or ipam.get('Driver') != 'default'
                    or type(configs) is not list or len(configs) != 1
                    or type(configs[0]) is not dict
                    or set(configs[0]) != {'Subnet', 'Gateway'}):
                raise ValueError
            subnet = ipaddress.IPv4Network(configs[0]['Subnet'], strict=True)
            gateway = configs[0]['Gateway']
        except (KeyError, TypeError, ValueError):
            raise DockerEngineError('Proxy network IPAM verification failed') from None
        if subnet.prefixlen != 29 or not subnet.subnet_of(pool):
            raise DockerEngineError('Proxy network subnet is outside the configured pool')
        base = subnet.network_address
        plan = {
            'name': ('pa-agent-' if role == 'agent' else 'pa-front-') + instance_id,
            'bridge': ('bza' if role == 'agent' else 'bzf') + instance_id[:12],
            'subnet': str(subnet), 'gateway': str(base + 1),
            'sidecar_ip': str(base + (2 if role == 'agent' else 3)),
        }
        plan['gateway_ip' if role == 'agent' else 'web_ip'] = str(base + 3 if role == 'agent' else base + 2)
        expected = cls._proxy_network_payload(instance_id, plan, role=role)
        if (observed.get('Id') is None or observed.get('Name') != expected['Name']
                or observed.get('Driver') != 'bridge' or observed.get('Internal') is not True
                or observed.get('Attachable') is not False or observed.get('EnableIPv6') is not False
                or observed.get('Ingress') is not False or observed.get('Options') != expected['Options']
                or observed.get('Labels') != expected['Labels'] or gateway != str(base + 1)):
            raise DockerEngineError('Proxy network configuration verification failed')
        return plan

    def _find_control_plane_web(self, control_ui_domain):
        """Select one running labeled web container and pin its immutable image ID."""
        if type(control_ui_domain) is not str or len(control_ui_domain) > 253:
            raise DockerEngineError('Control Plane domain is invalid')
        labels = control_ui_domain.split('.')
        label_re = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        if len(labels) < 2 or any(re.fullmatch(label_re, label) is None for label in labels):
            raise DockerEngineError('Control Plane domain is invalid')
        filters = {'label': [self.CONTROL_PLANE_LABEL + '=true']}
        rows = self._request('GET', '/containers/json?' + urlencode(
            {'all': 'true', 'filters': self._json(filters)}))
        if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
            raise DockerEngineError('Exactly one labeled Control Plane container is required')
        container_id = self._object(rows[0].get('Id'))
        observed = self._request('GET', '/containers/' + container_id + '/json')
        if type(observed) is not dict or observed.get('Id') != container_id:
            raise DockerEngineError('Control Plane container identity verification failed')
        state = observed.get('State')
        config = observed.get('Config')
        if type(config) is not dict:
            raise DockerEngineError('Control Plane container configuration is invalid')
        labels = config.get('Labels')
        if (type(state) is not dict or state.get('Running') is not True
                or state.get('Status') != 'running' or type(labels) is not dict
                or labels.get(self.CONTROL_PLANE_LABEL) != 'true'):
            raise DockerEngineError('Control Plane container is not uniquely running and labeled')
        env = config.get('Env')
        if type(env) is not list or any(type(item) is not str or '=' not in item for item in env):
            raise DockerEngineError('Control Plane domain environment is invalid')
        domains = [item.split('=', 1)[1] for item in env
                   if item.split('=', 1)[0] == 'AGENT_CONTROL_UI_DOMAIN']
        if domains != [control_ui_domain]:
            raise DockerEngineError('Control Plane domain does not match configured domain')
        image_id = observed.get('Image')
        if type(image_id) is not str or re.fullmatch(r'sha256:[0-9a-f]{64}', image_id) is None:
            raise DockerEngineError('Control Plane image ID is not immutable')
        image = self._request('GET', '/images/' + quote(image_id, safe='') + '/json')
        if (type(image) is not dict or image.get('Id') != image_id
                or type(image.get('Config')) is not dict):
            raise DockerEngineError('Control Plane image ID failed verification')
        network_settings = observed.get('NetworkSettings')
        networks = network_settings.get('Networks') if type(network_settings) is dict else None
        if type(networks) is not dict or not networks:
            raise DockerEngineError('Control Plane network attachment is unavailable')
        return {'container_id': container_id, 'image_id': image_id,
                'networks': networks, 'image_info': image}

    def _discover_control_plane_image(self, control_ui_domain):
        return self._find_control_plane_web(control_ui_domain)['image_id']

    def _read_existing_proxy_token_file(self, host_path):
        host_path = self._host_path(host_path)
        nofollow = getattr(os, 'O_NOFOLLOW', None)
        directory_flag = getattr(os, 'O_DIRECTORY', None)
        if type(nofollow) is not int or type(directory_flag) is not int:
            raise DockerEngineError('Secure sidecar secret file access is unavailable')
        cloexec = getattr(os, 'O_CLOEXEC', 0)
        root_fd = file_fd = None
        try:
            root_fd = os.open(host_path, os.O_RDONLY | directory_flag | nofollow | cloexec)
            root_info = os.fstat(root_fd)
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                    or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700):
                raise DockerEngineError('Sidecar secret parent directory failed verification')
            file_fd = os.open(self.PROXY_TOKEN_FILE_HOST,
                              os.O_RDONLY | nofollow | cloexec, dir_fd=root_fd)
            info = os.fstat(file_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 1000 or info.st_gid != 1000
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 40 <= info.st_size <= 64):
                raise DockerEngineError('Sidecar secret file failed verification')
            raw = os.read(file_fd, 65)
            if len(raw) != info.st_size:
                raise DockerEngineError('Sidecar secret file read-back failed')
            try:
                token = raw.decode('ascii')
            except UnicodeError:
                raise DockerEngineError('Sidecar secret file failed verification') from None
            if self._SIDECAR_TOKEN.fullmatch(token) is None:
                raise DockerEngineError('Sidecar secret file failed verification')
            return token
        except DockerEngineError:
            raise
        except OSError:
            raise DockerEngineError('Sidecar secret file operation failed') from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if root_fd is not None:
                os.close(root_fd)

    def _ensure_proxy_token_file(self, host_path):
        """Create or verify a private system token, outside Gateway bind mounts."""
        host_path = self._host_path(host_path)
        nofollow = getattr(os, 'O_NOFOLLOW', None)
        directory_flag = getattr(os, 'O_DIRECTORY', None)
        if type(nofollow) is not int or type(directory_flag) is not int:
            raise DockerEngineError('Secure sidecar secret file access is unavailable')
        cloexec = getattr(os, 'O_CLOEXEC', 0)
        root_fd = file_fd = None
        try:
            root_fd = os.open(host_path, os.O_RDONLY | directory_flag | nofollow | cloexec)
            root_info = os.fstat(root_fd)
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                    or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700):
                raise DockerEngineError('Sidecar secret parent directory failed verification')
            fchown = getattr(os, 'fchown', None)
            fchmod = getattr(os, 'fchmod', None)
            if not callable(fchown) or not callable(fchmod):
                raise DockerEngineError('Secure sidecar secret ownership is unavailable')
            create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow | cloexec
            try:
                file_fd = os.open(self.PROXY_TOKEN_FILE_HOST, create_flags, 0o600,
                                  dir_fd=root_fd)
                token = secrets.token_urlsafe(32)
                if self._SIDECAR_TOKEN.fullmatch(token) is None:
                    raise DockerEngineError('Generated sidecar credential is invalid')
                fchown(file_fd, 1000, 1000)
                fchmod(file_fd, 0o600)
                raw = token.encode('ascii')
                view = memoryview(raw)
                while view:
                    written = os.write(file_fd, view)
                    if written <= 0:
                        raise DockerEngineError('Sidecar secret file write failed')
                    view = view[written:]
                os.fsync(file_fd)
                os.fsync(root_fd)
            except FileExistsError:
                file_fd = os.open(self.PROXY_TOKEN_FILE_HOST,
                                  os.O_RDONLY | nofollow | cloexec, dir_fd=root_fd)
            info = os.fstat(file_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 1000 or info.st_gid != 1000
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 40 <= info.st_size <= 64):
                raise DockerEngineError('Sidecar secret file failed verification')
            os.lseek(file_fd, 0, os.SEEK_SET)
            raw = os.read(file_fd, 65)
            if len(raw) != info.st_size:
                raise DockerEngineError('Sidecar secret file read-back failed')
            try:
                token = raw.decode('ascii')
            except UnicodeError:
                raise DockerEngineError('Sidecar secret file failed verification') from None
            if self._SIDECAR_TOKEN.fullmatch(token) is None:
                raise DockerEngineError('Sidecar secret file failed verification')
            return token
        except DockerEngineError:
            raise
        except OSError:
            raise DockerEngineError('Sidecar secret file operation failed') from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if root_fd is not None:
                os.close(root_fd)

    def proxy_network_policies(self):
        """Read every managed agent/frontend /29 pair for firewall readiness."""
        if (type(self.agent_network_pool) is not str
                or type(self.frontend_network_pool) is not str):
            raise DockerEngineError('Proxy network pools are unavailable')
        rows = self._request('GET', '/networks')
        if type(rows) is not list or len(rows) > 4096:
            raise DockerEngineError('Docker network inventory is invalid')
        grouped = {}
        for row in rows:
            if type(row) is not dict:
                raise DockerEngineError('Docker network inventory is invalid')
            name = row.get('Name')
            if type(name) is not str or not name.startswith(('pa-agent-', 'pa-front-')):
                continue
            match = re.fullmatch(r'pa-(agent|front)-([0-9a-f]{32})', name)
            labels = row.get('Labels')
            if match is None or type(labels) is not dict:
                raise DockerEngineError('Unrecognized proxy network in managed namespace')
            role = 'agent' if match.group(1) == 'agent' else 'frontend'
            instance_id = match.group(2)
            expected_labels = {
                self.MANAGED_LABEL: 'true', self.INSTANCE_LABEL: instance_id,
                self.NETWORK_SCHEMA_LABEL: self.NETWORK_PROFILE_PROXY + ':' + role,
            }
            if labels != expected_labels:
                raise DockerEngineError('Proxy network ownership labels failed verification')
            role_pool = self.agent_network_pool if role == 'agent' else self.frontend_network_pool
            network_id = self._object(row.get('Id'))
            observed = self._request('GET', '/networks/' + network_id)
            plan = self._proxy_network_from_observation(
                instance_id, role, observed, self._proxy_pool(role_pool))
            if observed.get('Id') != network_id or observed.get('Name') != name:
                raise DockerEngineError('Proxy network identity verification failed')
            roles = grouped.setdefault(instance_id, {})
            if role in roles:
                raise DockerEngineError('Duplicate proxy network role')
            roles[role] = plan
        policies = []
        for instance_id, roles in grouped.items():
            if set(roles) != {'agent', 'frontend'}:
                raise DockerEngineError('Proxy network pair is incomplete')
            policies.append(self._proxy_firewall_policy(instance_id, roles))
        return validate_networks(policies) if policies else ()

    def _proxy_firewall_policy(self, instance_id, plan):
        instance_id = self._instance(instance_id)
        if type(plan) is not dict or set(plan) != {'agent', 'frontend'}:
            raise ValueError('Invalid proxy network plan')
        agent = plan['agent']
        frontend = plan['frontend']
        self._proxy_network_payload(instance_id, agent, role='agent')
        self._proxy_network_payload(instance_id, frontend, role='frontend')
        return NetworkPolicy(
            instance_id, agent['subnet'], frontend['subnet'],
            agent['bridge'], frontend['bridge'],
            EndpointPair(agent['sidecar_ip'], agent['gateway_ip']),
            EndpointPair(frontend['web_ip'], frontend['sidecar_ip']))

    def _proxy_sidecar_payload(self, instance_id, *, owner_id, control_ui_origin,
                               gateway_ip, listen_ip, image_id, host_path, plan,
                               image_info=None):
        instance_id = self._instance(instance_id)
        host_path = self._host_path(host_path)
        if (type(owner_id) is not str or not 1 <= len(owner_id) <= 256
                or any(ord(char) <= 32 or ord(char) == 127 for char in owner_id)):
            raise ValueError('Invalid Control UI owner identity')
        if type(control_ui_origin) is not str or len(control_ui_origin) > 300:
            raise ValueError('Invalid per-instance Control UI origin')
        try:
            origin = urlsplit(control_ui_origin)
            labels = origin.hostname.split('.') if origin.hostname else []
        except (ValueError, AttributeError):
            raise ValueError('Invalid per-instance Control UI origin') from None
        label_re = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        if (origin.scheme != 'https' or not labels or labels[0] != instance_id
                or len(labels) < 3 or origin.netloc != origin.hostname
                or origin.path or origin.query or origin.fragment
                or any(re.fullmatch(label_re, label) is None for label in labels)):
            raise ValueError('Invalid per-instance Control UI origin')
        if (type(image_id) is not str or re.fullmatch(r'sha256:[0-9a-f]{64}', image_id) is None):
            raise ValueError('Sidecar requires an immutable image ID')
        if type(plan) is not dict or set(plan) != {'agent', 'frontend'}:
            raise ValueError('Invalid proxy network plan')
        self._proxy_network_payload(instance_id, plan['agent'], role='agent')
        self._proxy_network_payload(instance_id, plan['frontend'], role='frontend')
        try:
            gateway = ipaddress.IPv4Address(gateway_ip)
            listener = ipaddress.IPv4Address(listen_ip)
        except (ValueError, TypeError):
            raise ValueError('Invalid sidecar network address') from None
        if (str(gateway) != gateway_ip or str(listener) != listen_ip
                or gateway_ip != plan['agent']['gateway_ip']
                or listen_ip != plan['frontend']['sidecar_ip']):
            raise ValueError('Sidecar network address does not match its verified plan')
        frontend_name = plan['frontend']['name']
        spec = {
            'version': 1, 'image_id': image_id, 'owner_id': owner_id,
            'control_ui_origin': control_ui_origin,
            'gateway_ip': gateway_ip, 'listen_ip': listen_ip,
            'host_path': host_path, 'agent': plan['agent'], 'frontend': plan['frontend'],
        }
        labels = {
            self.INSTANCE_LABEL: instance_id, self.SIDECAR_ROLE_LABEL: self.SIDECAR_ROLE,
            self.SIDECAR_SPEC_LABEL: self._json(spec),
            self.SIDECAR_CONFIG_LABEL: self._hash(spec),
        }
        environment = {
            'BEZR_SIDECAR_OWNER_ID': owner_id,
            'BEZR_SIDECAR_PUBLIC_ORIGIN': control_ui_origin,
            'BEZR_SIDECAR_GATEWAY_IP': gateway_ip,
            'BEZR_SIDECAR_LISTEN_IP': listen_ip,
            'BEZR_SIDECAR_PROXY_TOKEN_FILE': '/run/secrets/bezr-proxy-token',
        }
        if image_info is None:
            image_info = self._request(
                'GET', '/images/' + quote(image_id, safe='') + '/json')
        image_config = image_info.get('Config') if type(image_info) is dict else None
        if (type(image_info) is not dict or image_info.get('Id') != image_id
                or type(image_config) is not dict):
            raise DockerEngineError('Sidecar image verification failed')
        inherited = image_config.get('Env')
        if inherited is None:
            inherited = []
        if (type(inherited) is not list
                or any(type(item) is not str or '=' not in item for item in inherited)):
            raise DockerEngineError('Invalid sidecar image environment')
        inherited_keys = [item.split('=', 1)[0] for item in inherited]
        if (any(not key or any(ord(char) <= 32 or ord(char) == 127 for char in key)
                for key in inherited_keys)
                or len(inherited_keys) != len(set(inherited_keys))):
            raise DockerEngineError('Duplicate or invalid sidecar image environment keys')
        unset_env = sorted(
            set(inherited_keys) - self.SIDECAR_SAFE_IMAGE_ENV - set(environment))
        return {
            'Image': image_id, 'User': '1000:1000', 'Entrypoint': ['python'],
            'Cmd': ['-m', 'control_plane.proxy_sidecar'], 'WorkingDir': '/app/backend',
            'Env': unset_env + [key + '=' + value for key, value in sorted(environment.items())],
            'Healthcheck': {
                'Test': ['CMD', 'python', '-m', 'control_plane.proxy_sidecar', '--healthcheck'],
                'Interval': 30_000_000_000, 'Timeout': 5_000_000_000,
                'Retries': 3, 'StartPeriod': 10_000_000_000,
            },
            'StopTimeout': 10, 'Tty': False, 'OpenStdin': False, 'StdinOnce': False,
            'Labels': labels,
            'HostConfig': {
                'Mounts': [{
                    'Type': 'bind',
                    'Source': host_path + '/' + self.PROXY_TOKEN_FILE_HOST,
                    'Target': self.PROXY_TOKEN_FILE_CONTAINER,
                    'ReadOnly': True,
                    'BindOptions': {'Propagation': 'rprivate', 'CreateMountpoint': False},
                }],
                'ReadonlyRootfs': True, 'Privileged': False,
                'CapDrop': ['ALL'], 'CapAdd': [],
                'SecurityOpt': ['no-new-privileges:true', 'seccomp=' + self.seccomp],
                'Memory': self.SIDECAR_RAM_BYTES, 'MemorySwap': self.SIDECAR_RAM_BYTES,
                'NanoCpus': self.SIDECAR_CPU_NANO, 'PidsLimit': self.SIDECAR_PIDS_LIMIT,
                'Init': True, 'Tmpfs': {
                    '/tmp': 'rw,nosuid,nodev,noexec,size=16m',
                    '/app/backend/data': 'rw,nosuid,nodev,noexec,size=4m',
                },
                'LogConfig': {'Type': 'none', 'Config': {}},
                'NetworkMode': frontend_name, 'PortBindings': {}, 'PublishAllPorts': False,
                'CgroupnsMode': 'private', 'IpcMode': 'private', 'Runtime': 'runc',
                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
            },
            'NetworkingConfig': {'EndpointsConfig': {
                frontend_name: {'IPAMConfig': {'IPv4Address': listen_ip}},
            }},
        }

    def _network_rows(self, instance_id):
        filters = {'name': [self._network_name(instance_id)]}
        rows = self._request('GET', '/networks?' + urlencode({'filters': self._json(filters)}))
        if type(rows) is not list or len(rows) > 1:
            raise DockerEngineError('Managed network identity is ambiguous')
        return rows

    def _verify_network(self, instance_id, network_id, *, expected_container_id=None):
        instance_id = self._instance(instance_id)
        network_id = self._object(network_id)
        network = self._request('GET', '/networks/' + network_id)
        if (type(network) is not dict
                or network.get('Id') != network_id
                or network.get('Name') != self._network_name(instance_id)
                or network.get('Driver') != 'bridge'
                or network.get('Internal') is not True
                or network.get('Attachable') is not False
                or network.get('EnableIPv6') is not False
                or network.get('Ingress') is not False
                or network.get('Labels') != self._network_payload(instance_id)['Labels']):
            raise DockerEngineError('Managed network configuration verification failed')
        containers = network.get('Containers') or {}
        if type(containers) is not dict:
            raise DockerEngineError('Managed network membership verification failed')
        expected = set() if expected_container_id is None else {self._object(expected_container_id)}
        if set(containers) != expected:
            raise DockerEngineError('Managed network membership verification failed')
        return network

    def ensure_instance_network(self, instance_id):
        """Create or verify the isolated internal network assigned to one instance."""
        instance_id = self._instance(instance_id)
        rows = self._network_rows(instance_id)
        if rows:
            row = rows[0]
            if type(row) is not dict:
                raise DockerEngineError('Invalid managed network observation')
            network_id = self._object(row.get('Id'))
        else:
            created = self._request('POST', '/networks/create', self._network_payload(instance_id), ok=(201,))
            if type(created) is not dict:
                raise DockerEngineError('Invalid managed network creation response')
            network_id = self._object(created.get('Id'))
        self._verify_network(instance_id, network_id)
        return self._network_name(instance_id)

    def remove_instance_network(self, instance_id):
        """Delete only the exact empty managed network for a removed instance."""
        instance_id = self._instance(instance_id)
        rows = self._network_rows(instance_id)
        if not rows:
            return
        row = rows[0]
        if type(row) is not dict:
            raise DockerEngineError('Invalid managed network observation')
        network_id = self._object(row.get('Id'))
        self._verify_network(instance_id, network_id)
        self._request('DELETE', '/networks/' + network_id, ok=(204,))
        if self._network_rows(instance_id):
            raise DockerEngineError('Managed network removal could not be verified')

    def _retained_proxy_network_has_foreign_host_route(
            self, inventory, instance_id, role, network_id, observed, plan):
        """Ignore only routes corroborated by a fully inspected BEZR Docker bridge."""
        if not isinstance(inventory, HostIPv4Inventory):
            raise DockerEngineError('Host IPv4 route inventory is unavailable')
        network_id = self._object(network_id)
        expected = self._proxy_network_payload(instance_id, plan, role=role)
        if (type(observed) is not dict or observed.get('Id') != network_id
                or observed.get('Name') != expected['Name']
                or observed.get('Labels') != expected['Labels']
                or observed.get('Options') != expected['Options']):
            raise DockerEngineError('Retained proxy Docker network identity failed verification')
        subnet = ipaddress.IPv4Network(expected['IPAM']['Config'][0]['Subnet'])
        bridge = expected['Options']['com.docker.network.bridge.name']
        gateway = expected['IPAM']['Config'][0]['Gateway']
        gateway_address_present = any(
            address.ifname == bridge and address.local == gateway
            and address.prefixlen == subnet.prefixlen
            for address in inventory.addresses)
        for address in inventory.addresses:
            address_network = ipaddress.IPv4Network(address.network)
            if not address_network.overlaps(subnet):
                continue
            if (gateway_address_present and address.ifname == bridge
                    and address.local == gateway and address.prefixlen == subnet.prefixlen):
                continue
            return True
        for route in inventory.routes:
            route_network = ipaddress.IPv4Network(route.network)
            if not route_network.overlaps(subnet):
                continue
            if (not gateway_address_present or route.interface != bridge
                    or route.protocol != 'kernel'
                    or route.prefsrc not in (None, gateway)):
                return True
            if (route_network == subnet and route.scope == 'link'
                    and route.route_type in (None, 'unicast')):
                continue
            local_gateway_route = ipaddress.IPv4Network(gateway + '/32')
            if (route_network == local_gateway_route and route.route_type == 'local'
                    and route.scope == 'host'):
                continue
            broadcast_routes = {
                ipaddress.IPv4Network(str(address) + '/32')
                for address in (subnet.network_address, subnet.broadcast_address)
            }
            if (route_network in broadcast_routes and route.route_type == 'broadcast'
                    and route.scope == 'link'):
                continue
            return True
        return False

    def ensure_proxy_networks(self, instance_id, *, agent_network_pool, frontend_network_pool):
        """Create or reuse exact per-agent /29 networks without changing retained IPAM."""
        instance_id = self._instance(instance_id)
        agent_pool = self._proxy_pool(agent_network_pool)
        frontend_pool = self._proxy_pool(frontend_network_pool)
        try:
            host_inventory = self.host_route_provider()
            if not isinstance(host_inventory, HostIPv4Inventory):
                raise ValueError
        except Exception:
            raise DockerEngineError('Host IPv4 route inventory is unavailable') from None
        rows = self._request('GET', '/networks')
        if type(rows) is not list or len(rows) > 4096:
            raise DockerEngineError('Docker network inventory is invalid')
        occupied = []
        by_name = {}
        for row in rows:
            if type(row) is not dict:
                raise DockerEngineError('Docker network inventory is invalid')
            if type(row.get('Name')) is str:
                if row['Name'] in by_name:
                    raise DockerEngineError('Docker network names are ambiguous')
                by_name[row['Name']] = row
            ipam = row.get('IPAM') or {}
            config = ipam.get('Config') or [] if type(ipam) is dict else []
            if type(config) is not list:
                raise DockerEngineError('Docker network inventory is invalid')
            for item in config:
                if type(item) is dict and type(item.get('Subnet')) is str:
                    occupied.append(item['Subnet'])
        names = {'agent': 'pa-agent-' + instance_id,
                 'frontend': 'pa-front-' + instance_id}
        plan = {}
        existing_ids = {}
        for role in ('agent', 'frontend'):
            row = by_name.get(names[role])
            if row is None:
                continue
            network_id = self._object(row.get('Id'))
            observed = self._request('GET', '/networks/' + network_id)
            role_pool = agent_pool if role == 'agent' else frontend_pool
            plan[role] = self._proxy_network_from_observation(
                instance_id, role, observed, role_pool)
            if self._retained_proxy_network_has_foreign_host_route(
                    host_inventory, instance_id, role, network_id, observed, plan[role]):
                raise DockerEngineError('Retained proxy subnet overlaps a host route')
            existing_ids[role] = network_id
        if len(plan) != 2:
            allocated = self._proxy_network_plan(
                instance_id, agent_network_pool=str(agent_pool),
                frontend_network_pool=str(frontend_pool), occupied_subnets=occupied,
                host_routes=host_inventory.networks)
            for role in ('agent', 'frontend'):
                if role not in plan:
                    plan[role] = allocated[role]
        created = []
        try:
            for role in ('agent', 'frontend'):
                expected = self._proxy_network_payload(instance_id, plan[role], role=role)
                network_id = existing_ids.get(role)
                if network_id is None:
                    result = self._request('POST', '/networks/create', expected, ok=(201,))
                    if type(result) is not dict:
                        raise DockerEngineError('Invalid proxy network creation response')
                    network_id = self._object(result.get('Id'))
                    created.append(network_id)
                observed = self._request('GET', '/networks/' + network_id)
                role_pool = agent_pool if role == 'agent' else frontend_pool
                actual_plan = self._proxy_network_from_observation(
                    instance_id, role, observed, role_pool)
                if actual_plan != plan[role]:
                    raise DockerEngineError('Proxy network postcondition verification failed')
        except Exception:
            for network_id in reversed(created):
                try:
                    self._request('DELETE', '/networks/' + network_id, ok=(204,))
                except Exception:
                    pass
            raise
        return plan

    def remove_proxy_networks(self, instance_id):
        """Purge only exact empty proxy networks, after a complete read-only preflight."""
        instance_id = self._instance(instance_id)
        verified = []
        for role, name_prefix in (('agent', 'pa-agent-'), ('frontend', 'pa-front-')):
            name = name_prefix + instance_id
            rows = self._request('GET', '/networks?' + urlencode(
                {'filters': self._json({'name': [name]})}))
            if type(rows) is not list or len(rows) > 1:
                raise DockerEngineError('Proxy network identity is ambiguous')
            if not rows:
                continue
            row = rows[0]
            if type(row) is not dict:
                raise DockerEngineError('Invalid proxy network observation')
            network_id = self._object(row.get('Id'))
            observed = self._request('GET', '/networks/' + network_id)
            pool = self.agent_network_pool if role == 'agent' else self.frontend_network_pool
            if type(pool) is not str:
                raise DockerEngineError('Proxy network pools are unavailable')
            plan = self._proxy_network_from_observation(
                instance_id, role, observed, self._proxy_pool(pool))
            if (observed.get('Id') != network_id or observed.get('Name') != name
                    or observed.get('Containers') not in ({}, None)):
                raise DockerEngineError('Proxy network removal verification failed')
            verified.append((role, name, network_id, plan))
        firewall = self.firewall
        apply_policy = getattr(firewall, 'apply', None)
        if getattr(firewall, 'can_apply', False) is not True or not callable(apply_policy):
            raise DockerEngineError('Firewall policy manager is unavailable for network purge')
        for role, name, network_id, _plan in verified:
            self._request('DELETE', '/networks/' + network_id, ok=(204,))
            remaining = self._request('GET', '/networks?' + urlencode(
                {'filters': self._json({'name': [name]})}))
            if type(remaining) is not list or remaining:
                raise DockerEngineError('Proxy network removal could not be verified')
        try:
            current_policies = tuple(self.proxy_network_policies())
            remaining_policies = validate_networks(current_policies) if current_policies else ()
            apply_policy(remaining_policies)
        except Exception:
            raise DockerEngineError('Firewall policy cleanup could not be verified') from None

    def _verify_proxy_network_membership(self, instance_id, role, network_id,
                                         expected_plan, expected_container_ids, *,
                                         expected_ips, allow_unstarted=False):
        instance_id = self._instance(instance_id)
        network_id = self._object(network_id)
        if (role not in {'agent', 'frontend'} or type(expected_container_ids) is not set
                or type(expected_ips) is not dict or type(allow_unstarted) is not bool):
            raise ValueError('Invalid proxy network membership request')
        expected_ids = {self._object(item) for item in expected_container_ids}
        if set(expected_ips) != expected_ids:
            raise ValueError('Proxy network endpoint identities are incomplete')
        for address in expected_ips.values():
            if type(address) is not str:
                raise ValueError('Invalid expected proxy network address')
            try:
                canonical = str(ipaddress.IPv4Address(address))
            except ValueError:
                raise ValueError('Invalid expected proxy network address') from None
            if canonical != address:
                raise ValueError('Invalid expected proxy network address')
        pool = self.agent_network_pool if role == 'agent' else self.frontend_network_pool
        if type(pool) is not str:
            raise DockerEngineError('Proxy network pools are unavailable')
        observed = self._request('GET', '/networks/' + network_id)
        if type(observed) is not dict or observed.get('Id') != network_id:
            raise DockerEngineError('Proxy network identity verification failed')
        actual_plan = self._proxy_network_from_observation(
            instance_id, role, observed, self._proxy_pool(pool))
        if actual_plan != expected_plan:
            raise DockerEngineError('Proxy network plan verification failed')
        raw_containers = observed.get('Containers')
        containers = {} if raw_containers is None else raw_containers
        if type(containers) is not dict:
            raise DockerEngineError('Proxy network membership verification failed')
        actual_ids = set(containers)
        if actual_ids - expected_ids:
            raise DockerEngineError('Proxy network has an unexpected container participant')
        if not allow_unstarted and actual_ids != expected_ids:
            raise DockerEngineError('Proxy network membership verification failed')
        for container_id in expected_ids:
            member = containers.get(container_id)
            container = self._request('GET', '/containers/' + container_id + '/json')
            if type(container) is not dict or container.get('Id') != container_id:
                raise DockerEngineError('Proxy network participant identity verification failed')
            try:
                status = self._verify_proxy_endpoint(
                    container, expected_plan['name'], network_id, expected_ips[container_id])
            except (ValueError, KeyError, TypeError):
                raise DockerEngineError('Proxy network participant endpoint verification failed') from None
            if status == 'running' or status in self._LIVE_NOT_READY_CONTAINER_STATES:
                if container_id not in actual_ids or type(member) is not dict:
                    raise DockerEngineError('Live proxy participant is absent from its network')
                member_address = member.get('IPv4Address')
                if type(member_address) is not str:
                    raise DockerEngineError('Live proxy participant network address is unavailable')
                try:
                    member_ip = str(ipaddress.ip_interface(member_address).ip)
                except ValueError:
                    raise DockerEngineError('Live proxy participant network address is invalid') from None
                if member_ip != expected_ips[container_id]:
                    raise DockerEngineError('Live proxy participant network address drifted')
            elif status in self._CONFIG_ONLY_CONTAINER_STATES and allow_unstarted:
                if container_id in actual_ids:
                    if type(member) is not dict:
                        raise DockerEngineError('Proxy participant network metadata is invalid')
                    member_address = member.get('IPv4Address')
                    if member_address not in (None, ''):
                        if type(member_address) is not str:
                            raise DockerEngineError('Proxy participant network address is invalid')
                        try:
                            member_ip = str(ipaddress.ip_interface(member_address).ip)
                        except ValueError:
                            raise DockerEngineError('Proxy participant network address is invalid') from None
                        if member_ip != expected_ips[container_id]:
                            raise DockerEngineError('Proxy participant network address drifted')
            else:
                raise DockerEngineError('Proxy network is not in a safe lifecycle state')
        return observed

    def _existing_proxy_network(self, instance_id, role):
        instance_id = self._instance(instance_id)
        if role not in {'agent', 'frontend'}:
            raise ValueError('Invalid proxy network role')
        name = ('pa-agent-' if role == 'agent' else 'pa-front-') + instance_id
        rows = self._request('GET', '/networks?' + urlencode(
            {'filters': self._json({'name': [name]})}))
        if type(rows) is not list or len(rows) > 1:
            raise DockerEngineError('Proxy network identity is ambiguous')
        if not rows:
            return None
        if type(rows[0]) is not dict:
            raise DockerEngineError('Invalid proxy network observation')
        network_id = self._object(rows[0].get('Id'))
        observed = self._request('GET', '/networks/' + network_id)
        pool = self.agent_network_pool if role == 'agent' else self.frontend_network_pool
        if type(pool) is not str or type(observed) is not dict:
            raise DockerEngineError('Proxy network verification is unavailable')
        plan = self._proxy_network_from_observation(
            instance_id, role, observed, self._proxy_pool(pool))
        if observed.get('Id') != network_id or observed.get('Name') != name:
            raise DockerEngineError('Proxy network identity verification failed')
        return network_id, plan, observed

    def _proxy_network_id(self, instance_id, role, expected):
        instance_id = self._instance(instance_id)
        if role not in {'agent', 'frontend'}:
            raise ValueError('Invalid proxy network role')
        name = ('pa-agent-' if role == 'agent' else 'pa-front-') + instance_id
        rows = self._request('GET', '/networks?' + urlencode(
            {'filters': self._json({'name': [name]})}))
        if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
            raise DockerEngineError('Proxy network identity is ambiguous')
        network_id = self._object(rows[0].get('Id'))
        observed = self._request('GET', '/networks/' + network_id)
        pool = self.agent_network_pool if role == 'agent' else self.frontend_network_pool
        if type(pool) is not str:
            raise DockerEngineError('Proxy network pools are unavailable')
        actual = self._proxy_network_from_observation(
            instance_id, role, observed, self._proxy_pool(pool))
        if actual != expected:
            raise DockerEngineError('Proxy network does not match the prepared plan')
        return network_id

    def prepare_control_ui(self, instance_id, owner_id, control_ui_domain, host_path):
        """Create verified, stopped sidecar resources for one explicit proxy instance."""
        instance_id = self._instance(instance_id)
        if type(self.agent_network_pool) is not str or type(self.frontend_network_pool) is not str:
            raise DockerEngineError('Explicit proxy network pools are required')
        if (type(control_ui_domain) is not str or len(control_ui_domain) > 253
                or type(owner_id) is not str):
            raise DockerEngineError('Control UI instance configuration is invalid')
        origin = f'https://{instance_id}.{control_ui_domain}'
        firewall_ready = getattr(self.firewall, 'ready', None)
        firewall_apply = getattr(self.firewall, 'apply', None)
        if (not callable(firewall_ready) or not callable(firewall_apply)
                or getattr(self.firewall, 'can_apply', False) is not True):
            raise DockerEngineError('Per-agent firewall readiness is unavailable')
        plan = self.ensure_proxy_networks(
            instance_id, agent_network_pool=self.agent_network_pool,
            frontend_network_pool=self.frontend_network_pool)
        policies = self.proxy_network_policies()
        firewall_apply(policies)
        if firewall_ready(policies) is not True:
            raise DockerEngineError('Per-agent firewall policy is not ready')
        self._ensure_proxy_token_file(host_path)
        web = self._find_control_plane_web(control_ui_domain)
        if any(type(name) is str and name.startswith('pa-agent-')
               for name in web['networks']):
            raise DockerEngineError('Control Plane is attached to an agent network')
        network_ids = {
            role: self._proxy_network_id(instance_id, role, plan[role])
            for role in ('agent', 'frontend')
        }
        self._ensure_container_network(
            web['container_id'], network_ids['frontend'], plan['frontend']['name'],
            plan['frontend']['web_ip'])
        payload = self._proxy_sidecar_payload(
            instance_id, owner_id=owner_id, control_ui_origin=origin,
            gateway_ip=plan['agent']['gateway_ip'],
            listen_ip=plan['frontend']['sidecar_ip'], image_id=web['image_id'],
            host_path=host_path, plan=plan, image_info=web['image_info'])
        sidecar_id = self._create_proxy_sidecar(instance_id, payload, plan, network_ids)
        expected_agent_ids = {self._object(sidecar_id)}
        expected_agent_ips = {self._object(sidecar_id): plan['agent']['sidecar_ip']}
        gateway = self._find(instance_id)
        if gateway is not None:
            gateway_id = self._verify(instance_id, gateway)
            expected_agent_ids.add(gateway_id)
            expected_agent_ips[gateway_id] = plan['agent']['gateway_ip']
        self._verify_proxy_network_membership(
            instance_id, 'agent', network_ids['agent'], plan['agent'], expected_agent_ids,
            expected_ips=expected_agent_ips, allow_unstarted=True)
        self._verify_proxy_network_membership(
            instance_id, 'frontend', network_ids['frontend'], plan['frontend'],
            {web['container_id'], sidecar_id},
            expected_ips={web['container_id']: plan['frontend']['web_ip'],
                          sidecar_id: plan['frontend']['sidecar_ip']},
            allow_unstarted=True)
        return {'sidecar_ip': plan['agent']['sidecar_ip'],
                'agent_subnet': plan['agent']['subnet'],
                'control_ui_origin': origin}

    def _verify_proxy_sidecar(self, instance_id, observed, expected, plan, network_ids):
        try:
            self._instance(instance_id)
            container_id = self._object(observed['Id'])
            config = observed['Config']
            host = observed['HostConfig']
            labels = config['Labels']
            if (observed.get('Image') != expected['Image']
                    or any(labels.get(key) != value for key, value in expected['Labels'].items())):
                raise ValueError
            for key in ('User', 'Entrypoint', 'Cmd', 'WorkingDir', 'StopTimeout'):
                if config.get(key) != expected.get(key):
                    raise ValueError
            health = config.get('Healthcheck') or {}
            wanted_health = expected['Healthcheck']
            for key in ('Test', 'Interval', 'Timeout', 'Retries', 'StartPeriod'):
                if health.get(key) != wanted_health.get(key):
                    raise ValueError
            env_items = config.get('Env') or []
            if (type(env_items) is not list
                    or any(type(item) is not str or not item.split('=', 1)[0]
                           for item in env_items)
                    or len({item.split('=', 1)[0] for item in env_items}) != len(env_items)):
                raise ValueError
            env = dict(item.split('=', 1) for item in env_items if '=' in item)
            observed_unset = {item for item in env_items if '=' not in item}
            expected_env_items = expected.get('Env')
            if type(expected_env_items) is not list:
                raise ValueError
            expected_keys = []
            expected_assignments = []
            unset_env = []
            for item in expected_env_items:
                if type(item) is not str:
                    raise ValueError
                key, separator, value = item.partition('=')
                if (not key or any(ord(char) <= 32 or ord(char) == 127 for char in key)):
                    raise ValueError
                expected_keys.append(key)
                if separator:
                    expected_assignments.append((key, value))
                else:
                    unset_env.append(key)
            if (len(expected_keys) != len(set(expected_keys))
                    or set(unset_env).intersection(self.SIDECAR_SAFE_IMAGE_ENV)):
                raise ValueError
            wanted_env = dict(expected_assignments)
            if any(env.get(key) != value for key, value in wanted_env.items()):
                raise ValueError
            if observed_unset - set(unset_env):
                raise ValueError
            if set(env).intersection(unset_env):
                raise ValueError
            if (set(env) - set(wanted_env) - self.SIDECAR_SAFE_IMAGE_ENV
                    or 'BEZR_SIDECAR_PROXY_TOKEN' in env
                    or 'WEBUI_SECRET_KEY' in env):
                raise ValueError
            expected_host = expected['HostConfig']
            for key in ('ReadonlyRootfs', 'Privileged', 'CapDrop', 'CapAdd',
                        'Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit', 'Init',
                        'Tmpfs', 'NetworkMode', 'PublishAllPorts', 'RestartPolicy'):
                if host.get(key) != expected_host.get(key):
                    raise ValueError
            if (host.get('PortBindings') or host.get('Devices') or host.get('Binds')
                    or host.get('VolumesFrom') or host.get('NetworkMode') != plan['frontend']['name']):
                raise ValueError
            security = host.get('SecurityOpt') or []
            if (type(security) is not list
                    or set(security) != set(expected_host['SecurityOpt'])):
                raise ValueError
            mounts = observed.get('Mounts')
            if type(mounts) is not list:
                raise ValueError
            expected_source = expected_host['Mounts'][0]['Source']
            secret_mounts = [mount for mount in mounts
                             if type(mount) is dict
                             and mount.get('Destination') == self.PROXY_TOKEN_FILE_CONTAINER]
            if (len(secret_mounts) != 1 or secret_mounts[0].get('Type') != 'bind'
                    or secret_mounts[0].get('Source') != expected_source
                    or secret_mounts[0].get('RW') is not False):
                raise ValueError
            if any(type(mount) is not dict or mount.get('Type') == 'volume'
                   or mount.get('Destination') not in {
                       self.PROXY_TOKEN_FILE_CONTAINER, '/tmp', '/app/backend/data'}
                   for mount in mounts):
                raise ValueError
            settings = observed.get('NetworkSettings') or {}
            networks = settings.get('Networks') or {}
            if type(networks) is not dict or set(networks) != {
                    plan['agent']['name'], plan['frontend']['name']}:
                raise ValueError
            for role in ('agent', 'frontend'):
                name = plan[role]['name']
                expected_ip = plan[role]['sidecar_ip']
                self._verify_proxy_endpoint(
                    observed, name, network_ids[role], expected_ip)
            if any((settings.get('Ports') or {}).values()):
                raise ValueError
            return container_id
        except (ValueError, KeyError, TypeError, AttributeError, IndexError):
            raise DockerEngineError('Proxy sidecar configuration verification failed') from None

    def _create_proxy_sidecar(self, instance_id, payload, plan, network_ids):
        instance_id = self._instance(instance_id)
        existing = self._find_proxy_sidecar(instance_id)
        if existing is not None:
            return self._verify_proxy_sidecar(instance_id, existing, payload, plan, network_ids)
        try:
            result = self._request('POST', '/containers/create?' + urlencode(
                {'name': 'pa-proxy-' + instance_id}), payload, ok=(201,))
            if type(result) is not dict:
                raise DockerEngineError('Invalid proxy sidecar creation response')
            container_id = self._object(result.get('Id'))
        except DockerEngineError:
            # A response may be lost after Docker created the container. Adopt
            # only the exact role-labelled container after complete verification.
            existing = self._find_proxy_sidecar(instance_id)
            if existing is None:
                raise DockerEngineError('Proxy sidecar creation failed') from None
            return self._verify_proxy_sidecar(instance_id, existing, payload, plan, network_ids)
        try:
            self._ensure_container_network(
                container_id, network_ids['agent'], plan['agent']['name'],
                plan['agent']['sidecar_ip'])
            existing = self._find_proxy_sidecar(instance_id)
            if existing is None or existing.get('Id') != container_id:
                raise DockerEngineError('Proxy sidecar creation could not be verified')
            return self._verify_proxy_sidecar(instance_id, existing, payload, plan, network_ids)
        except Exception:
            try:
                self._request('DELETE', '/containers/' + container_id + '?force=true', ok=(204,))
                if self._find_proxy_sidecar(instance_id) is not None:
                    raise DockerEngineError('Proxy sidecar cleanup could not be verified')
            except Exception:
                raise DockerEngineError('Proxy sidecar partial creation cleanup failed') from None
            raise DockerEngineError('Proxy sidecar creation verification failed') from None

    def _ensure_container_network(self, container_id, network_id, network_name, ipv4):
        container_id = self._object(container_id)
        network_id = self._object(network_id)
        try:
            address = ipaddress.IPv4Address(ipv4)
        except (ValueError, TypeError):
            raise ValueError('Static IPv4 endpoint required') from None
        if str(address) != ipv4:
            raise ValueError('Static IPv4 endpoint required')
        observed = self._request('GET', '/containers/' + container_id + '/json')
        if type(observed) is not dict or observed.get('Id') != container_id:
            raise DockerEngineError('Container identity verification failed')
        settings = observed.get('NetworkSettings')
        networks = settings.get('Networks') if type(settings) is dict else None
        if type(networks) is not dict:
            raise DockerEngineError('Container network inspection is unavailable')
        attached = networks.get(network_name)
        if attached is None:
            self._request('POST', '/networks/' + network_id + '/connect', {
                'Container': container_id,
                'EndpointConfig': {'IPAMConfig': {'IPv4Address': ipv4}},
            }, ok=(200,))
            observed = self._request('GET', '/containers/' + container_id + '/json')
            if type(observed) is not dict or observed.get('Id') != container_id:
                raise DockerEngineError('Container identity verification failed after network connect')
            settings = observed.get('NetworkSettings')
            networks = settings.get('Networks') if type(settings) is dict else None
            attached = networks.get(network_name) if type(networks) is dict else None
        try:
            self._verify_proxy_endpoint(observed, network_name, network_id, ipv4)
        except ValueError:
            raise DockerEngineError('Static container network endpoint verification failed') from None
        return observed

    def _find_proxy_sidecar(self, instance_id):
        instance_id = self._instance(instance_id)
        filters = {'label': [
            f'{self.INSTANCE_LABEL}={instance_id}',
            f'{self.SIDECAR_ROLE_LABEL}={self.SIDECAR_ROLE}',
        ]}
        rows = self._request('GET', '/containers/json?' + urlencode(
            {'all': 'true', 'filters': self._json(filters)}))
        if type(rows) is not list or len(rows) > 1:
            raise DockerEngineError('Proxy sidecar identity is ambiguous')
        if not rows:
            return None
        row = rows[0]
        if type(row) is not dict:
            raise DockerEngineError('Invalid proxy sidecar observation')
        container_id = self._object(row.get('Id'))
        observed = self._request('GET', '/containers/' + container_id + '/json')
        config = observed.get('Config') if type(observed) is dict else None
        labels = config.get('Labels') if type(config) is dict else None
        if (type(observed) is not dict or observed.get('Id') != container_id
                or type(labels) is not dict
                or labels.get(self.INSTANCE_LABEL) != instance_id
                or labels.get(self.SIDECAR_ROLE_LABEL) != self.SIDECAR_ROLE):
            raise DockerEngineError('Proxy sidecar ownership verification failed')
        return observed

    def _find(self, instance_id):

        filters = {'label': [f'{k}={v}' for k, v in self._labels(instance_id).items()]}
        rows = self._request('GET', '/containers/json?' + urlencode(
            {'all': 'true', 'filters': self._json(filters)}))
        if not isinstance(rows, list) or len(rows) > 1:
            raise DockerEngineError('Managed container identity is ambiguous')
        if not rows:
            return None
        row = rows[0]
        if not isinstance(row, dict):
            raise DockerEngineError('Invalid managed container observation')
        container_id = self._object(row.get('Id'))
        result = self._request('GET', f'/containers/{container_id}/json')
        if not isinstance(result, dict) or result.get('Id') != container_id:
            raise DockerEngineError('Managed container identity verification failed')
        config = result.get('Config')
        labels = config.get('Labels') if isinstance(config, dict) else None
        if (not isinstance(labels, dict)
                or any(labels.get(k) != v for k, v in self._labels(instance_id).items())):
            raise DockerEngineError('Managed container ownership verification failed')
        return result

    def check_host(self):
        info = self._request('GET', '/info')
        required = ('MemoryLimit', 'SwapLimit', 'CpuCfsPeriod', 'CpuCfsQuota', 'PidsLimit')
        if (not isinstance(info, dict) or info.get('OSType') != 'linux'
                or any(info.get(key) is not True for key in required)
                or not any(isinstance(value, str) and value.startswith('name=seccomp')
                           for value in info.get('SecurityOptions', []))):
            raise DockerEngineError('Required Linux cgroup and seccomp support is unavailable')
        return True

    def _image_info(self):
        self.check_host()
        info = self._request('GET', '/images/' + quote(self.image, safe='') + '/json')
        if not isinstance(info, dict) or not isinstance(info.get('Config'), dict):
            raise DockerEngineError('The pinned Docker image is unavailable')
        self._object(info.get('Id', '').removeprefix('sha256:'))
        if self.image.startswith('sha256:'):
            matches = info['Id'] == self.image
        else:
            matches = self.image in (info.get('RepoDigests') or [])
        if not matches or info['Config'].get('Volumes'):
            raise DockerEngineError('The pinned Docker image failed verification')
        return info

    @staticmethod
    def _host_path(host_path):
        if (not isinstance(host_path, str) or len(host_path) > 4096
                or re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', host_path) is None
                or '..' in PurePosixPath(host_path).parts
                or str(PurePosixPath(host_path)) != host_path):
            raise ValueError('A canonical non-root POSIX instance directory is required')
        return host_path

    @staticmethod
    def _limits(limits):
        if type(limits) is not AgentLimits:
            raise ValueError('Typed AgentLimits are required')
        for value in asdict(limits).values():
            if type(value) is not int or not 0 < value <= 2**63 - 1:
                raise ValueError('Agent limits must be positive bounded integers')
        if limits.cpu_millicores > (2**63 - 1) // 1000000:
            raise ValueError('CPU limit exceeds Docker NanoCpus range')
        return asdict(limits)

    def _spec(self, host_path, limits, *, version=2, instance_id=None, proxy_network=None,
              owner_id=None, control_ui_origin=None):
        if type(version) is not int or version not in (1, 2, 3):
            raise ValueError('Unsupported managed container spec version')
        spec = {'version': version, 'image': self.image,
                'host_path': self._host_path(host_path), 'limits': self._limits(limits)}
        if version == 3:
            instance_id = self._instance(instance_id)
            if type(proxy_network) is not dict:
                raise ValueError('Proxy network plan is required for proxy profile')
            self._proxy_network_payload(instance_id, proxy_network, role='agent')
            if (type(owner_id) is not str or not 1 <= len(owner_id) <= 256
                    or any(ord(char) <= 32 or ord(char) == 127 for char in owner_id)):
                raise ValueError('Invalid Control UI owner identity')
            if type(control_ui_origin) is not str or len(control_ui_origin) > 300:
                raise ValueError('Invalid per-instance Control UI origin')
            try:
                origin = urlsplit(control_ui_origin)
                labels = origin.hostname.split('.') if origin.hostname else []
            except (ValueError, AttributeError):
                raise ValueError('Invalid per-instance Control UI origin') from None
            label_re = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
            if (origin.scheme != 'https' or not labels or labels[0] != instance_id
                    or len(labels) < 3 or origin.netloc != origin.hostname
                    or origin.path or origin.query or origin.fragment
                    or any(re.fullmatch(label_re, label) is None for label in labels)):
                raise ValueError('Invalid per-instance Control UI origin')
            spec.update(proxy_network=dict(proxy_network), owner_id=owner_id,
                        control_ui_origin=control_ui_origin)
        elif any(value is not None for value in
                 (instance_id, proxy_network, owner_id, control_ui_origin)):
            raise ValueError('Proxy settings are only valid for proxy profile')
        return spec

    def _payload(self, instance_id, spec, token, image_info, *, proxy_network=None):
        proxy_profile = spec.get('version') == 3
        if proxy_profile:
            if token is not None or not isinstance(proxy_network, dict):
                raise ValueError('Proxy profile must not use Gateway token authentication')
            self._proxy_network_payload(instance_id, proxy_network, role='agent')
            if spec.get('proxy_network') != proxy_network:
                raise ValueError('Proxy network does not match the managed container spec')
        elif (not isinstance(token, str) or not 1 <= len(token) <= 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError('A nonempty bounded gateway token is required')
        environment = {}
        for item in image_info['Config'].get('Env') or []:
            if not isinstance(item, str) or '=' not in item:
                raise DockerEngineError('Invalid pinned image environment')
            key, value = item.split('=', 1)
            environment[key] = value
        environment.update(self._ENV)
        if proxy_profile:
            environment.pop('OPENCLAW_GATEWAY_TOKEN', None)
        else:
            environment['OPENCLAW_GATEWAY_TOKEN'] = token
        path = spec['host_path']
        limits = spec['limits']
        mounts = [
            {'Type': 'bind', 'Source': path + '/state', 'Target': '/home/node/.openclaw',
             'ReadOnly': False, 'BindOptions': {'Propagation': 'rprivate', 'CreateMountpoint': False}},
            {'Type': 'bind', 'Source': path + '/secrets', 'Target': '/home/node/.config/openclaw',
             'ReadOnly': False, 'BindOptions': {'Propagation': 'rprivate', 'CreateMountpoint': False}},
        ]
        if proxy_profile:
            assert isinstance(proxy_network, dict)
            network_mode = proxy_network['name']
        else:
            network_mode = 'none' if spec['version'] == 1 else self._network_name(instance_id)
        payload = {
            'Image': self.image, 'User': '1000:1000', 'Cmd': list(self._CMD),
            'Env': [k + '=' + v for k, v in sorted(environment.items())],
            'Entrypoint': image_info['Config'].get('Entrypoint') or [],
            'WorkingDir': image_info['Config'].get('WorkingDir') or '',
            'Healthcheck': dict(self._HEALTH), 'StopTimeout': 10,
            'Tty': False, 'OpenStdin': False, 'StdinOnce': False,
            'Labels': self._labels(instance_id),
            'HostConfig': {
                'Mounts': mounts, 'ReadonlyRootfs': True, 'Privileged': False,
                'CapDrop': ['ALL'], 'CapAdd': [],
                'SecurityOpt': ['no-new-privileges:true', 'seccomp=' + self.seccomp],
                'Memory': limits['ram_bytes'], 'MemorySwap': limits['ram_bytes'],
                'NanoCpus': limits['cpu_millicores'] * 1000000,
                'PidsLimit': limits['pids_limit'], 'Init': True,
                'Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=64m'},
                'LogConfig': {'Type': 'none', 'Config': {}},
                'NetworkMode': network_mode, 'PortBindings': {}, 'PublishAllPorts': False,
                'CgroupnsMode': 'private', 'IpcMode': 'private', 'Runtime': 'runc',
                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
            },

        }
        if proxy_profile:
            assert isinstance(proxy_network, dict)
            payload['NetworkingConfig'] = {'EndpointsConfig': {
                network_mode: {'IPAMConfig': {'IPv4Address': proxy_network['gateway_ip']}},
            }}
        return payload

    def _projection(self, config, host, mounts, image_id):
        """Canonical security/config view; ignore daemon-generated IDs and IPs."""
        env = config.get('Env') or []
        if (not isinstance(env, list) or any(not isinstance(e, str) or '=' not in e for e in env)
                or len({e.split('=', 1)[0] for e in env}) != len(env)):
            raise DockerEngineError('Managed container environment verification failed')
        # Never place the plaintext token in a label or public observation.
        safe_env = [e if not e.startswith('OPENCLAW_GATEWAY_TOKEN=') else
                    'OPENCLAW_GATEWAY_TOKEN_SHA256=' + hashlib.sha256(
                        e.split('=', 1)[1].encode('utf-8')).hexdigest() for e in env]
        return {
            'image_id': image_id,
            'config': {k: config.get(k) for k in ('Image', 'User', 'Cmd', 'WorkingDir',
                                                 'Healthcheck', 'StopTimeout')},
            'entrypoint': config.get('Entrypoint') or [], 'env': sorted(safe_env),
            'host': {k: host.get(k) for k in (
                'ReadonlyRootfs', 'Privileged', 'CapDrop', 'SecurityOpt', 'Memory',
                'MemorySwap', 'NanoCpus', 'PidsLimit', 'Init', 'Tmpfs', 'LogConfig',
                'NetworkMode', 'RestartPolicy')},
            'mounts': sorted(mounts, key=lambda m: m['Destination']),
        }

    @staticmethod
    def _expected_mounts(payload):
        return [{'Type': m['Type'], 'Source': m['Source'], 'Destination': m['Target'],
                 'RW': not m['ReadOnly'], 'Propagation': 'rprivate'}
                for m in payload['HostConfig']['Mounts']]

    def _verify(self, instance_id, observed, expected_spec=None, expected_token=None):
        """Verify labels AND actual immutable image/mounts/resources/isolation."""
        try:
            cfg, host = observed['Config'], observed['HostConfig']
            labels = cfg['Labels']
            if any(labels.get(k) != v for k, v in self._labels(instance_id).items()):
                raise ValueError
            spec = json.loads(labels[self.SPEC_LABEL])
            if type(spec) is not dict or type(spec.get('version')) is not int:
                raise ValueError
            spec_keys = {'version', 'image', 'host_path', 'limits'}
            if spec['version'] == 3:
                spec_keys.update({'proxy_network', 'owner_id', 'control_ui_origin'})
            elif spec['version'] not in (1, 2):
                raise ValueError
            if set(spec) != spec_keys:
                raise ValueError
            expected_spec = self._spec(
                spec['host_path'], AgentLimits(**spec['limits']), version=spec['version'],
                instance_id=instance_id if spec['version'] == 3 else None,
                proxy_network=spec.get('proxy_network'), owner_id=spec.get('owner_id'),
                control_ui_origin=spec.get('control_ui_origin'))
            if spec != expected_spec:
                raise ValueError
            if spec['image'] != self.image or (expected_spec is not None and spec != expected_spec):
                raise ValueError
            env = cfg.get('Env') or []
            tokens = [e.split('=', 1)[1] for e in env if e.startswith('OPENCLAW_GATEWAY_TOKEN=')]
            if spec['version'] == 3:
                if tokens or expected_token is not None:
                    raise ValueError
                token = None
            else:
                if len(tokens) != 1 or (expected_token is not None and tokens[0] != expected_token):
                    raise ValueError
                token = tokens[0]
            container_id = self._object(observed['Id'])
            image_info = self._image_info()
            expected = self._payload(
                instance_id, spec, token, image_info,
                proxy_network=spec.get('proxy_network'))
            # Inherited image metadata is checked too, not just a user-facing tag.
            if observed.get('Image') != image_info['Id']:
                raise ValueError
            actual_mounts = [{k: m.get(k) for k in ('Type', 'Source', 'Destination', 'RW', 'Propagation')}
                             for m in observed.get('Mounts', [])]
            projection = self._projection(cfg, host, actual_mounts, observed['Image'])
            wanted = self._projection(expected, expected['HostConfig'],
                                      self._expected_mounts(expected), image_info['Id'])
            if projection != wanted or labels.get(self.CONFIG_LABEL) != self._hash(wanted):
                raise ValueError
            # Reject side channels and secondary namespace/network attachments.
            for key in ('Privileged', 'PublishAllPorts', 'AutoRemove', 'ReadonlyPathsDisabled'):
                if host.get(key, False):
                    raise ValueError
            for key in ('CapAdd', 'Devices', 'DeviceRequests', 'DeviceCgroupRules',
                        'Binds', 'VolumesFrom', 'PortBindings', 'Links', 'ExtraHosts',
                        'Dns', 'DnsOptions', 'DnsSearch', 'GroupAdd', 'Sysctls',
                        'StorageOpt', 'LxcConf', 'Ulimits', 'CgroupParent'):
                if host.get(key):
                    raise ValueError
            for key in ('PidMode', 'UTSMode', 'UsernsMode'):
                if host.get(key, ''):
                    raise ValueError
            for key in ('CpuShares', 'CpuPeriod', 'CpuQuota', 'CpuRealtimePeriod',
                        'CpuRealtimeRuntime', 'CpusetCpus', 'CpusetMems',
                        'MemoryReservation', 'OomKillDisable'):
                if host.get(key):
                    raise ValueError
            if host.get('IpcMode', 'private') not in ('', 'private'):
                raise ValueError
            if host.get('CgroupnsMode', 'private') != 'private':
                raise ValueError
            if host.get('Runtime', 'runc') not in ('', 'runc'):
                raise ValueError
            if any(cfg.get(k, False) for k in ('Tty', 'OpenStdin', 'StdinOnce')):
                raise ValueError
            settings = observed.get('NetworkSettings') or {}
            networks = settings.get('Networks') or {}
            if type(networks) is not dict or any((settings.get('Ports') or {}).values()):
                raise ValueError
            if spec['version'] == 1:
                if set(networks) - {'none'}:
                    raise ValueError
            elif spec['version'] == 2:
                network_name = self._network_name(instance_id)
                if set(networks) != {network_name}:
                    raise ValueError
                attached = networks[network_name]
                if type(attached) is not dict:
                    raise ValueError
                self._verify_network(instance_id, attached.get('NetworkID'),
                                     expected_container_id=container_id)
            else:
                proxy_network = spec['proxy_network']
                network_name = proxy_network['name']
                if set(networks) != {network_name}:
                    raise ValueError
                attached = networks[network_name]
                if type(attached) is not dict:
                    raise ValueError
                network_id = self._proxy_network_id(
                    instance_id, 'agent', proxy_network)
                self._verify_proxy_endpoint(
                    observed, network_name, network_id, proxy_network['gateway_ip'])
                sidecar = self._find_proxy_sidecar(instance_id)
                if sidecar is None:
                    raise ValueError
                sidecar_id = self._object(sidecar['Id'])
                if sidecar_id == container_id:
                    raise ValueError
                self._verify_proxy_network_membership(
                    instance_id, 'agent', network_id, proxy_network,
                    {container_id, sidecar_id},
                    expected_ips={container_id: proxy_network['gateway_ip'],
                                  sidecar_id: proxy_network['sidecar_ip']},
                    allow_unstarted=True)
            return container_id
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError):
            raise DockerEngineError('Managed container configuration verification failed') from None

    def create(self, instance_id, host_path, limits, token, *,
               network_profile=NETWORK_PROFILE_LEGACY, owner_id=None,
               sidecar_ip=None, control_ui_origin=None):
        """Idempotently create a Gateway; legacy_none remains the default."""
        instance_id = self._instance(instance_id)
        versions = {self.NETWORK_PROFILE_LEGACY: 1,
                    self.NETWORK_PROFILE_PRIVATE: 2,
                    self.NETWORK_PROFILE_PROXY: 3}
        if type(network_profile) is not str or network_profile not in versions:
            raise ValueError('Unsupported managed network profile')
        version = versions[network_profile]
        proxy_network = None
        if version == 3:
            if (token is not None or type(owner_id) is not str
                    or type(control_ui_origin) is not str or type(sidecar_ip) is not str):
                raise ValueError('Proxy profile requires owner, origin and sidecar identity, not Gateway token')
            if type(self.agent_network_pool) is not str or type(self.frontend_network_pool) is not str:
                raise ValueError('Both explicit proxy network pools are required')
            plan = self.ensure_proxy_networks(
                instance_id, agent_network_pool=self.agent_network_pool,
                frontend_network_pool=self.frontend_network_pool)
            if sidecar_ip != plan['agent']['sidecar_ip']:
                raise ValueError('Trusted proxy address does not match the per-agent network plan')
            proxy_network = plan['agent']
            spec = self._spec(host_path, limits, version=3, instance_id=instance_id,
                              proxy_network=proxy_network, owner_id=owner_id,
                              control_ui_origin=control_ui_origin)
        else:
            if owner_id is not None or sidecar_ip is not None or control_ui_origin is not None:
                raise ValueError('Proxy settings are only valid for proxy profile')
            spec = self._spec(host_path, limits, version=version)
            if (not isinstance(token, str) or not 1 <= len(token) <= 4096
                    or any(ord(c) < 33 or ord(c) > 126 for c in token)):
                raise ValueError('A nonempty bounded gateway token is required')
        existing = self._find(instance_id)
        if existing is not None:
            return self._verify(instance_id, existing, spec, token)
        image_info = self._image_info()  # Missing local image fails; never pull.
        if version == 2:
            self.ensure_instance_network(instance_id)
        payload = self._payload(instance_id, spec, token, image_info,
                                proxy_network=proxy_network)
        digest = self._hash(self._projection(payload, payload['HostConfig'],
                                             self._expected_mounts(payload), image_info['Id']))
        payload['Labels'].update({self.SPEC_LABEL: self._json(spec), self.CONFIG_LABEL: digest})
        try:
            result = self._request('POST', '/containers/create?' + urlencode(
                {'name': 'pa-' + instance_id}), payload, ok=(201,))
            if not isinstance(result, dict):
                raise DockerEngineError('Invalid managed container creation response')
            created_id = self._object(result.get('Id'))
        except DockerEngineError:
            # A lost response or concurrent retry may have created it. Exact labels
            # and the full expected configuration are mandatory before adoption.
            existing = self._find(instance_id)
            if existing is None:
                raise DockerEngineError('Managed container creation failed') from None
            return self._verify(instance_id, existing, spec, token)
        existing = self._find(instance_id)
        if existing is None or existing['Id'] != created_id:
            raise DockerEngineError('Managed container creation could not be verified')
        return self._verify(instance_id, existing, spec, token)

    def control_ui_target(self, instance_id, owner_id):
        """Resolve an owner-bound private sidecar only after all live checks pass."""
        try:
            instance_id = self._instance(instance_id)
            if not callable(getattr(self.firewall, 'ready', None)):
                return None
            if type(owner_id) is not str or not 1 <= len(owner_id) <= 256:
                return None
            gateway = self._find(instance_id)
            if gateway is None:
                return None
            gateway_id = self._verify(instance_id, gateway)
            gateway_labels = gateway['Config']['Labels']
            gateway_spec = json.loads(gateway_labels[self.SPEC_LABEL])
            if (type(gateway_spec) is not dict or gateway_spec.get('version') != 3
                    or gateway_spec.get('owner_id') != owner_id):
                return None
            origin = gateway_spec.get('control_ui_origin')
            prefix = 'https://' + instance_id + '.'
            if type(origin) is not str or not origin.startswith(prefix):
                return None
            domain = origin[len(prefix):]
            if not domain:
                return None
            sidecar = self._find_proxy_sidecar(instance_id)
            if sidecar is None:
                return None
            labels = sidecar.get('Config', {}).get('Labels', {})
            sidecar_spec = json.loads(labels[self.SIDECAR_SPEC_LABEL])
            if (type(sidecar_spec) is not dict
                    or set(sidecar_spec) != {
                        'version', 'image_id', 'owner_id', 'control_ui_origin',
                        'gateway_ip', 'listen_ip', 'host_path', 'agent', 'frontend'}
                    or sidecar_spec.get('version') != 1
                    or sidecar_spec.get('owner_id') != owner_id
                    or sidecar_spec.get('control_ui_origin') != origin
                    or sidecar_spec.get('host_path') != gateway_spec.get('host_path')
                    or sidecar_spec.get('agent') != gateway_spec.get('proxy_network')):
                return None
            if labels.get(self.SIDECAR_CONFIG_LABEL) != self._hash(sidecar_spec):
                return None
            plan = {'agent': gateway_spec['proxy_network'],
                    'frontend': sidecar_spec['frontend']}
            self._proxy_network_payload(instance_id, plan['agent'], role='agent')
            self._proxy_network_payload(instance_id, plan['frontend'], role='frontend')
            web = self._find_control_plane_web(domain)
            if web['image_id'] != sidecar_spec['image_id']:
                return None
            network_ids = {
                'agent': self._proxy_network_id(instance_id, 'agent', plan['agent']),
                'frontend': self._proxy_network_id(instance_id, 'frontend', plan['frontend']),
            }
            expected_sidecar = self._proxy_sidecar_payload(
                instance_id, owner_id=owner_id, control_ui_origin=origin,
                gateway_ip=plan['agent']['gateway_ip'],
                listen_ip=plan['frontend']['sidecar_ip'],
                image_id=sidecar_spec['image_id'], host_path=sidecar_spec['host_path'],
                plan=plan, image_info=web['image_info'])
            sidecar_id = self._verify_proxy_sidecar(
                instance_id, sidecar, expected_sidecar, plan, network_ids)
            self._verify_proxy_endpoint(
                {'State': {'Status': 'running'},
                 'NetworkSettings': {'Networks': web['networks']}},
                plan['frontend']['name'], network_ids['frontend'],
                plan['frontend']['web_ip'])
            gateway_state = gateway.get('State') or {}
            sidecar_state = sidecar.get('State') or {}
            if (gateway_state.get('Status') != 'running'
                    or (gateway_state.get('Health') or {}).get('Status') != 'healthy'
                    or sidecar_state.get('Status') != 'running'
                    or (sidecar_state.get('Health') or {}).get('Status') != 'healthy'):
                return None
            self._verify_proxy_network_membership(
                instance_id, 'agent', network_ids['agent'], plan['agent'],
                {gateway_id, sidecar_id},
                expected_ips={gateway_id: plan['agent']['gateway_ip'],
                              sidecar_id: plan['agent']['sidecar_ip']})
            self._verify_proxy_network_membership(
                instance_id, 'frontend', network_ids['frontend'], plan['frontend'],
                {web['container_id'], sidecar_id},
                expected_ips={web['container_id']: plan['frontend']['web_ip'],
                              sidecar_id: plan['frontend']['sidecar_ip']})
            firewall_ready = getattr(self.firewall, 'ready', None)
            policy = self._proxy_firewall_policy(instance_id, plan)
            policies = self.proxy_network_policies()
            if not callable(firewall_ready) or policy not in policies or not firewall_ready(policies):
                return None
            latest_gateway = self._find(instance_id)
            if latest_gateway is None:
                return None
            latest_gateway_id = self._verify(instance_id, latest_gateway)
            latest_sidecar = self._find_proxy_sidecar(instance_id)
            if latest_sidecar is None:
                return None
            latest_sidecar_id = self._verify_proxy_sidecar(
                instance_id, latest_sidecar, expected_sidecar, plan, network_ids)
            latest_web = self._find_control_plane_web(domain)
            if (latest_gateway_id != gateway_id or latest_sidecar_id != sidecar_id
                    or latest_web['container_id'] != web['container_id']
                    or latest_web['image_id'] != web['image_id']):
                return None
            self._verify_proxy_endpoint(
                {'State': {'Status': 'running'},
                 'NetworkSettings': {'Networks': latest_web['networks']}},
                plan['frontend']['name'], network_ids['frontend'],
                plan['frontend']['web_ip'])
            for latest in (latest_gateway, latest_sidecar):
                state = latest.get('State') or {}
                if state.get('Status') != 'running' or (state.get('Health') or {}).get('Status') != 'healthy':
                    return None
            self._verify_proxy_network_membership(
                instance_id, 'agent', network_ids['agent'], plan['agent'],
                {latest_gateway_id, latest_sidecar_id},
                expected_ips={latest_gateway_id: plan['agent']['gateway_ip'],
                              latest_sidecar_id: plan['agent']['sidecar_ip']})
            self._verify_proxy_network_membership(
                instance_id, 'frontend', network_ids['frontend'], plan['frontend'],
                {latest_web['container_id'], latest_sidecar_id},
                expected_ips={latest_web['container_id']: plan['frontend']['web_ip'],
                              latest_sidecar_id: plan['frontend']['sidecar_ip']})
            policies = self.proxy_network_policies()
            if policy not in policies or firewall_ready(policies) is not True:
                return None
            token = self._read_existing_proxy_token_file(gateway_spec['host_path'])
            identity = {
                'gateway_id': gateway_id, 'sidecar_id': sidecar_id,
                'agent_network_id': network_ids['agent'],
                'frontend_network_id': network_ids['frontend'],
            }
            return {'ip': plan['frontend']['sidecar_ip'], 'port': self.SIDECAR_PORT,
                    'proxy_token': token, 'identity': identity}
        except Exception:
            return None

    def inspect(self, instance_id):
        self._instance(instance_id)
        observed = self._find(instance_id)
        if observed is None:
            return {'state': 'absent', 'gateway': 'unknown', 'container_id': None}
        try:
            container_id = self._verify(instance_id, observed)
        except Exception:
            try:
                failed_spec = json.loads(observed.get('Config', {}).get('Labels', {}).get(
                    self.SPEC_LABEL, '{}'))
                docker_status = (observed.get('State') or {}).get('Status')
                is_live_proxy = (type(failed_spec) is dict
                                 and failed_spec.get('version') == 3
                                 and docker_status in {'running', 'paused', 'restarting'})
            except Exception:
                is_live_proxy = False
            if is_live_proxy and not self._stop_proxy_containers(instance_id):
                raise DockerEngineError(
                    'Proxy verification failed and container stop could not be verified') from None
            raise
        status = observed.get('State') or {}
        docker_state = status.get('Status')
        if docker_state == 'running':
            state = 'running'
        elif docker_state in ('paused', 'restarting'):
            state = docker_state
        elif docker_state == 'created':
            state = 'created'
        elif docker_state == 'exited' and status.get('ExitCode') == 0 and not status.get('OOMKilled'):
            state = 'stopped'
        else:
            state = 'failed'
        health = (status.get('Health') or {}).get('Status')
        gateway = 'unknown'
        if health in ('healthy', 'unhealthy', 'starting'):
            gateway = 'ready' if state == 'running' and health == 'healthy' else 'not_ready'
        spec_version = json.loads(observed['Config']['Labels'][self.SPEC_LABEL])['version']
        network_profile = {1: self.NETWORK_PROFILE_LEGACY,
                           2: self.NETWORK_PROFILE_PRIVATE,
                           3: self.NETWORK_PROFILE_PROXY}[spec_version]
        result = {'state': state, 'gateway': gateway, 'container_id': container_id,
                  'network_profile': network_profile}
        if spec_version == 3:
            spec = json.loads(observed['Config']['Labels'][self.SPEC_LABEL])
            target = self.control_ui_target(instance_id, spec['owner_id'])
            if target is None and state == 'running' and not self._proxy_firewall_ready(instance_id, spec):
                if not self._stop_proxy_containers(instance_id):
                    raise DockerEngineError(
                        'Proxy isolation drift detected and container stop could not be verified')
                latest = self._find(instance_id)
                if latest is None:
                    result.update({'state': 'absent', 'gateway': 'unknown', 'container_id': None})
                else:
                    latest_state = latest.get('State') or {}
                    latest_status = latest_state.get('Status') if type(latest_state) is dict else None
                    if latest_status == 'created':
                        result['state'] = 'created'
                    elif (latest_status == 'exited' and latest_state.get('ExitCode') == 0
                          and not latest_state.get('OOMKilled')):
                        result['state'] = 'stopped'
                    elif latest_status in {'exited', 'dead'}:
                        result['state'] = 'failed'
                    else:
                        raise DockerEngineError('Proxy containers remained live after stop')
                    result['gateway'] = 'not_ready'
            result['proxy_state'] = 'ready' if target is not None else 'not_ready'
            result['proxy_identity'] = target['identity'] if target is not None else None
        return result

    def _action(self, instance_id, action):
        self._instance(instance_id)
        observed = self._find(instance_id)
        if observed is None:
            raise DockerEngineError('Managed container is absent')
        container_id = self._verify(instance_id, observed)
        # Docker may reject stop/start while paused. Resume only as part of the
        # already-authorized lifecycle operation, then verify its postcondition.
        if (observed.get('State') or {}).get('Status') == 'paused':
            self._request('POST', f'/containers/{container_id}/unpause', ok=(204,))
        query = '?t=10' if action in ('stop', 'restart') else ''
        self._request('POST', f'/containers/{container_id}/{action}' + query, ok=(204, 304))
        # An HTTP success is not proof of the requested postcondition.
        state = self.inspect(instance_id)
        expected = ('created', 'stopped', 'failed') if action == 'stop' else ('running',)
        if state['container_id'] != container_id or state['state'] not in expected:
            raise DockerEngineError('Managed container action could not be verified')
        return state

    def _proxy_firewall_ready(self, instance_id, gateway_spec):
        ready = getattr(self.firewall, 'ready', None)
        if not callable(ready):
            return False
        try:
            instance_id = self._instance(instance_id)
            if type(gateway_spec) is not dict or gateway_spec.get('version') != 3:
                return False
            gateway = self._find(instance_id)
            if gateway is None or self._verify(instance_id, gateway) is None:
                return False
            gateway_labels = gateway.get('Config', {}).get('Labels', {})
            observed_gateway_spec = json.loads(gateway_labels[self.SPEC_LABEL])
            if observed_gateway_spec != gateway_spec:
                return False
            sidecar = self._find_proxy_sidecar(instance_id)
            if sidecar is None:
                return False
            labels = sidecar.get('Config', {}).get('Labels', {})
            sidecar_spec = json.loads(labels[self.SIDECAR_SPEC_LABEL])
            if (type(sidecar_spec) is not dict
                    or set(sidecar_spec) != {
                        'version', 'image_id', 'owner_id', 'control_ui_origin',
                        'gateway_ip', 'listen_ip', 'host_path', 'agent', 'frontend'}
                    or sidecar_spec.get('version') != 1
                    or sidecar_spec.get('owner_id') != gateway_spec.get('owner_id')
                    or sidecar_spec.get('control_ui_origin') != gateway_spec.get('control_ui_origin')
                    or sidecar_spec.get('host_path') != gateway_spec.get('host_path')
                    or sidecar_spec.get('agent') != gateway_spec.get('proxy_network')
                    or labels.get(self.SIDECAR_CONFIG_LABEL) != self._hash(sidecar_spec)):
                return False
            origin = gateway_spec.get('control_ui_origin')
            prefix = 'https://' + instance_id + '.'
            if type(origin) is not str or not origin.startswith(prefix):
                return False
            domain = origin[len(prefix):]
            if not domain:
                return False
            plan = {'agent': gateway_spec['proxy_network'],
                    'frontend': sidecar_spec['frontend']}
            self._proxy_network_payload(instance_id, plan['agent'], role='agent')
            self._proxy_network_payload(instance_id, plan['frontend'], role='frontend')
            web = self._find_control_plane_web(domain)
            if web['image_id'] != sidecar_spec['image_id']:
                return False
            network_ids = {
                'agent': self._proxy_network_id(instance_id, 'agent', plan['agent']),
                'frontend': self._proxy_network_id(instance_id, 'frontend', plan['frontend']),
            }
            expected_sidecar = self._proxy_sidecar_payload(
                instance_id, owner_id=gateway_spec['owner_id'],
                control_ui_origin=origin, gateway_ip=plan['agent']['gateway_ip'],
                listen_ip=plan['frontend']['sidecar_ip'],
                image_id=sidecar_spec['image_id'], host_path=sidecar_spec['host_path'],
                plan=plan, image_info=web['image_info'])
            sidecar_id = self._verify_proxy_sidecar(
                instance_id, sidecar, expected_sidecar, plan, network_ids)
            gateway_id = self._object(gateway.get('Id'))
            self._verify_proxy_endpoint(
                {'State': {'Status': 'running'},
                 'NetworkSettings': {'Networks': web['networks']}},
                plan['frontend']['name'], network_ids['frontend'],
                plan['frontend']['web_ip'])
            self._verify_proxy_network_membership(
                instance_id, 'agent', network_ids['agent'], plan['agent'],
                {gateway_id, sidecar_id},
                expected_ips={gateway_id: plan['agent']['gateway_ip'],
                              sidecar_id: plan['agent']['sidecar_ip']},
                allow_unstarted=True)
            self._verify_proxy_network_membership(
                instance_id, 'frontend', network_ids['frontend'], plan['frontend'],
                {web['container_id'], sidecar_id},
                expected_ips={web['container_id']: plan['frontend']['web_ip'],
                              sidecar_id: plan['frontend']['sidecar_ip']},
                allow_unstarted=True)
            policy = self._proxy_firewall_policy(instance_id, plan)
            policies = self.proxy_network_policies()
            return policy in policies and ready(policies) is True
        except Exception:
            return False

    def _delete_container(self, container_id):
        container_id = self._object(container_id)
        self._request('DELETE', f'/containers/{container_id}?force=true&v=false', ok=(204,))

    def _disconnect_control_plane_from_frontend(self, instance_id):
        current = self._existing_proxy_network(instance_id, 'frontend')
        if current is None:
            return
        network_id, _plan, network = current
        containers = network.get('Containers') or {}
        if type(containers) is not dict:
            raise DockerEngineError('Frontend network membership is invalid')
        web_ids = []
        for raw_id in containers:
            container_id = self._object(raw_id)
            observed = self._request('GET', '/containers/' + container_id + '/json')
            config = observed.get('Config') if type(observed) is dict else None
            labels = config.get('Labels') if type(config) is dict else None
            if type(labels) is dict and labels.get(self.CONTROL_PLANE_LABEL) == 'true':
                web_ids.append(container_id)
        if len(web_ids) > 1:
            raise DockerEngineError('Control Plane network membership is ambiguous')
        if web_ids:
            self._request('POST', '/networks/' + network_id + '/disconnect',
                          {'Container': web_ids[0], 'Force': False}, ok=(200,))
        remaining = self._existing_proxy_network(instance_id, 'frontend')
        if remaining is not None and (remaining[2].get('Containers') or {}):
            raise DockerEngineError('Frontend network did not become empty')

    def _remove_proxy_resources(self, instance_id, *, retain_networks):
        instance_id = self._instance(instance_id)
        sidecar = self._find_proxy_sidecar(instance_id)
        if sidecar is not None:
            sidecar_id = self._object(sidecar.get('Id'))
            self._delete_container(sidecar_id)
            if self._find_proxy_sidecar(instance_id) is not None:
                raise DockerEngineError('Proxy sidecar removal could not be verified')
        gateway = self._find(instance_id)
        if gateway is not None:
            gateway_id = self._object(gateway.get('Id'))
            self._delete_container(gateway_id)
            if self._find(instance_id) is not None:
                raise DockerEngineError('Gateway container removal could not be verified')
        self._disconnect_control_plane_from_frontend(instance_id)
        for role in ('agent', 'frontend'):
            current = self._existing_proxy_network(instance_id, role)
            if current is not None and (current[2].get('Containers') or {}):
                raise DockerEngineError('Proxy network did not become empty')
        if not retain_networks:
            self.remove_proxy_networks(instance_id)
        return {'state': 'absent', 'gateway': 'unknown', 'container_id': None}

    def abort_control_ui_prepare(self, instance_id):
        """Remove partial proxy containers and web attachment, retaining IPAM/data."""
        return self._remove_proxy_resources(instance_id, retain_networks=True)

    def _stop_proxy_containers(self, instance_id):
        """Best-effort rollback; return true only after both live containers are stopped."""
        instance_id = self._instance(instance_id)
        clean = True
        for finder in (self._find_proxy_sidecar, self._find):
            try:
                observed = finder(instance_id)
                if observed is None:
                    continue
                container_id = self._object(observed.get('Id'))
                state = observed.get('State') or {}
                status = state.get('Status') if type(state) is dict else None
                if status not in {'created', 'exited', 'dead'}:
                    if status == 'paused':
                        self._request('POST', f'/containers/{container_id}/unpause', ok=(204,))
                    self._request('POST', f'/containers/{container_id}/stop?t=10', ok=(204, 304))
                latest = finder(instance_id)
                if latest is not None:
                    latest_state = latest.get('State') or {}
                    if (type(latest_state) is not dict
                            or latest_state.get('Status') not in {'created', 'exited', 'dead'}):
                        clean = False
            except Exception:
                clean = False
        return clean

    def start(self, instance_id):
        instance_id = self._instance(instance_id)
        observed = self._find(instance_id)
        if observed is None:
            raise DockerEngineError('Managed container is absent')
        labels = observed.get('Config', {}).get('Labels', {})
        try:
            spec = json.loads(labels[self.SPEC_LABEL])
        except Exception:
            raise DockerEngineError('Managed container configuration verification failed') from None
        if type(spec) is not dict or spec.get('version') != 3:
            return self._action(instance_id, 'start')
        try:
            gateway_id = self._verify(instance_id, observed)
        except Exception:
            if not self._stop_proxy_containers(instance_id):
                raise DockerEngineError(
                    'Gateway verification failed and proxy stop could not be verified') from None
            raise
        if not self._proxy_firewall_ready(instance_id, spec):
            if not self._stop_proxy_containers(instance_id):
                raise DockerEngineError(
                    'Per-agent firewall policy is not ready and proxy stop could not be verified')
            raise DockerEngineError('Per-agent firewall policy is not ready')
        try:
            gateway_state = observed.get('State') or {}
            if gateway_state.get('Status') != 'running':
                self._action(instance_id, 'start')
            sidecar = self._find_proxy_sidecar(instance_id)
            if sidecar is None:
                raise DockerEngineError('Proxy sidecar is absent')
            sidecar_id = self._object(sidecar.get('Id'))
            if (sidecar.get('State') or {}).get('Status') != 'running':
                self._request('POST', f'/containers/{sidecar_id}/start', ok=(204, 304))
            latest_gateway = self._find(instance_id)
            latest_sidecar = self._find_proxy_sidecar(instance_id)
            if (latest_gateway is None or latest_gateway.get('Id') != gateway_id
                    or (latest_gateway.get('State') or {}).get('Status') != 'running'
                    or latest_sidecar is None or latest_sidecar.get('Id') != sidecar_id
                    or (latest_sidecar.get('State') or {}).get('Status') != 'running'
                    or not self._proxy_firewall_ready(instance_id, spec)):
                raise DockerEngineError('Post-start proxy isolation verification failed')
            result = self.inspect(instance_id)
            if result.get('container_id') != gateway_id or result.get('state') != 'running':
                raise DockerEngineError('Post-start Gateway verification failed')
            if result.get('proxy_state') != 'ready':
                # Health can still be starting immediately after Docker start. Keep
                # the UI closed, but repeat the strict live network/firewall checks.
                if not self._proxy_firewall_ready(instance_id, spec):
                    raise DockerEngineError('Post-start proxy isolation verification failed')
                latest_gateway = self._find(instance_id)
                latest_sidecar = self._find_proxy_sidecar(instance_id)
                gateway_health = ((latest_gateway or {}).get('State') or {}).get('Health') or {}
                sidecar_health = ((latest_sidecar or {}).get('State') or {}).get('Health') or {}
                if (gateway_health.get('Status') == 'healthy'
                        and sidecar_health.get('Status') == 'healthy'):
                    raise DockerEngineError('Control UI target failed after healthy startup')
            return result
        except Exception:
            if not self._stop_proxy_containers(instance_id):
                raise DockerEngineError(
                    'Proxy start failed and container stop could not be verified') from None
            raise

    def stop(self, instance_id):
        instance_id = self._instance(instance_id)
        observed = self._find(instance_id)
        if observed is None:
            raise DockerEngineError('Managed container is absent')
        labels = observed.get('Config', {}).get('Labels', {})
        try:
            spec = json.loads(labels[self.SPEC_LABEL])
        except Exception:
            raise DockerEngineError('Managed container configuration verification failed') from None
        if type(spec) is not dict or spec.get('version') != 3:
            return self._action(instance_id, 'stop')
        errors = []
        sidecar = self._find_proxy_sidecar(instance_id)
        if sidecar is None:
            errors.append('sidecar_absent')
        else:
            sidecar_id = self._object(sidecar.get('Id'))
            if (sidecar.get('State') or {}).get('Status') not in {'created', 'exited', 'dead'}:
                try:
                    self._request('POST', f'/containers/{sidecar_id}/stop?t=10', ok=(204, 304))
                    verified = self._find_proxy_sidecar(instance_id)
                    if (verified is None or (verified.get('State') or {}).get('Status') == 'running'):
                        errors.append('sidecar_stop_unverified')
                except Exception:
                    errors.append('sidecar_stop_failed')
        try:
            gateway_state = self._action(instance_id, 'stop')
            if gateway_state['state'] not in {'created', 'stopped', 'failed'}:
                errors.append('gateway_stop_unverified')
        except Exception:
            errors.append('gateway_stop_failed')
        if errors:
            raise DockerEngineError('Proxy containers did not stop cleanly')
        return self.inspect(instance_id)

    def restart(self, instance_id):
        instance_id = self._instance(instance_id)
        observed = self._find(instance_id)
        if observed is None:
            raise DockerEngineError('Managed container is absent')
        labels = observed.get('Config', {}).get('Labels', {})
        try:
            spec = json.loads(labels[self.SPEC_LABEL])
        except Exception:
            raise DockerEngineError('Managed container configuration verification failed') from None
        if type(spec) is not dict or spec.get('version') != 3:
            return self._action(instance_id, 'restart')
        if not self._proxy_firewall_ready(instance_id, spec):
            raise DockerEngineError('Per-agent firewall policy is not ready')
        self.stop(instance_id)
        return self.start(instance_id)

    def remove(self, instance_id, *, retain_networks=False):
        """Remove containers without deleting bind data; proxy IPAM follows action policy."""
        instance_id = self._instance(instance_id)
        observed = self._find(instance_id)
        proxy_gateway = False
        if observed is not None:
            try:
                spec = json.loads(observed['Config']['Labels'][self.SPEC_LABEL])
                proxy_gateway = type(spec) is dict and spec.get('version') == 3
            except Exception:
                proxy_gateway = False
        sidecar = self._find_proxy_sidecar(instance_id) if observed is None or proxy_gateway else None
        proxy_networks = False
        if observed is None and sidecar is None and not retain_networks:
            try:
                proxy_networks = (self._existing_proxy_network(instance_id, 'agent') is not None
                                  or self._existing_proxy_network(instance_id, 'frontend') is not None)
            except Exception:
                raise DockerEngineError('Proxy network identity verification failed') from None
        if proxy_gateway or sidecar is not None or proxy_networks or retain_networks:
            return self._remove_proxy_resources(instance_id, retain_networks=retain_networks)
        if observed is not None:
            container_id = self._verify(instance_id, observed)
            self._request('DELETE', f'/containers/{container_id}?force=true&v=false', ok=(204,))
            if self._find(instance_id) is not None:
                raise DockerEngineError('Managed container removal could not be verified')
        self.remove_instance_network(instance_id)
        return {'state': 'absent', 'gateway': 'unknown', 'container_id': None}
