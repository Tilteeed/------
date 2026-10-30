"""Small, fail-closed Linux Docker Engine v1.45 client (stdlib only).

No subprocesses, Docker SDK, image pulls, filesystem writes or published ports.
The caller owns storage/quota verification and writes config/secrets before create.
Stage 3 uses NetworkMode=none: local healthchecks work, but models, chat and proxy
access are unavailable until a separately reviewed Stage 5 networking policy.
Labels are an ownership/configuration receipt, not protection from a hostile daemon
administrator. Never expose this object or the Docker socket to agent workloads.
"""
from dataclasses import asdict
import hashlib
import http.client
import json
from pathlib import Path, PurePosixPath
import re
import socket
import time
from urllib.parse import quote, urlencode

from .config import AgentLimits


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

    def __init__(self, image, engine_socket='/var/run/docker.sock'):
        if not isinstance(image, str) or not self._IMAGE.fullmatch(image):
            raise ValueError('An explicit immutable Docker image digest is required')
        if (not isinstance(engine_socket, str) or not engine_socket.startswith('/')
                or '\x00' in engine_socket or len(engine_socket) > 4096):
            raise ValueError('An explicit Unix socket path is required')
        self.image = image
        self.engine_socket = engine_socket
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

    def _labels(self, instance_id):
        return {self.MANAGED_LABEL: 'true', self.INSTANCE_LABEL: instance_id}

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

    def _spec(self, host_path, limits):
        return {'version': 1, 'image': self.image, 'host_path': self._host_path(host_path),
                'limits': self._limits(limits)}

    def _payload(self, instance_id, spec, token, image_info):
        if (not isinstance(token, str) or not 1 <= len(token) <= 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError('A nonempty bounded gateway token is required')
        environment = {}
        for item in image_info['Config'].get('Env') or []:
            if not isinstance(item, str) or '=' not in item:
                raise DockerEngineError('Invalid pinned image environment')
            key, value = item.split('=', 1)
            environment[key] = value
        environment.update(self._ENV)
        environment['OPENCLAW_GATEWAY_TOKEN'] = token
        path = spec['host_path']
        limits = spec['limits']
        mounts = [
            {'Type': 'bind', 'Source': path + '/state', 'Target': '/home/node/.openclaw',
             'ReadOnly': False, 'BindOptions': {'Propagation': 'rprivate', 'CreateMountpoint': False}},
            {'Type': 'bind', 'Source': path + '/secrets', 'Target': '/home/node/.config/openclaw',
             'ReadOnly': False, 'BindOptions': {'Propagation': 'rprivate', 'CreateMountpoint': False}},
        ]
        return {
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
                'NetworkMode': 'none', 'PortBindings': {}, 'PublishAllPorts': False,
                'CgroupnsMode': 'private', 'IpcMode': 'private', 'Runtime': 'runc',
                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
            },

        }

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
            if set(spec) != {'version', 'image', 'host_path', 'limits'} or spec['version'] != 1:
                raise ValueError
            if spec != self._spec(spec['host_path'], AgentLimits(**spec['limits'])):
                raise ValueError
            if spec['image'] != self.image or (expected_spec is not None and spec != expected_spec):
                raise ValueError
            env = cfg.get('Env') or []
            tokens = [e.split('=', 1)[1] for e in env if e.startswith('OPENCLAW_GATEWAY_TOKEN=')]
            if len(tokens) != 1 or (expected_token is not None and tokens[0] != expected_token):
                raise ValueError
            container_id = self._object(observed['Id'])
            image_info = self._image_info()
            expected = self._payload(instance_id, spec, tokens[0], image_info)
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
            if set(networks) - {'none'} or any((settings.get('Ports') or {}).values()):
                raise ValueError
            return container_id
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError):
            raise DockerEngineError('Managed container configuration verification failed') from None

    def create(self, instance_id, host_path, limits, token):
        """Idempotently create (not start); return the actual 64-hex container ID.

        Bind paths must already exist; Engine Mounts deliberately never mkdir them.
        disk_bytes is part of the receipt; XFS enforcement belongs to the caller.
        """
        self._instance(instance_id)
        spec = self._spec(host_path, limits)
        # Validate token before any Engine operation, including network creation.
        if (not isinstance(token, str) or not 1 <= len(token) <= 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError('A nonempty bounded gateway token is required')
        existing = self._find(instance_id)
        if existing is not None:
            return self._verify(instance_id, existing, spec, token)
        image_info = self._image_info()  # Missing local image fails; never pull.
        payload = self._payload(instance_id, spec, token, image_info)
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

    def inspect(self, instance_id):
        self._instance(instance_id)
        observed = self._find(instance_id)
        if observed is None:
            return {'state': 'absent', 'gateway': 'unknown', 'container_id': None}
        container_id = self._verify(instance_id, observed)
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
        return {'state': state, 'gateway': gateway, 'container_id': container_id}

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

    def start(self, instance_id):
        return self._action(instance_id, 'start')

    def stop(self, instance_id):
        return self._action(instance_id, 'stop')

    def restart(self, instance_id):
        return self._action(instance_id, 'restart')

    def remove(self, instance_id):
        """Remove only the verified container; never remove bind data or networks."""
        self._instance(instance_id)
        observed = self._find(instance_id)
        if observed is not None:
            container_id = self._verify(instance_id, observed)
            self._request('DELETE', f'/containers/{container_id}?force=true&v=false', ok=(204,))
            if self._find(instance_id) is not None:
                raise DockerEngineError('Managed container removal could not be verified')
        return {'state': 'absent', 'gateway': 'unknown', 'container_id': None}
