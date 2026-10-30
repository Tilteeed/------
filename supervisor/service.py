"""Root-only, explicitly enabled AF_UNIX host runtime service; stdlib only.

No imports open files, collect metrics, touch Docker, or start a listener.
The trusted parent authenticates users; actor_id is accepted only with the
service bearer secret. This is not a browser-facing authentication API.
"""
import argparse
from dataclasses import asdict
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import errno
import socketserver
import stat
import sys
import threading
import time

from .config import load_profile, _unique_object, _reject_constant
from .metrics import HostMetrics, MetricsUnavailable
from .policy import evaluate_admission
from .runtime_store import RuntimeStore, StoreError, canonical


class ServiceError(Exception):
    def __init__(self, code, status=409):
        self.code, self.status = code, status
        super().__init__(code)


MESSAGES = {
    'invalid_request': 'Invalid request.', 'unauthorized': 'Authentication required.',
    'not_found': 'Endpoint not found.', 'method_not_allowed': 'POST required.',
    'body_too_large': 'Request body exceeds limit.',
    'admission_denied': 'Host resource policy currently denies this action.',
    'metrics_unavailable': 'Trusted host observations are unavailable.',
    'capacity_exhausted': 'Reservation capacity is exhausted (retained disk included).',
    'owner_has_instance': 'This owner already has an active instance.',
    'instance_not_found': 'No current instance exists for this owner.',
    'operation_not_found': 'No saved operation exists for this owner and key.',
    'idempotency_conflict': 'Idempotency key was already used with a different request.',
    'operation_pending': 'Retry the pending operation using its original key.',
    'quota_unverified': 'Instance storage could not be verified.',
    'storage_unavailable': 'Instance storage is unavailable.',
    'runtime_unavailable': 'Runtime operation could not be verified.',
    'instance_retired': 'This operation belongs to a retained, removed instance.',
    'profile_drift': 'Deployment profile differs from the durable binding.',
    'unsafe_initialization': 'Initial private runtime files could not be verified.',
    'internal_error': 'Service operation failed.',
}


def decode_json(blob):
    try:
        return json.loads(blob.decode('utf-8'), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ServiceError('invalid_request', 400) from None


def actor(value):
    if (type(value) is not str or not 1 <= len(value) <= 256
            or any(ord(c) < 33 or ord(c) == 127 for c in value)):
        raise ServiceError('invalid_request', 400)
    return value


def validate_action(payload):
    if type(payload) is not dict or set(payload) != {
            'actor_id', 'action', 'idempotency_key', 'settings_revision', 'settings'}:
        raise ServiceError('invalid_request', 400)
    actor(payload['actor_id'])
    if type(payload['action']) is not str or payload['action'] not in {'create', 'start', 'stop', 'restart', 'remove'}:
        raise ServiceError('invalid_request', 400)
    key = payload['idempotency_key']
    if type(key) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', key) is None:
        raise ServiceError('invalid_request', 400)
    revision = payload['settings_revision']
    if type(revision) is not int or not 0 <= revision <= 2**63 - 1:
        raise ServiceError('invalid_request', 400)
    settings = payload['settings']
    if (type(settings) is not dict or set(settings) != {'name', 'instructions'}
            or type(settings['name']) is not str or not 1 <= len(settings['name']) <= 128
            or any(ord(c) < 32 for c in settings['name'])
            or type(settings['instructions']) is not str or len(settings['instructions']) > 32768
            or '\x00' in settings['instructions']):
        raise ServiceError('invalid_request', 400)
    # Snapshot mutable caller input before exact-payload persistence.
    return decode_json(canonical(payload).encode('ascii'))


def _private_dir_at(parent_fd, name, uid=1000):
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        os.chown(name, uid, uid, dir_fd=parent_fd, follow_symlinks=False)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    info = os.fstat(fd)
    if info.st_uid != uid or info.st_gid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise ServiceError('unsafe_initialization', 503)
    return fd


def _initial_file(parent_fd, name, data):
    existing = False
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
    except FileExistsError:
        existing = True
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    else:
        try:
            os.fchown(fd, 1000, 1000)
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent_fd)
        except BaseException:
            os.close(fd)
            raise
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 1000
                or info.st_gid != 1000 or stat.S_IMODE(info.st_mode) != 0o600):
            raise ServiceError('unsafe_initialization', 503)
        if existing:
            with os.fdopen(os.dup(fd), 'rb') as stream:
                if stream.read(len(data) + 1) != data:
                    raise ServiceError('unsafe_initialization', 503)
    finally:
        os.close(fd)


def initialize_files(instance, evidence):
    """Fixed filenames only. Existing initialized agent files are never overwritten."""
    root_fd = os.open(evidence['host_path'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    state_fd = workspace_fd = None
    try:
        state_fd = _private_dir_at(root_fd, 'state')
        # Same bootstrap accepted for the pinned Stage-2 image; no public origins.
        config = {'gateway': {'mode': 'local', 'bind': 'lan',
            'auth': {'mode': 'token', 'token': instance['gateway_token']},
            'controlUi': {'allowedOrigins': ['http://localhost:18789', 'http://127.0.0.1:18789']}}}
        _initial_file(state_fd, 'openclaw.json', (canonical(config) + '\n').encode('utf-8'))
        # A torn initial write must not silently permit a container to start.
        fd = os.open('openclaw.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=state_fd)
        with os.fdopen(fd, 'rb') as stream:
            blob = stream.read(65537)
        if len(blob) > 65536:
            raise ServiceError('unsafe_initialization', 503)
        try:
            current = decode_json(blob)
            if (current['gateway']['mode'] != 'local'
                    or current['gateway']['auth']['token'] != instance['gateway_token']):
                raise ValueError()
        except (ServiceError, KeyError, TypeError, ValueError):
            raise ServiceError('unsafe_initialization', 503) from None
        workspace_fd = _private_dir_at(state_fd, 'workspace')
        settings = json.loads(instance['settings'])
        user = '# ' + settings['name'] + '\n\n' + settings['instructions'] + '\n'
        _initial_file(workspace_fd, 'USER.md', user.encode('utf-8'))
    finally:
        for fd in (workspace_fd, state_fd, root_fd):
            if fd is not None:
                os.close(fd)


class RuntimeService:
    """Portable injectable controller; production dependencies are built only by CLI."""
    def __init__(self, profile, store, volumes, engine, metrics, *, capacities,
                 disk_floor_bytes, clock=time.monotonic, initialize=initialize_files):
        fingerprint = hashlib.sha256(canonical(asdict(profile)).encode('ascii')).hexdigest()
        if (store.profile_version, store.profile_hash) != (profile.profile_version, fingerprint):
            raise StoreError('profile_drift')
        self.profile, self.store, self.volumes = profile, store, volumes
        self.engine, self.metrics, self.capacities = engine, metrics, tuple(capacities)
        self.disk_floor_bytes, self.clock, self.initialize = disk_floor_bytes, clock, initialize
        self.lock = threading.RLock()

    def _sample(self):
        try:
            sample = self.metrics.snapshot()
            physical = (sample['total_ram_bytes'], sample['total_cpu_millicores'], sample['total_disk_bytes'])
            if (len(self.capacities) != 3 or any(type(c) is not int or not 0 < c <= p
                    for c, p in zip(self.capacities, physical))):
                raise ValueError()
            return sample
        except (MetricsUnavailable, OSError, ValueError, KeyError):
            raise ServiceError('metrics_unavailable', 503) from None

    def _admit(self, *, quota, preparing=False):
        sample, limits = self._sample(), self.profile.agent_limits
        decision = evaluate_admission(mode=self.profile.mode, now=self.clock(),
            sampled_at=sample['sampled_at'], cpu_window_seconds=sample['cpu_window_seconds'],
            total_ram_bytes=sample['total_ram_bytes'], available_ram_bytes=sample['available_ram_bytes'],
            cpu_percent=sample['cpu_percent'], requested_ram_bytes=limits.ram_bytes,
            free_disk_bytes=sample['free_disk_bytes'], requested_disk_bytes=limits.disk_bytes,
            disk_floor_bytes=self.disk_floor_bytes, disk_quota_verified=quota)
        reasons = set(decision.reasons)
        if preparing:
            # This sole exception permits quota PREPARATION, never runtime execution.
            reasons.discard('disk_quota_unverified')
        if reasons:
            raise ServiceError('admission_denied', 503)
        return decision

    def _inspect(self, instance_id):
        try:
            info = self.engine.inspect(instance_id)
            if type(info) is not dict or info.get('state') not in {
                    'absent', 'not_created', 'missing', 'created', 'running', 'stopped',
                    'exited', 'paused', 'restarting', 'dead', 'failed'}:
                raise ValueError()
            return info
        except Exception:
            raise ServiceError('runtime_unavailable', 503) from None

    @staticmethod
    def _absent(info):
        return info['state'] in {'absent', 'not_created', 'missing'}

    def _storage(self, instance, *, prepare=False):
        try:
            if prepare:
                self.volumes.prepare(instance['id'], instance['disk'])
            evidence = self.volumes.verify(instance['id'], instance['disk'])
            if (type(evidence) is not dict or evidence.get('disk_quota_verified') is not True
                    or type(evidence.get('host_path')) is not str
                    or type(evidence.get('project_id')) is not int):
                raise ServiceError('quota_unverified', 503)
            old = json.loads(instance['storage']) if instance['storage'] else None
            if old and any(old.get(key) != evidence.get(key) for key in ('host_path', 'project_id')):
                raise ServiceError('quota_unverified', 503)
            self.store.storage_ready(instance['id'], evidence)
            return evidence
        except ServiceError:
            raise
        except Exception as error:
            code = getattr(error, 'code', 'storage_operation_failed')
            if type(code) is not str or re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code) is None:
                code = 'storage_operation_failed'
            print('Storage guard: ' + code, file=sys.stderr, flush=True)
            raise ServiceError('storage_unavailable', 503) from None

    def _view(self, instance=None, operation=None, info=None):
        state = instance['state'] if instance else 'not_created'
        runtime = dict(state=state, gateway='not_connected', model='not_connected',
                       telegram='not_connected', instance_id=instance['id'] if instance else None,
                       settings_revision=instance['revision'] if instance else None)
        if info and instance and instance['active']:
            runtime['state'] = (state if state in {'preparing', 'failed', 'not_created'} else 'absent') if self._absent(info) else info['state']
            # Never return arbitrary engine fields, endpoints, tokens or Docker IDs.
            gateway = info.get('gateway')
            if gateway in ('connected', 'ready', 'starting', 'not_connected', 'unavailable', 'unknown', 'not_ready'):
                runtime['gateway'] = gateway
        result = dict(runtime=runtime, capabilities=dict(provisioning=False, chat=False, telegram=False, metrics=False))
        try:
            sample = self._sample()
            result['capabilities']['metrics'] = (sample['cpu_window_seconds'] >= 60
                and 0 <= self.clock() - sample['sampled_at'] <= 10)
            self._admit(quota=False, preparing=True)
            limits = self.profile.agent_limits
            result['capabilities']['provisioning'] = all(
                used + (0 if instance and instance['active'] else requested) <= capacity for used, requested, capacity in zip(
                    self.store.totals(), (limits.ram_bytes, limits.cpu_millicores, limits.disk_bytes), self.capacities))
        except (ServiceError, ValueError):
            pass
        if instance and instance['active']:
            retry_key = self.store.create_retry(instance['id'])
            if retry_key:
                # Owner-scoped operation identifier, not a credential. Enables
                # recovery from another tab/device without changing the snapshot.
                runtime['pending_create_key'] = retry_key
                runtime['pending_create_revision'] = instance['revision']
        if operation:
            result['operation'] = {'id': operation['id'], 'status': operation['status']}
        return result

    def me(self, payload):
        if type(payload) is not dict or set(payload) != {'actor_id'}:
            raise ServiceError('invalid_request', 400)
        owner = actor(payload['actor_id'])
        with self.lock:
            instance = self.store.current(owner)
            info = self._inspect(instance['id']) if instance else None
            result = self._view(instance, info=info)
            try:
                sample = self._sample()
                result['capabilities']['metrics'] = (sample['cpu_window_seconds'] >= 60
                    and 0 <= self.clock() - sample['sampled_at'] <= 10)
                result['metrics'] = dict(sample, reserved_ram_bytes=self.store.totals()[0],
                                         reserved_cpu_millicores=self.store.totals()[1],
                                         reserved_disk_bytes=self.store.totals()[2])
            except ServiceError:
                result['capabilities']['metrics'] = False
            return result

    def replay(self, payload):
        if type(payload) is not dict or set(payload) != {
                'actor_id', 'action', 'idempotency_key', 'settings_revision'}:
            raise ServiceError('invalid_request', 400)
        owner = actor(payload['actor_id'])
        if (type(payload['action']) is not str
                or payload['action'] not in {'create', 'start', 'stop', 'restart', 'remove'}
                or type(payload['idempotency_key']) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', payload['idempotency_key']) is None
                or type(payload['settings_revision']) is not int
                or not 0 <= payload['settings_revision'] <= 2**63 - 1):
            raise ServiceError('invalid_request', 400)
        with self.lock:
            saved = self.store.saved_request(owner, payload['idempotency_key'])
            if saved is None:
                raise ServiceError('operation_not_found', 404)
            if (saved['action'] != payload['action']
                    or saved['settings_revision'] != payload['settings_revision']):
                raise ServiceError('idempotency_conflict')
            return self.action(saved)

    def action(self, payload):
        payload = validate_action(payload)
        operation = None
        with self.lock:
            try:
                previous = self.store.lookup(payload)
                if previous and previous['status'] == 'completed':
                    instance = self.store.instance(previous['instance_id'])
                    info = self._inspect(instance['id']) if instance['active'] else None
                    return self._view(instance, previous, info)
                if previous:
                    instance = self.store.instance(previous['instance_id'])
                    current = self.store.current(payload['actor_id'])
                    if not instance['active'] or current is None or current['id'] != instance['id']:
                        raise ServiceError('instance_retired')
                if payload['action'] == 'create':
                    self._admit(quota=False, preparing=True)
                limits = self.profile.agent_limits
                operation = self.store.intent(payload, (limits.ram_bytes, limits.cpu_millicores, limits.disk_bytes), self.capacities)
                self.store.pending(operation['id'])
                instance = self.store.instance(operation['instance_id'])
                instance_id, action = instance['id'], payload['action']
                if action in {'create', 'start', 'restart'}:
                    evidence = self._storage(instance, prepare=action == 'create')
                    if not instance['initialized']:
                        self.initialize(instance, evidence)
                        self.store.initialized(instance_id)
                    # Re-observe AFTER real quota verification. Intent is not a permit.
                    self._admit(quota=evidence['disk_quota_verified'])
                info = self._inspect(instance_id)
                if action == 'create':
                    # create is idempotent and verifies the EXACT expected spec/token
                    # when recovering an existing labelled container.
                    self._admit(quota=evidence['disk_quota_verified'])
                    self.engine.create(instance_id, evidence['host_path'], limits, instance['gateway_token'])
                    info = self._inspect(instance_id)
                    if self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    # Also on crash recovery/adoption, verify and re-evaluate right before start.
                    evidence = self._storage(self.store.instance(instance_id))
                    self._admit(quota=evidence['disk_quota_verified'])
                    if info['state'] != 'running':
                        self.engine.start(instance_id)
                elif action == 'start':
                    if self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    self._admit(quota=evidence['disk_quota_verified'])
                    if info['state'] != 'running':
                        self.engine.start(instance_id)
                elif action == 'restart':
                    if self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    self._admit(quota=evidence['disk_quota_verified'])
                    self.engine.restart(instance_id)
                elif action == 'stop':
                    if not self._absent(info) and info['state'] not in {'stopped', 'exited', 'created'}:
                        self.engine.stop(instance_id)
                elif action == 'remove':
                    if not self._absent(info):
                        self.engine.remove(instance_id)
                info = self._inspect(instance_id)
                if action in {'create', 'start', 'restart'} and info['state'] != 'running':
                    raise ServiceError('runtime_unavailable', 503)
                if action == 'stop' and not (self._absent(info) or info['state'] in {'stopped', 'exited', 'created', 'failed'}):
                    raise ServiceError('runtime_unavailable', 503)
                if action == 'remove' and not self._absent(info):
                    raise ServiceError('runtime_unavailable', 503)
                state = 'removed' if action == 'remove' else ('not_created' if self._absent(info) else info['state'])
                self.store.complete(operation['id'], state, info.get('container_id'))
                operation['status'] = 'completed'
                return self._view(self.store.instance(instance_id), operation, info)
            except StoreError as error:
                status = 404 if error.code == 'instance_not_found' else (503 if error.code == 'capacity_exhausted' else 409)
                raise ServiceError(error.code if error.code in MESSAGES else 'internal_error', status) from None
            except Exception as error:
                safe = error if isinstance(error, ServiceError) else ServiceError('runtime_unavailable', 503)
                if operation:
                    if safe.code in {'quota_unverified', 'storage_unavailable'} and payload['action'] in {'create', 'start', 'restart'}:
                        # A crash-recovered container may already be running. Do
                        # not leave it running after failed storage verification.
                        try:
                            found = self._inspect(operation['instance_id'])
                            if not self._absent(found) and found['state'] not in {'stopped', 'exited', 'created'}:
                                self.engine.stop(operation['instance_id'])
                                found = self._inspect(operation['instance_id'])
                                if found['state'] not in {'stopped', 'exited', 'created', 'failed'}:
                                    raise ServiceError('runtime_unavailable', 503)
                                self.store.observe(operation['instance_id'], found['state'], found.get('container_id'))
                        except Exception:
                            safe = ServiceError('runtime_unavailable', 503)
                    self.store.fail(operation['id'], safe.code)
                raise safe from None

    def reconcile(self):
        """Inspect known IDs only; never create/start queued or failed intents."""
        with self.lock:
            for instance in self.store.all_instances():
                info = self._inspect(instance['id'])
                if not instance['active']:
                    if not self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    continue
                if info['state'] in {'running', 'restarting', 'paused'}:
                    try:
                        self._storage(instance)
                    except ServiceError:
                        self.engine.stop(instance['id'])
                        info = self._inspect(instance['id'])
                        if info['state'] not in {'stopped', 'exited', 'created', 'failed'}:
                            raise ServiceError('runtime_unavailable', 503) from None
                state = instance['state'] if self._absent(info) else info['state']
                self.store.observe(instance['id'], state, info.get('container_id'))


class RuntimeApplication(RuntimeService):
    """DI entry point. Inject all adapters plus initialize for non-Linux smoke.

    No directories are created. A default store opens an existing state_dir;
    default adapters remain inert until a controller method is explicitly called.
    """
    def __init__(self, config, profile, store=None, volumes=None, engine=None,
                 metrics=None, *, initialize=initialize_files, clock=time.monotonic):
        if store is None:
            fingerprint = hashlib.sha256(canonical(asdict(profile)).encode('ascii')).hexdigest()
            store = RuntimeStore(Path(config['state_dir']) / 'runtime.sqlite3', profile.profile_version, fingerprint)
        if volumes is None:
            from .volumes import XfsVolumes
            volumes = XfsVolumes(profile, config['state_dir'])
        if engine is None:
            from .docker_engine import DockerEngine
            engine = DockerEngine(config['image'])
        if metrics is None:
            metrics = HostMetrics(profile.storage.mountpoint, clock=clock)
        super().__init__(profile, store, volumes, engine, metrics,
                         capacities=tuple(config[k] for k in ('capacity_ram_bytes', 'capacity_cpu_millicores', 'capacity_disk_bytes')),
                         disk_floor_bytes=config['disk_floor_bytes'], initialize=initialize, clock=clock)

    def close(self):
        if hasattr(self.metrics, 'close'):
            self.metrics.close()
        self.store.close()


CONFIG_KEYS = {'profile_path', 'state_dir', 'socket_path', 'token_file', 'image',
               'capacity_ram_bytes', 'capacity_cpu_millicores', 'capacity_disk_bytes', 'disk_floor_bytes'}


def load_service_config(path):
    with open(path, 'rb') as stream:
        blob = stream.read(65537)
    if len(blob) > 65536:
        raise ValueError('Invalid service config')
    config = decode_json(blob)
    if type(config) is not dict or set(config) != CONFIG_KEYS:
        raise ValueError('Invalid service config')
    for key in ('profile_path', 'state_dir', 'socket_path', 'token_file'):
        value = config[key]
        if (type(value) is not str or len(value) > 4096 or not value.startswith('/')
                or str(PurePosixPath(value)) != value or '..' in PurePosixPath(value).parts
                or value == '/' or '\x00' in value):
            raise ValueError('Invalid service config path')
    if (Path(config['state_dir']) == Path('/') or Path(config['socket_path']).parent == Path('/')
            or Path(config['socket_path']).name != 'control.sock'
            or Path(config['token_file']) != Path(config['state_dir']) / 'service.token'):
        raise ValueError('Invalid service state/socket/token layout')
    if len(config['socket_path'].encode('utf-8')) > 107:
        raise ValueError('Socket path exceeds Linux limit')
    for key in ('capacity_ram_bytes', 'capacity_cpu_millicores', 'capacity_disk_bytes', 'disk_floor_bytes'):
        if type(config[key]) is not int or not 0 <= config[key] <= 2**63 - 1:
            raise ValueError('Invalid service capacity')
        if key != 'disk_floor_bytes' and config[key] == 0:
            raise ValueError('Invalid service capacity')
    if (type(config['image']) is not str or re.fullmatch(
            r'(?:sha256:[a-f0-9]{64}|[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64})', config['image']) is None):
        raise ValueError('Immutable image digest required')
    return config


def _trusted_directory(path, mode=None, create=False):
    path = Path(path)
    if create and not os.path.lexists(path):
        _trusted_directory(path.parent)
        path.mkdir(mode=mode)
        os.chown(path, 0, 0, follow_symlinks=False)
        os.chmod(path, mode, follow_symlinks=False)  # Newly created dedicated directory only.
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    if str(path.resolve(strict=True)) != str(path):
        raise ValueError('Unsafe directory')
    for directory in (path, *path.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe directory')
    if mode is not None and (stat.S_IMODE(path.stat().st_mode) != mode or path.stat().st_gid != 0):
        raise ValueError('Unsafe directory mode')


def _root_file(path, mode, *, create=False):
    flags = os.O_RDWR | os.O_NOFOLLOW
    if create:
        try:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError:
            fd = os.open(path, flags)
    else:
        fd = os.open(path, flags)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode):
        os.close(fd)
        raise ValueError('Unsafe private file')
    return fd


def _service_token(path):
    _trusted_directory(Path(path).parent)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    except FileExistsError:
        pass
    else:
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o640)
            os.write(fd, secrets.token_urlsafe(48).encode('ascii'))
            os.fsync(fd)
        finally:
            os.close(fd)
        parent_fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    fd = _root_file(path, 0o640)
    with os.fdopen(fd, 'rb') as stream:
        token = stream.read(257)
    if re.fullmatch(rb'[A-Za-z0-9_-]{32,256}', token) is None:
        raise ValueError('Invalid service secret')
    return token


class APIHandler(BaseHTTPRequestHandler):
    server_version = 'Supervisor'
    sys_version = ''

    def log_message(self, *_args):
        pass

    def _json(self, status, value):
        body = canonical(value).encode('ascii')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self._json(code, {'code': 'invalid_request', 'message': MESSAGES['invalid_request']})

    def do_POST(self):
        try:
            headers = self.headers.get_all('Authorization', [])
            expected = b'Bearer ' + self.service_secret
            supplied = headers[0].encode('utf-8') if len(headers) == 1 else b''
            if not hmac.compare_digest(supplied, expected):
                raise ServiceError('unauthorized', 401)
            if self.path not in ('/v1/me', '/v1/actions', '/v1/replay'):
                raise ServiceError('not_found', 404)
            lengths = self.headers.get_all('Content-Length', [])
            if (len(lengths) != 1 or re.fullmatch(r'[0-9]{1,10}', lengths[0]) is None
                    or self.headers.get_all('Transfer-Encoding', [])
                    or self.headers.get_content_type() != 'application/json'):
                raise ServiceError('invalid_request', 400)
            length = int(lengths[0])
            if length > 65536:
                raise ServiceError('body_too_large', 413)
            blob = self.rfile.read(length)
            if len(blob) != length:
                raise ServiceError('invalid_request', 400)
            payload = decode_json(blob)
            controller = self.controller
            dispatch = {'/v1/me': controller.me, '/v1/actions': controller.action,
                        '/v1/replay': controller.replay}
            result = dispatch[self.path](payload)
            self._json(200, result)
        except ServiceError as error:
            self._json(error.status, {'code': error.code, 'message': MESSAGES.get(error.code, MESSAGES['internal_error'])})
        except Exception:
            self._json(500, {'code': 'internal_error', 'message': MESSAGES['internal_error']})

    def do_GET(self):
        self._json(405, {'code': 'method_not_allowed', 'message': MESSAGES['method_not_allowed']})

    do_PUT = do_DELETE = do_PATCH = do_GET


def create_handler(app, token):
    """Export a handler class for injected test transport; no listener/root checks.

    Production uses AF_UNIX exclusively. A caller may use HTTPServer ONLY for a
    portable fake-adapter smoke; this factory itself never binds any transport.
    """
    secret = token.encode('ascii') if isinstance(token, str) else token
    if type(secret) is not bytes or not secret or len(secret) > 256:
        raise ValueError('Explicit bounded bearer token required')

    class BoundHandler(APIHandler):
        controller = app
        service_secret = secret

    return BoundHandler


def serve(config):
    # Deliberately imported only beyond explicit Linux/root CLI gate.
    import fcntl
    from .volumes import XfsVolumes
    from .docker_engine import DockerEngine
    os.umask(0o077)
    profile = load_profile(config['profile_path'])
    # Validate trusted paths and physical ceilings BEFORE creating state/socket files.
    profile_path = Path(config['profile_path'])
    _trusted_directory(profile_path.parent)
    profile_info = profile_path.lstat()
    if (not stat.S_ISREG(profile_info.st_mode) or profile_info.st_uid != 0
            or profile_info.st_mode & 0o022 or str(profile_path.resolve(strict=True)) != str(profile_path)):
        raise ValueError('Unsafe profile file')
    state = Path(config['state_dir'])
    socket_path = Path(config['socket_path'])
    pool = Path(profile.storage.mountpoint)
    if (state == Path('/') or socket_path.parent == Path('/') or socket_path.name != 'control.sock'
            or Path(config['token_file']) != state / 'service.token'
            or state.is_relative_to(pool) or socket_path.is_relative_to(state)
            or socket_path.parent.is_relative_to(pool) or state.is_relative_to(socket_path.parent)
            or Path(config['token_file']).is_relative_to(pool)):
        raise ValueError('Invalid state layout')
    for directory, mode in ((state, 0o700), (socket_path.parent, 0o750)):
        if os.path.lexists(directory):
            _trusted_directory(directory, mode)
        else:
            _trusted_directory(directory.parent)
    for target in (Path(config['token_file']), socket_path):
        if target.is_symlink():
            raise ValueError('Unsafe service target')
    engine = DockerEngine(config['image'])
    engine.check_host()
    metrics = HostMetrics(profile.storage.mountpoint)
    metrics.collect()
    capacities = tuple(config[key] for key in ('capacity_ram_bytes', 'capacity_cpu_millicores', 'capacity_disk_bytes'))
    physical_sample = metrics.snapshot()
    physical = (physical_sample['total_ram_bytes'], physical_sample['total_cpu_millicores'], physical_sample['total_disk_bytes'])
    if any(type(c) is not int or not 0 < c <= p for c, p in zip(capacities, physical)):
        raise ValueError('Capacity exceeds physical total')
    _trusted_directory(state, 0o700, create=True)
    _trusted_directory(socket_path.parent, 0o750, create=True)
    lock_fd = _root_file(state / 'service.lock', 0o600, create=True)
    store = server = None
    bound_identity = None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        secret = _service_token(config['token_file'])
        db_path = state / 'runtime.sqlite3'
        os.close(_root_file(db_path, 0o600, create=True))
        for suffix in ('-wal', '-shm'):
            if os.path.lexists(str(db_path) + suffix):
                os.close(_root_file(str(db_path) + suffix, 0o600))
        fingerprint = hashlib.sha256(canonical(asdict(profile)).encode('ascii')).hexdigest()
        store = RuntimeStore(db_path, profile.profile_version, fingerprint)
        metrics.start()
        controller = RuntimeService(profile, store, XfsVolumes(profile, state), engine,
                                    metrics, capacities=capacities, disk_floor_bytes=config['disk_floor_bytes'])
        controller._sample()  # Reject explicit ceilings above physical totals.
        if any(used > maximum for used, maximum in zip(store.totals(), capacities)):
            raise ValueError('Existing reservations exceed configured ceilings')
        controller.reconcile()
        if os.path.lexists(socket_path):
            info = socket_path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                raise ValueError('Unsafe socket target')
            # Never unlink a live listener using another state-directory lock.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(1)
                try:
                    probe.connect(str(socket_path))
                except OSError as error:
                    if error.errno != errno.ECONNREFUSED:
                        raise ValueError('Socket target is not safely stale') from None
                else:
                    raise ValueError('Socket is already serving')
            if socket_path.lstat() != info:
                raise ValueError('Socket target changed')
            socket_path.unlink()

        class UnixServer(socketserver.UnixStreamServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(30)
                return connection, address

        server = UnixServer(str(socket_path), create_handler(controller, secret))
        os.chown(socket_path, 0, 0)
        os.chmod(socket_path, 0o660)
        info = socket_path.lstat()
        bound_identity = (info.st_dev, info.st_ino)
        server.controller, server.service_secret = controller, secret
        print('Supervisor listening on private Unix socket; CPU window warms for 60 seconds.', flush=True)
        server.serve_forever(poll_interval=0.5)
    finally:
        if server:
            server.server_close()
        if bound_identity and os.path.lexists(socket_path):
            info = socket_path.lstat()
            if (info.st_dev, info.st_ino) == bound_identity:
                socket_path.unlink()
        if metrics:
            metrics.close()
        if store:
            store.close()
        os.close(lock_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Privileged Linux AF_UNIX runtime service (no TCP).')
    parser.add_argument('--config', required=True)
    parser.add_argument('--enable-host-runtime', action='store_true', help='Explicitly permit privileged host runtime side effects')
    args = parser.parse_args(argv)
    if not args.enable_host_runtime or sys.platform != 'linux' or os.geteuid() != 0:
        print('Service blocked: explicit --enable-host-runtime, Linux and root are required.', file=sys.stderr)
        return 2
    try:
        serve(load_service_config(args.config))
    except KeyboardInterrupt:
        return 0
    except Exception:
        print('Service blocked: check trusted configuration, permissions, profile binding, storage and runtime.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
