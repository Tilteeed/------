"""Root-only, explicitly enabled AF_UNIX host runtime service; stdlib only.

No imports open files, collect metrics, touch Docker, or start a listener.
The trusted parent authenticates users; actor_id is accepted only with the
service bearer secret. This is not a browser-facing authentication API.
"""
import argparse
from dataclasses import asdict, dataclass
import hashlib
import hmac
import ipaddress
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
import struct
import sys
import threading
import time
from typing import Any
from urllib.parse import quote, urlsplit

from .config import load_profile, _unique_object, _reject_constant
from .config_lock import (
    initialize_config_fd, is_immutable, read_managed_config_fd,
    replace_locked_config_at, verify_config_fd,
)
from .metrics import HostMetrics, MetricsUnavailable
from .openclaw_config import build_gateway_config
from .ollama_config import (
    MODEL_NAMES, ollama_policy_matches_config,
    replace_ollama_policy_in_config, validate_ollama_config,
)
from .ollama_firewall import validate_ollama_route_inputs
from .policy import evaluate_admission
from .runtime_store import RuntimeStore, StoreError, canonical
from .workspace_files import RetainedWorkspace, WorkspaceFileError


class ServiceError(Exception):
    def __init__(self, code, status=409):
        self.code, self.status = code, status
        super().__init__(code)


@dataclass(frozen=True)
class WorkspaceDownload:
    name: str
    content: bytes


_CONTROL_UI_INSTANCE_RE = re.compile(r'[0-9a-f]{32}\Z')
_CONTROL_UI_PROXY_TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{40,64}\Z')
_CONTROL_UI_DOCKER_ID_RE = re.compile(r'[0-9a-f]{64}\Z')
_CONTROL_UI_SIDECAR_PORT = 18790


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
    'purge_scrub_unverified': 'Purge cleanup is pending; retry using the original operation key.',
    'profile_drift': 'Deployment profile differs from the durable binding.',
    'unsafe_initialization': 'Initial private runtime files could not be verified.',
    'model_policy_unverified': 'Administrator model policy could not be verified.',
    'invalid_admin_model': 'Unsupported administrator-selected model.',
    'admin_config_uninitialized': 'Administrator model selection is not initialized.',
    'admin_config_conflict': 'Administrator model selection changed; reload and retry.',
    'admin_config_invalid': 'Administrator model selection failed integrity checks.',
    'internal_error': 'Service operation failed.',
    'invalid_file_path': 'Invalid workspace path.',
    'file_not_found': 'Workspace file not found.',
    'file_too_large': 'Workspace file exceeds the download limit.',
    'preview_not_supported': 'File cannot be previewed as UTF-8 text.',
    'file_changed': 'Workspace file changed while it was being read.',
    'workspace_unavailable': 'Retained workspace is unavailable or failed verification.',
    'maintenance_in_progress': 'Host maintenance is in progress; lifecycle changes are blocked.',
    'migration_plan_changed': 'Docker state changed after the migration plan; create a new plan.',
    'migration_preflight_blocked': 'Migration preflight found an unsafe or ambiguous instance.',
    'migration_in_progress': 'Migration is already in progress; use status or resume.',
    'migration_not_found': 'No saved migration exists to resume.',
    'migration_journal_unavailable': 'Migration journal is unavailable or failed integrity checks.',
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
    common = {'actor_id', 'action', 'idempotency_key', 'settings_revision'}
    if type(payload) is not dict:
        raise ServiceError('invalid_request', 400)
    action = payload.get('action')
    expected = common | ({'settings'} if action != 'restore' else set())
    if type(action) is str and action in {'purge', 'restore'}:
        expected.add('instance_id')
    if set(payload) != expected:
        raise ServiceError('invalid_request', 400)
    actor(payload['actor_id'])
    if type(action) is not str or action not in {'create', 'start', 'stop', 'restart', 'remove', 'purge', 'restore'}:
        raise ServiceError('invalid_request', 400)
    if action in {'purge', 'restore'} and (type(payload['instance_id']) is not str
            or re.fullmatch(r'[0-9a-f]{32}', payload['instance_id']) is None):
        raise ServiceError('invalid_request', 400)
    key = payload['idempotency_key']
    if type(key) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', key) is None:
        raise ServiceError('invalid_request', 400)
    revision = payload['settings_revision']
    if type(revision) is not int or not 0 <= revision <= 2**63 - 1:
        raise ServiceError('invalid_request', 400)
    if action != 'restore':
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


def _initial_managed_config_at(parent_fd, data, *, require_immutable):
    """Create or harden only the fixed Gateway config path before container creation."""
    if (type(parent_fd) is not int or parent_fd < 0 or type(data) is not bytes
            or not 1 <= len(data) <= 65536 or type(require_immutable) is not bool):
        raise ServiceError('unsafe_initialization', 503)
    nofollow = getattr(os, 'O_NOFOLLOW', None)
    if type(nofollow) is not int:
        raise ServiceError('unsafe_initialization', 503)
    name = 'openclaw.json'
    fd = None
    try:
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
                         0o600, dir_fd=parent_fd)
        except FileExistsError:
            fd = os.open(name, os.O_RDONLY | nofollow, dir_fd=parent_fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_size != len(data)):
                raise ServiceError('unsafe_initialization', 503)
            with os.fdopen(os.dup(fd), 'rb') as stream:
                existing = stream.read(65537)
            if existing != data:
                raise ServiceError('unsafe_initialization', 503)
            metadata = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            if metadata == (0, 1000, 0o440):
                if not require_immutable:
                    verify_config_fd(fd, data, require_immutable=False)
                    return
                if is_immutable(fd) is True:
                    verify_config_fd(fd, data, require_immutable=True)
                    return
            elif metadata != (1000, 1000, 0o600):
                raise ServiceError('unsafe_initialization', 503)
            identity = (info.st_dev, info.st_ino)
            os.close(fd)
            fd = None
            fd = os.open(name, os.O_RDWR | nofollow, dir_fd=parent_fd)
            writable_info = os.fstat(fd)
            if (writable_info.st_dev, writable_info.st_ino) != identity:
                raise ServiceError('unsafe_initialization', 503)
        initialize_config_fd(fd, data, require_immutable=require_immutable)
        os.fsync(parent_fd)
        verify_config_fd(fd, data, require_immutable=require_immutable)
    except ServiceError:
        raise
    except Exception:
        raise ServiceError('unsafe_initialization', 503) from None
    finally:
        if fd is not None:
            os.close(fd)


def initialize_files(instance, evidence, ollama_config=None):
    """Fixed filenames only. Existing initialized agent files are never overwritten."""
    root_fd = os.open(evidence['host_path'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    state_fd = workspace_fd = None
    try:
        state_fd = _private_dir_at(root_fd, 'state')
        # Per-agent profile config trusts one exact sidecar IP and one owner;
        # the legacy/internal profiles retain token auth until explicit migration.
        try:
            config = build_gateway_config(instance, ollama=ollama_config)
        except ValueError:
            raise ServiceError('unsafe_initialization', 503) from None
        config_blob = (canonical(config) + '\n').encode('utf-8')
        _initial_managed_config_at(
            state_fd, config_blob, require_immutable=ollama_config is not None)
        # A torn initial write must not silently permit a container to start.
        fd = os.open('openclaw.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=state_fd)
        with os.fdopen(fd, 'rb') as stream:
            blob = stream.read(65537)
        if len(blob) > 65536:
            raise ServiceError('unsafe_initialization', 503)
        try:
            current = decode_json(blob)
            if current != config:
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
                 disk_floor_bytes, clock=time.monotonic, initialize=initialize_files,
                 network_profile_default=RuntimeStore.NETWORK_PROFILE_LEGACY,
                 control_ui_domain=None, agent_network_pool=None,
                 frontend_network_pool=None, ollama_config=None):
        fingerprint = hashlib.sha256(canonical(asdict(profile)).encode('ascii')).hexdigest()
        if (store.profile_version, store.profile_hash) != (profile.profile_version, fingerprint):
            raise StoreError('profile_drift')
        if type(network_profile_default) is not str or network_profile_default not in RuntimeStore.NETWORK_PROFILES:
            raise ValueError('Unsupported default network profile')
        if control_ui_domain is not None and (type(control_ui_domain) is not str
                or len(control_ui_domain) > 253 or len(control_ui_domain.split('.')) < 2
                or any(_CONTROL_UI_DOMAIN_LABEL.fullmatch(label) is None
                       for label in control_ui_domain.split('.'))):
            raise ValueError('Invalid Control UI domain')
        if (agent_network_pool is None) != (frontend_network_pool is None):
            raise ValueError('Both Control UI network pools must be provided together')
        if agent_network_pool is not None:
            agent_pool = _network_pool(agent_network_pool)
            frontend_pool = _network_pool(frontend_network_pool)
            if agent_pool.overlaps(frontend_pool):
                raise ValueError('Control UI network pools must not overlap')
            agent_network_pool, frontend_network_pool = str(agent_pool), str(frontend_pool)
        if network_profile_default == RuntimeStore.NETWORK_PROFILE_PROXY:
            if control_ui_domain is None:
                raise ValueError('Control UI domain required for proxy profile')
            if agent_network_pool is None:
                raise ValueError('Control UI network pools required for proxy profile')
        self.profile, self.store, self.volumes = profile, store, volumes
        self.engine, self.metrics, self.capacities = engine, metrics, tuple(capacities)
        self.disk_floor_bytes, self.clock, self.initialize = disk_floor_bytes, clock, initialize
        self.network_profile_default = network_profile_default
        self.control_ui_domain = control_ui_domain
        self.agent_network_pool = agent_network_pool
        self.frontend_network_pool = frontend_network_pool
        self.ollama_config = (None if ollama_config is None else
                              asdict(validate_ollama_config(ollama_config)))
        if self.ollama_config is not None:
            selected_model = self.store.ollama_model_id()
            if selected_model is None:
                selected_model = self.store.seed_ollama_model_id(
                    self.ollama_config['default_model_id'])
            self.ollama_config = {**self.ollama_config,
                                  'default_model_id': selected_model}
        self.lock = threading.RLock()
        self.sidecar_migration: Any = None

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

    def _admit(self, *, quota, preparing=False, requested_disk_bytes=None, network_profile=None):
        sample, limits = self._sample(), self.profile.agent_limits
        network_profile = self.network_profile_default if network_profile is None else network_profile
        if type(network_profile) is not str or network_profile not in RuntimeStore.NETWORK_PROFILES:
            raise ServiceError('invalid_network_profile', 503)
        proxy_ram = (RuntimeStore.SIDECAR_RAM_BYTES
                     if network_profile == RuntimeStore.NETWORK_PROFILE_PROXY else 0)
        disk_request = limits.disk_bytes if requested_disk_bytes is None else requested_disk_bytes
        decision = evaluate_admission(mode=self.profile.mode, now=self.clock(),
            sampled_at=sample['sampled_at'], cpu_window_seconds=sample['cpu_window_seconds'],
            total_ram_bytes=sample['total_ram_bytes'], available_ram_bytes=sample['available_ram_bytes'],
            cpu_percent=sample['cpu_percent'], requested_ram_bytes=limits.ram_bytes + proxy_ram,
            free_disk_bytes=sample['free_disk_bytes'], requested_disk_bytes=disk_request,
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
            instance = self.store.instance(instance_id)
            expected_profile = instance['network_profile'] if instance else None
            actual_profile = info.get('network_profile')
            if not self._absent(info):
                if actual_profile not in RuntimeStore.NETWORK_PROFILES:
                    raise ValueError()
                config_policy_version = info.get('config_policy_version', 0)
                if type(config_policy_version) is not int or config_policy_version not in (0, 1):
                    raise ValueError()
                if expected_profile is not None and actual_profile != expected_profile:
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

    def _read_managed_gateway_config(self, evidence, *, require_immutable, with_bytes=False):
        if (type(with_bytes) is not bool or type(evidence) is not dict
                or type(evidence.get('host_path')) is not str):
            return None
        nofollow, directory = getattr(os, 'O_NOFOLLOW', None), getattr(os, 'O_DIRECTORY', None)
        if type(nofollow) is not int or type(directory) is not int:
            return None
        root_fd = state_fd = config_fd = None
        try:
            root_fd = os.open(evidence['host_path'], os.O_RDONLY | directory | nofollow)
            state_fd = os.open('state', os.O_RDONLY | directory | nofollow, dir_fd=root_fd)
            state_info = os.fstat(state_fd)
            if (not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != 1000
                    or state_info.st_gid != 1000 or stat.S_IMODE(state_info.st_mode) != 0o700):
                return None
            config_fd = os.open('openclaw.json', os.O_RDONLY | nofollow, dir_fd=state_fd)
            _info, blob = read_managed_config_fd(
                config_fd, require_immutable=require_immutable)
            current = decode_json(blob)
            if type(current) is not dict:
                return None
            return (current, blob) if with_bytes else current
        except Exception:
            return None
        finally:
            for fd in (config_fd, state_fd, root_fd):
                if fd is not None:
                    os.close(fd)

    def _open_gateway_state_fd(self, evidence):
        if type(evidence) is not dict or type(evidence.get('host_path')) is not str:
            raise ServiceError('storage_unavailable', 503)
        nofollow, directory = getattr(os, 'O_NOFOLLOW', None), getattr(os, 'O_DIRECTORY', None)
        if type(nofollow) is not int or type(directory) is not int:
            raise ServiceError('unsafe_initialization', 503)
        root_fd = state_fd = None
        try:
            root_fd = os.open(evidence['host_path'], os.O_RDONLY | directory | nofollow)
            state_fd = os.open('state', os.O_RDONLY | directory | nofollow, dir_fd=root_fd)
            info = os.fstat(state_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 1000 or info.st_gid != 1000
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ServiceError('unsafe_initialization', 503)
            result = state_fd
            state_fd = None
            return result
        except ServiceError:
            raise
        except Exception:
            raise ServiceError('unsafe_initialization', 503) from None
        finally:
            if state_fd is not None:
                os.close(state_fd)
            if root_fd is not None:
                os.close(root_fd)

    def _ollama_policy_file_matches(self, evidence):
        """Require the exact selected provider and tool policy in immutable config."""
        if self.ollama_config is None:
            return True
        current = self._read_managed_gateway_config(evidence, require_immutable=True)
        return current is not None and ollama_policy_matches_config(current, self.ollama_config)

    def _require_ollama_policy(self, instance, evidence, info):
        if self.ollama_config is None:
            return
        verified = (type(info) is dict and info.get('config_policy_version') == 1
                    and self._ollama_policy_file_matches(evidence))
        if verified:
            ensure_route = getattr(self.engine, 'ensure_ollama_route', None)
            try:
                route = ensure_route(instance['id']) if callable(ensure_route) else None
                verified = type(route) is dict and route.get('ready') is True
            except Exception:
                verified = False
        if verified:
            return
        if type(info) is dict and info.get('state') in {'running', 'restarting', 'paused'}:
            try:
                self.engine.stop(instance['id'])
                latest = self._inspect(instance['id'])
                if latest['state'] not in {'stopped', 'exited', 'created', 'failed'}:
                    raise ServiceError('runtime_unavailable', 503)
                self.store.observe(instance['id'], latest['state'], latest.get('container_id'))
            except ServiceError:
                raise
            except Exception:
                raise ServiceError('runtime_unavailable', 503) from None
        raise ServiceError('model_policy_unverified', 503)

    def _view(self, instance=None, operation=None, info=None):
        state = instance['state'] if instance else 'not_created'
        runtime = dict(state=state,
                       desired_state=(instance.get('desired_state', 'stopped') if instance else 'stopped'),
                       gateway='not_connected', model='not_connected',
                       telegram='not_connected', instance_id=instance['id'] if instance else None,
                       settings_revision=instance['revision'] if instance else None)
        if info and instance and instance['active']:
            runtime['state'] = (state if state in {'preparing', 'failed', 'not_created'} else 'absent') if self._absent(info) else info['state']
            # Never return arbitrary engine fields, endpoints, tokens or Docker IDs.
            network_profile = info.get('network_profile')
            gateway = info.get('gateway')
            if network_profile in RuntimeStore.NETWORK_PROFILES:
                runtime['network_profile'] = network_profile
            if gateway in ('connected', 'ready', 'starting', 'not_connected', 'unavailable', 'unknown', 'not_ready'):
                runtime['gateway'] = gateway
        result: dict[str, Any] = dict(runtime=runtime,
            capabilities=dict(provisioning=False, chat=False, telegram=False, metrics=False),
            retained=self.store.retained(instance['actor']) if instance else [])
        try:
            sample = self._sample()
            result['capabilities']['metrics'] = (sample['cpu_window_seconds'] >= 60
                and 0 <= self.clock() - sample['sampled_at'] <= 10)
            self._admit(quota=False, preparing=True)
            limits = self.profile.agent_limits
            requested = RuntimeStore._with_proxy_reservation(
                (limits.ram_bytes, limits.cpu_millicores, limits.disk_bytes),
                self.network_profile_default)
            result['capabilities']['provisioning'] = all(
                used + (0 if instance and instance['active'] else needed) <= capacity
                for used, needed, capacity in zip(self.store.totals(), requested, self.capacities))
        except (ServiceError, ValueError):
            pass
        if instance and instance['active']:
            retry_key = (self.store.create_retry(instance['id'])
                         if instance['state'] in {'preparing', 'failed'} else None)
            if retry_key:
                # Owner-scoped operation identifier, not a credential. Enables
                # recovery from another tab/device without changing the snapshot.
                runtime['pending_create_key'] = retry_key
                runtime['pending_create_revision'] = instance['revision']
            restore_retry = self.store.restore_retry(instance['id'])
            if restore_retry:
                runtime['pending_restore_key'] = restore_retry['key']
                runtime['pending_restore_revision'] = restore_retry['revision']
            purge_retry = self.store.purge_retry(instance['id'])
            if purge_retry:
                runtime['pending_purge_key'] = purge_retry['key']
                runtime['pending_purge_revision'] = purge_retry['revision']
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
            result['retained'] = self.store.retained(owner)
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

    def retained_workspace(self, payload):
        """Browse an owner's removed workspace only; never expose paths or private state."""
        if type(payload) is not dict:
            raise ServiceError('invalid_request', 400)
        action = payload.get('action')
        if type(action) is not str or action not in {'list', 'preview', 'download'}:
            raise ServiceError('invalid_request', 400)
        fields = {'actor_id', 'instance_id', 'action'}
        if action == 'list':
            fields.update({'directory', 'offset'})
        elif action in {'preview', 'download'}:
            fields.add('path')
        if set(payload) != fields or action not in {'list', 'preview', 'download'}:
            raise ServiceError('invalid_request', 400)
        owner = actor(payload['actor_id'])
        instance_id = payload['instance_id']
        if type(instance_id) is not str or re.fullmatch(r'[0-9a-f]{32}', instance_id) is None:
            raise ServiceError('invalid_request', 400)
        with self.lock:
            instance = self.store.retained_instance(owner, instance_id)
            if instance is None:
                raise ServiceError('instance_not_found', 404)
            evidence = self._storage(instance)
            reader = RetainedWorkspace(evidence['host_path'],
                                       mount_id=getattr(self.volumes, '_mount_id', None))
            try:
                if action == 'list':
                    return reader.list_directory(payload['directory'], payload['offset'])
                if action == 'preview':
                    return {'text': reader.preview(payload['path'])}
                name, content = reader.download(payload['path'])
                return WorkspaceDownload(name, content)
            except WorkspaceFileError as error:
                statuses = {'invalid_file_path': 400, 'file_not_found': 404,
                            'file_too_large': 413, 'preview_not_supported': 415,
                            'file_changed': 409, 'workspace_unavailable': 503}
                raise ServiceError(error.code, statuses.get(error.code, 503)) from None

    def replay(self, payload):
        common = {'actor_id', 'action', 'idempotency_key', 'settings_revision'}
        if type(payload) is not dict:
            raise ServiceError('invalid_request', 400)
        action = payload.get('action')
        expected = common | {'instance_id'} if type(action) is str and action in {'purge', 'restore'} else common
        if set(payload) != expected:
            raise ServiceError('invalid_request', 400)
        owner = actor(payload['actor_id'])
        if (type(payload['action']) is not str
                or payload['action'] not in {'create', 'start', 'stop', 'restart', 'remove', 'purge', 'restore'}
                or type(payload['idempotency_key']) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', payload['idempotency_key']) is None
                or type(payload['settings_revision']) is not int
                or not 0 <= payload['settings_revision'] <= 2**63 - 1):
            raise ServiceError('invalid_request', 400)
        if action in {'purge', 'restore'} and (type(payload['instance_id']) is not str
                or re.fullmatch(r'[0-9a-f]{32}', payload['instance_id']) is None):
            raise ServiceError('invalid_request', 400)
        with self.lock:
            previous = self.store.operation(owner, payload['idempotency_key'])
            if previous is None:
                raise ServiceError('operation_not_found', 404)
            metadata = self.store.request_metadata(owner, payload['idempotency_key'])
            if metadata is None:
                raise ServiceError('operation_not_found', 404)
            if (metadata.get('action') != payload['action']
                    or metadata.get('settings_revision') != payload['settings_revision']
                    or metadata.get('instance_id') != payload.get('instance_id')):
                raise ServiceError('idempotency_conflict')
            instance = self.store.instance(previous['instance_id'])
            if instance['state'] == 'purged':
                current = self.store.current(owner)
                if current is not None:
                    return self._view(current, previous, self._inspect(current['id']))
                return self._view(instance, previous, None)
            saved = self.store.saved_request(owner, payload['idempotency_key'])
            if saved is None:
                if previous['status'] == 'completed':
                    info = self._inspect(instance['id']) if instance['active'] else None
                    return self._view(instance, previous, info)
                retryable_purge = (payload['action'] == 'purge' and previous['action'] == 'purge'
                                   and instance['state'] == 'purging')
                retryable_restore = (payload['action'] == 'restore' and previous['action'] == 'restore'
                                     and bool(instance['active']))
                if not (retryable_purge or retryable_restore):
                    raise ServiceError('operation_not_found', 404)
                # A scrubbed pending operation has no user payload. Reconstruct
                # only fields consumed by the matching restore/purge action.
                saved = {'actor_id': owner, 'action': payload['action'],
                         'idempotency_key': payload['idempotency_key'],
                         'settings_revision': payload['settings_revision'],
                         'instance_id': payload.get('instance_id')}
                if payload['action'] != 'restore':
                    saved['settings'] = {'name': 'Agent', 'instructions': ''}
            return self.action(saved)

    def action(self, payload):
        payload = validate_action(payload)
        operation = None
        migration = getattr(self, 'sidecar_migration', None)
        with self.lock:
            if migration is not None:
                try:
                    if migration.status().get('status') in {
                            'in_progress', 'needs_attention'}:
                        raise ServiceError('maintenance_in_progress', 503)
                except ServiceError:
                    raise
                except Exception:
                    raise ServiceError('runtime_unavailable', 503) from None
            try:
                previous = self.store.lookup(payload)
                if previous and previous['status'] == 'completed':
                    instance = self.store.instance(previous['instance_id'])
                    if previous['action'] == 'purge':
                        current = self.store.current(payload['actor_id'])
                        if current is not None:
                            return self._view(current, previous, self._inspect(current['id']))
                    info = self._inspect(instance['id']) if instance['active'] else None
                    return self._view(instance, previous, info)
                if previous:
                    instance = self.store.instance(previous['instance_id'])
                    current = self.store.current(payload['actor_id'])
                    if payload['action'] != 'purge' and (
                            not instance['active'] or current is None or current['id'] != instance['id']):
                        raise ServiceError('instance_retired')
                if payload['action'] in {'create', 'restore'}:
                    admission_profile = self.network_profile_default
                    if payload['action'] == 'restore':
                        admission_profile = self.store.instance(payload['instance_id'])['network_profile']
                    self._admit(quota=False, preparing=True,
                                requested_disk_bytes=0 if payload['action'] == 'restore' else None,
                                network_profile=admission_profile)
                limits = self.profile.agent_limits
                operation = self.store.intent(
                    payload, (limits.ram_bytes, limits.cpu_millicores, limits.disk_bytes),
                    self.capacities, network_profile=self.network_profile_default)
                self.store.pending(operation['id'])
                instance = self.store.instance(operation['instance_id'])
                instance_id, action = instance['id'], payload['action']
                evidence = None
                prepared_instance = instance
                if action in {'create', 'start', 'restart', 'restore'}:
                    evidence = self._storage(instance, prepare=action == 'create')
                    prepared_instance = self._prepare_control_ui_instance(
                        instance, action=action,
                        host_path=evidence.get('host_path') if evidence else None)
                    if not instance['initialized']:
                        self.initialize(prepared_instance, evidence, self.ollama_config)
                        self.store.initialized(instance_id)
                    # Re-observe AFTER real quota verification. Intent is not a permit.
                    self._admit(quota=evidence['disk_quota_verified'],
                                requested_disk_bytes=0 if action == 'restore' else None,
                                network_profile=instance['network_profile'])
                info = self._inspect(instance_id)
                if action in {'create', 'restore'}:
                    assert evidence is not None
                    # create/restore are idempotent and verify the EXACT expected
                    # spec/token; restore reuses the existing instance and its data.
                    self._admit(quota=evidence['disk_quota_verified'],
                                requested_disk_bytes=0 if action == 'restore' else None,
                                network_profile=instance['network_profile'])
                    self._create_engine_instance(instance, evidence, limits, prepared_instance)
                    info = self._inspect(instance_id)
                    if self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    # Also on crash recovery/adoption, verify and re-evaluate right before start.
                    evidence = self._storage(self.store.instance(instance_id))
                    self._admit(quota=evidence['disk_quota_verified'],
                                requested_disk_bytes=0 if action == 'restore' else None,
                                network_profile=instance['network_profile'])
                    self._require_ollama_policy(instance, evidence, info)
                    if info['state'] != 'running':
                        self.engine.start(instance_id)
                elif action == 'start':
                    assert evidence is not None
                    if self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    self._admit(quota=evidence['disk_quota_verified'],
                                network_profile=instance['network_profile'])
                    self._require_ollama_policy(instance, evidence, info)
                    if info['state'] != 'running':
                        self.engine.start(instance_id)
                elif action == 'restart':
                    assert evidence is not None
                    if self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    self._admit(quota=evidence['disk_quota_verified'],
                                network_profile=instance['network_profile'])
                    self._require_ollama_policy(instance, evidence, info)
                    self.engine.restart(instance_id)
                elif action == 'stop':
                    if not self._absent(info) and info['state'] not in {'stopped', 'exited', 'created'}:
                        self.engine.stop(instance_id)
                elif action == 'remove':
                    if not self._absent(info):
                        self._remove_engine_instance(instance, action=action)
                elif action == 'purge':
                    if not self._absent(info):
                        self._remove_engine_instance(instance, action=action)
                    info = self._inspect(instance_id)
                    if not self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    evidence = json.loads(instance['storage']) if instance['storage'] else None
                    expected_project_id = evidence.get('project_id') if evidence else None
                    self.volumes.purge(instance_id, instance['disk'], expected_project_id)
                    self.store.complete(operation['id'], 'purged')
                    operation['status'] = 'completed'
                    current = self.store.current(payload['actor_id'])
                    if current is not None:
                        return self._view(current, operation, self._inspect(current['id']))
                    return self._view(self.store.instance(instance_id), operation, info)
                info = self._inspect(instance_id)
                if action in {'create', 'start', 'restart', 'restore'} and info['state'] != 'running':
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
                status = 404 if error.code == 'instance_not_found' else (503 if error.code in {'capacity_exhausted', 'purge_scrub_unverified'} else 409)
                raise ServiceError(error.code if error.code in MESSAGES else 'internal_error', status) from None
            except Exception as error:
                safe = error if isinstance(error, ServiceError) else ServiceError('runtime_unavailable', 503)
                if operation:
                    if payload['action'] in {'create', 'restore'}:
                        try:
                            failed_instance = self.store.instance(operation['instance_id'])
                            self._abort_control_ui_prepare(operation['instance_id'], failed_instance)
                        except Exception:
                            safe = ServiceError('runtime_unavailable', 503)
                    if safe.code in {'quota_unverified', 'storage_unavailable'} and payload['action'] in {'create', 'start', 'restart', 'restore'}:
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

    def _abort_control_ui_prepare(self, instance_id, instance):
        if (type(instance) is not dict
                or instance.get('network_profile') != RuntimeStore.NETWORK_PROFILE_PROXY):
            return
        abort = getattr(self.engine, 'abort_control_ui_prepare', None)
        if not callable(abort):
            raise ServiceError('runtime_unavailable', 503)
        try:
            abort(instance_id)
        except Exception:
            raise ServiceError('runtime_unavailable', 503) from None

    def _proxy_agent_identity_matches(self, sidecar_ip, agent_subnet):
        if type(self.agent_network_pool) is not str:
            return False
        if type(sidecar_ip) is not str or type(agent_subnet) is not str:
            return False
        try:
            pool = ipaddress.IPv4Network(self.agent_network_pool, strict=True)
            subnet = ipaddress.IPv4Network(agent_subnet, strict=True)
            address = ipaddress.IPv4Address(sidecar_ip)
        except (ValueError, TypeError):
            return False
        return (subnet.prefixlen == 29 and subnet.subnet_of(pool)
                and str(subnet) == agent_subnet
                and str(address) == sidecar_ip
                and address == subnet.network_address + 2)

    def _create_engine_instance(self, instance, evidence, limits, prepared_instance):
        """Keep legacy token auth isolated from proxy-profile container creation."""
        if instance.get('network_profile') == RuntimeStore.NETWORK_PROFILE_PROXY:
            if (type(prepared_instance) is not dict
                    or not self._proxy_agent_identity_matches(
                        prepared_instance.get('sidecar_ip'), prepared_instance.get('agent_subnet'))
                    or type(prepared_instance.get('control_ui_origin')) is not str):
                raise ServiceError('runtime_unavailable', 503)
            return self.engine.create(
                instance['id'], evidence['host_path'], limits, None,
                network_profile=RuntimeStore.NETWORK_PROFILE_PROXY,
                owner_id=instance['actor'], sidecar_ip=prepared_instance['sidecar_ip'],
                control_ui_origin=prepared_instance['control_ui_origin'])
        return self.engine.create(instance['id'], evidence['host_path'], limits,
                                  instance['gateway_token'],
                                  network_profile=instance['network_profile'])

    def _remove_engine_instance(self, instance, *, action):
        if action not in {'remove', 'purge'}:
            raise ValueError('Unsupported runtime removal action')
        if instance.get('network_profile') == RuntimeStore.NETWORK_PROFILE_PROXY:
            return self.engine.remove(instance['id'], retain_networks=action == 'remove')
        return self.engine.remove(instance['id'])

    def _prepare_control_ui_instance(self, instance, *, action='create', host_path=None):
        """Resolve trusted network identity before generating the Gateway policy."""
        if type(instance) is not dict:
            raise ServiceError('runtime_unavailable', 503)
        if action not in {'create', 'restore'}:
            return instance
        if instance.get('network_profile') != RuntimeStore.NETWORK_PROFILE_PROXY:
            return instance
        prepare = getattr(self.engine, 'prepare_control_ui', None)
        if (not callable(prepare) or type(self.control_ui_domain) is not str
                or type(host_path) is not str
                or not _CONTROL_UI_INSTANCE_RE.fullmatch(str(instance.get('id', '')))
                or type(instance.get('actor')) is not str):
            raise ServiceError('runtime_unavailable', 503)
        try:
            resolved = prepare(instance['id'], instance['actor'], self.control_ui_domain, host_path)
        except Exception:
            raise ServiceError('runtime_unavailable', 503) from None
        if (type(resolved) is not dict
                or set(resolved) != {'sidecar_ip', 'agent_subnet', 'control_ui_origin'}
                or not self._proxy_agent_identity_matches(
                    resolved.get('sidecar_ip'), resolved.get('agent_subnet'))
                or type(resolved['control_ui_origin']) is not str
                or resolved['control_ui_origin'] !=
                    f"https://{instance['id']}.{self.control_ui_domain}"):
            raise ServiceError('runtime_unavailable', 503)
        enriched = dict(instance)
        enriched.update(resolved)
        try:
            build_gateway_config(enriched, ollama=getattr(self, 'ollama_config', None))
        except Exception:
            raise ServiceError('runtime_unavailable', 503) from None
        return enriched

    def manage_control_ui_sidecars(self, payload):
        """Privileged maintenance RPC; public web handler never exposes this method."""
        migration = getattr(self, 'sidecar_migration', None)
        if migration is None:
            raise ServiceError('runtime_unavailable', 503)
        from .control_ui_migration import MigrationError
        try:
            return migration.handle(payload)
        except MigrationError as error:
            raise ServiceError(error.code, error.status) from None
        except Exception:
            raise ServiceError('runtime_unavailable', 503) from None

    def ollama_model_status(self):
        if self.ollama_config is None:
            raise ServiceError('runtime_unavailable', 503)
        try:
            model_id = self.store.ollama_model_id()
        except StoreError as error:
            raise ServiceError(error.code, 503) from None
        if model_id is None:
            raise ServiceError('admin_config_uninitialized', 503)
        return {'model_id': model_id}

    def change_ollama_model(self, payload):
        """Root-only model switch; rewrite locked config and retain every data volume."""
        if (type(payload) is not dict or set(payload) != {'expected_model_id', 'new_model_id'}
                or type(payload.get('expected_model_id')) is not str
                or payload['expected_model_id'] not in MODEL_NAMES
                or type(payload.get('new_model_id')) is not str
                or payload['new_model_id'] not in MODEL_NAMES):
            raise ServiceError('invalid_request', 400)
        with self.lock:
            if self.ollama_config is None:
                raise ServiceError('runtime_unavailable', 503)
            migration = getattr(self, 'sidecar_migration', None)
            if migration is not None:
                try:
                    if migration.status().get('status') in {'in_progress', 'needs_attention'}:
                        raise ServiceError('maintenance_in_progress', 503)
                except ServiceError:
                    raise
                except Exception:
                    raise ServiceError('runtime_unavailable', 503) from None

            try:
                current_id = self.store.ollama_model_id()
            except StoreError as error:
                raise ServiceError(error.code, 503) from None
            if current_id is None:
                raise ServiceError('admin_config_uninitialized', 503)
            new_id = payload['new_model_id']
            if new_id == current_id:
                return {'status': 'unchanged', 'model_id': current_id,
                        'updated_instances': 0, 'restart_pending': 0}
            if payload['expected_model_id'] != current_id:
                raise ServiceError('admin_config_conflict', 409)

            old_policy = dict(self.ollama_config)
            try:
                new_policy = asdict(validate_ollama_config(
                    {**old_policy, 'default_model_id': new_id}))
            except ValueError:
                raise ServiceError('invalid_admin_model', 400) from None

            plans = []
            for instance in self.store.all_instances():
                if (not instance.get('initialized') or not instance.get('storage')
                        or instance.get('state') == 'purged'):
                    continue
                info = self._inspect(instance['id'])
                if instance['active']:
                    if (not self._absent(info)
                            and info.get('config_policy_version') != 1):
                        raise ServiceError('model_policy_unverified', 503)
                elif not self._absent(info):
                    raise ServiceError('runtime_unavailable', 503)
                evidence = self._storage(instance)
                saved = self._read_managed_gateway_config(
                    evidence, require_immutable=False, with_bytes=True)
                if type(saved) is not tuple or len(saved) != 2:
                    raise ServiceError('model_policy_unverified', 503)
                current_config, old_blob = saved
                if ollama_policy_matches_config(current_config, old_policy):
                    updated_config = replace_ollama_policy_in_config(
                        current_config, old_policy, new_policy)
                    new_blob = (canonical(updated_config) + '\n').encode('utf-8')
                elif ollama_policy_matches_config(current_config, new_policy):
                    # Retry after a crash can finish files already switched before DB CAS.
                    new_blob = old_blob
                else:
                    raise ServiceError('model_policy_unverified', 503)
                plans.append({
                    'instance': instance, 'info': info, 'evidence': evidence,
                    'old_blob': old_blob, 'new_blob': new_blob,
                    'needs_update': old_blob != new_blob,
                })

            try:
                for plan in plans:
                    instance, info = plan['instance'], plan['info']
                    if instance['active'] and info['state'] in {'running', 'restarting', 'paused'}:
                        self.engine.stop(instance['id'])
                        stopped = self._inspect(instance['id'])
                        if stopped['state'] not in {'stopped', 'exited', 'created', 'failed'}:
                            raise ServiceError('runtime_unavailable', 503)
                        self.store.observe(instance['id'], stopped['state'],
                                           stopped.get('container_id'))
                        plan['info'] = stopped
            except Exception as stop_error:
                try:
                    self.reconcile()
                except Exception:
                    pass
                if isinstance(stop_error, ServiceError):
                    raise stop_error
                raise ServiceError('runtime_unavailable', 503) from None

            attempted = []
            try:
                for plan in plans:
                    if not plan['needs_update']:
                        continue
                    attempted.append(plan)
                    state_fd = self._open_gateway_state_fd(plan['evidence'])
                    try:
                        replace_locked_config_at(
                            state_fd, plan['old_blob'], plan['new_blob'])
                    finally:
                        os.close(state_fd)
                self.store.update_ollama_model_id(current_id, new_id)
                if self.store.ollama_model_id() != new_id:
                    raise StoreError('admin_config_conflict')
            except Exception as error:
                rollback_failed = False
                for plan in reversed(attempted):
                    try:
                        saved = self._read_managed_gateway_config(
                            plan['evidence'], require_immutable=False, with_bytes=True)
                        if type(saved) is not tuple or len(saved) != 2:
                            rollback_failed = True
                            continue
                        _current_config, current_blob = saved
                        if current_blob == plan['old_blob']:
                            continue
                        if current_blob != plan['new_blob']:
                            rollback_failed = True
                            continue
                        state_fd = self._open_gateway_state_fd(plan['evidence'])
                        try:
                            replace_locked_config_at(
                                state_fd, plan['new_blob'], plan['old_blob'])
                        finally:
                            os.close(state_fd)
                    except Exception:
                        rollback_failed = True
                if not rollback_failed:
                    try:
                        self.reconcile()
                    except Exception:
                        pass
                if rollback_failed:
                    raise ServiceError('model_policy_unverified', 503) from None
                if isinstance(error, ServiceError):
                    raise error
                if isinstance(error, StoreError):
                    code = error.code if error.code in MESSAGES else 'admin_config_conflict'
                    raise ServiceError(code, 409) from None
                raise ServiceError('runtime_unavailable', 503) from None

            self.ollama_config = new_policy
            try:
                self.reconcile()
            except Exception:
                # The selection and per-instance files are committed; recovery remains gated.
                pass
            restart_pending = 0
            for plan in plans:
                instance = plan['instance']
                if instance['active'] and instance.get('desired_state') == 'running':
                    try:
                        if self._inspect(instance['id'])['state'] != 'running':
                            restart_pending += 1
                    except Exception:
                        restart_pending += 1
            return {'status': 'updated', 'previous_model_id': current_id,
                    'model_id': new_id,
                    'updated_instances': sum(1 for item in plans if item['needs_update']),
                    'restart_pending': restart_pending}

    def control_ui_target(self, payload):
        """Return an owner-bound sidecar target only after live Docker verification."""
        if type(payload) is not dict or set(payload) != {'actor_id', 'instance_id'}:
            raise ServiceError('invalid_request', 400)
        owner_id = actor(payload['actor_id'])
        instance_id = payload['instance_id']
        if type(instance_id) is not str or _CONTROL_UI_INSTANCE_RE.fullmatch(instance_id) is None:
            raise ServiceError('invalid_request', 400)
        unavailable = {'ready': False, 'target': None}
        migration = getattr(self, 'sidecar_migration', None)
        with self.lock:
            if migration is not None:
                try:
                    if instance_id in migration.in_progress_instances():
                        return unavailable
                except Exception:
                    return unavailable
            instance = self.store.current(owner_id)
            if type(instance) is not dict or instance.get('id') != instance_id:
                return unavailable
            for _ in range(2):
                info = self._inspect(instance_id)
                if (info.get('state') != 'running' or info.get('gateway') != 'ready'
                        or info.get('network_profile') != RuntimeStore.NETWORK_PROFILE_PROXY
                        or info.get('proxy_state') != 'ready'):
                    return unavailable
                resolver = getattr(self.engine, 'control_ui_target', None)
                if not callable(resolver):
                    return unavailable
                try:
                    target = resolver(instance_id, owner_id)
                except Exception:
                    return unavailable
                if (type(target) is not dict
                        or set(target) != {'ip', 'port', 'proxy_token', 'identity'}
                        or type(target['ip']) is not str or type(target['port']) is not int
                        or type(target['proxy_token']) is not str
                        or type(target['identity']) is not dict
                        or set(target['identity']) != {
                            'gateway_id', 'sidecar_id', 'agent_network_id', 'frontend_network_id'}
                        or any(type(value) is not str or _CONTROL_UI_DOCKER_ID_RE.fullmatch(value) is None
                               for value in target['identity'].values())):
                    return unavailable
                if (target['identity']['gateway_id'] != info.get('container_id')
                        or target['identity'] != info.get('proxy_identity')):
                    return unavailable
                try:
                    address = ipaddress.ip_address(target['ip'])
                except ValueError:
                    return unavailable
                if (address.version != 4 or not address.is_private or address.is_loopback
                        or address.is_link_local or address.is_multicast or address.is_unspecified
                        or str(address) != target['ip'] or target['port'] != _CONTROL_UI_SIDECAR_PORT
                        or _CONTROL_UI_PROXY_TOKEN_RE.fullmatch(target['proxy_token']) is None):
                    return unavailable
                verified = self._inspect(instance_id)
                if (verified.get('state') != 'running' or verified.get('gateway') != 'ready'
                        or verified.get('network_profile') != RuntimeStore.NETWORK_PROFILE_PROXY
                        or verified.get('proxy_state') != 'ready'
                        or verified.get('container_id') != target['identity']['gateway_id']
                        or verified.get('proxy_identity') != target['identity']):
                    return unavailable
                current = self.store.current(owner_id)
                if type(current) is not dict or current.get('id') != instance_id:
                    return unavailable
                return {'ready': True, 'target': {
                    'ip': target['ip'], 'port': target['port'],
                    'proxy_token': target['proxy_token']}}
        return unavailable

    def reconcile(self):
        """Restore only persisted running intent after storage/resource/firewall gates.

        Never create missing containers, resume failed operations, or touch agent data.
        Docker's RestartPolicy is `no`; this is the sole boot restore path.
        """
        with self.lock:
            migrating = set()
            migration = getattr(self, 'sidecar_migration', None)
            if migration is not None:
                try:
                    migrating = migration.in_progress_instances()
                except Exception:
                    raise ServiceError('runtime_unavailable', 503) from None

            instances = self.store.all_instances()
            managed = [item for item in instances if item['id'] not in migrating]
            desired_running = [item for item in managed
                               if item.get('active') and item.get('desired_state') == 'running']
            firewall_ready = True
            firewall_instance_ids = set()
            if desired_running:
                restore_firewall = getattr(self.engine, 'restore_firewall', None)
                requires_firewall = any(
                    item.get('network_profile') != RuntimeStore.NETWORK_PROFILE_LEGACY
                    for item in desired_running)
                if callable(restore_firewall):
                    try:
                        restored = restore_firewall()
                        instance_ids = (restored.get('instance_ids')
                                        if type(restored) is dict else None)
                        if (type(restored) is not dict or restored.get('ready') is not True
                                or type(instance_ids) is not list or len(instance_ids) > 4096
                                or any(type(value) is not str
                                       or _CONTROL_UI_INSTANCE_RE.fullmatch(value) is None
                                       for value in instance_ids)
                                or len(set(instance_ids)) != len(instance_ids)):
                            firewall_ready = False
                        else:
                            firewall_instance_ids = set(instance_ids)
                    except Exception:
                        firewall_ready = False
                elif requires_firewall:
                    firewall_ready = False

            for instance in managed:
                info = self._inspect(instance['id'])
                if not instance['active']:
                    if not self._absent(info):
                        raise ServiceError('runtime_unavailable', 503)
                    continue

                desired_state = instance.get('desired_state', 'stopped')
                if desired_state not in {'running', 'stopped'}:
                    raise ServiceError('runtime_unavailable', 503)
                if (getattr(self, 'ollama_config', None) is not None
                        and not self._absent(info)
                        and info.get('config_policy_version') != 1):
                    if info['state'] in {'running', 'restarting', 'paused'}:
                        self.engine.stop(instance['id'])
                        info = self._inspect(instance['id'])
                        if info['state'] not in {'stopped', 'exited', 'created', 'failed'}:
                            raise ServiceError('runtime_unavailable', 503)
                    self.store.observe(instance['id'], info['state'], info.get('container_id'))
                    print('Boot recovery blocked for ' + instance['id'] + ': model_policy_unverified',
                          file=sys.stderr, flush=True)
                    continue
                networked = instance.get('network_profile') != RuntimeStore.NETWORK_PROFILE_LEGACY
                if desired_state == 'stopped' or (
                        networked and (not firewall_ready or instance['id'] not in firewall_instance_ids)):
                    if info['state'] in {'running', 'restarting', 'paused'}:
                        self.engine.stop(instance['id'])
                        info = self._inspect(instance['id'])
                        if info['state'] not in {'stopped', 'exited', 'created', 'failed'}:
                            raise ServiceError('runtime_unavailable', 503)
                    state = instance['state'] if self._absent(info) else info['state']
                    self.store.observe(instance['id'], state, info.get('container_id'))
                    continue

                if desired_state == 'running' and not self._absent(info):
                    try:
                        evidence = self._storage(instance)
                        self._admit(quota=evidence['disk_quota_verified'],
                                    requested_disk_bytes=0,
                                    network_profile=instance['network_profile'])
                        if getattr(self, 'ollama_config', None) is not None:
                            self._require_ollama_policy(instance, evidence, info)
                    except ServiceError as error:
                        if info['state'] in {'running', 'restarting', 'paused'}:
                            self.engine.stop(instance['id'])
                            info = self._inspect(instance['id'])
                            if info['state'] not in {'stopped', 'exited', 'created', 'failed'}:
                                raise ServiceError('runtime_unavailable', 503) from None
                        self.store.observe(instance['id'], info['state'], info.get('container_id'))
                        print('Boot recovery blocked for ' + instance['id'] + ': ' + error.code,
                              file=sys.stderr, flush=True)
                        continue

                    if info['state'] in {'stopped', 'exited', 'created'}:
                        try:
                            self.engine.start(instance['id'])
                            info = self._inspect(instance['id'])
                            if info['state'] != 'running':
                                raise ServiceError('runtime_unavailable', 503)
                        except Exception:
                            # A failed postcondition must not leave a networked
                            # Gateway/Sidecar active outside a verified recovery.
                            try:
                                latest = self._inspect(instance['id'])
                                if latest['state'] in {'running', 'restarting', 'paused'}:
                                    self.engine.stop(instance['id'])
                                    latest = self._inspect(instance['id'])
                                if latest['state'] not in {'stopped', 'exited', 'created', 'failed'}:
                                    raise ServiceError('runtime_unavailable', 503)
                                info = latest
                            except Exception:
                                raise ServiceError('runtime_unavailable', 503) from None
                            print('Boot recovery blocked for ' + instance['id'] + ': runtime_start_failed',
                                  file=sys.stderr, flush=True)
                state = instance['state'] if self._absent(info) else info['state']
                self.store.observe(instance['id'], state, info.get('container_id'))


def _runtime_firewall(config):
    """Build the production firewall manager from the host-local acceptance receipt."""
    from .firewall import FirewallManager, NftablesAdapter
    from .firewall_acceptance import load_firewall_acceptance_receipt
    accepted = load_firewall_acceptance_receipt(
        config['state_dir'], config.get('agent_network_pool'),
        config.get('frontend_network_pool'))
    return FirewallManager(NftablesAdapter(), semantics_validated=accepted)


def _runtime_ollama_firewall(config):
    """Use a distinct host-bound route receipt/table; absent receipt stays closed."""
    if config.get('ollama') is None:
        return None
    from .firewall import NftablesAdapter
    from .ollama_firewall import (
        TABLE_COMMENT, TABLE_NAME, OllamaFirewallManager,
        load_ollama_route_receipt,
    )
    endpoint = urlsplit(config['ollama']['base_url']).hostname
    accepted = load_ollama_route_receipt(
        config['state_dir'], config.get('agent_network_pool'),
        config.get('frontend_network_pool'), config.get('ollama_network_pool'),
        endpoint, config.get('ollama_egress_interface'))
    return OllamaFirewallManager(
        NftablesAdapter(table_name=TABLE_NAME, table_comment=TABLE_COMMENT),
        semantics_validated=accepted)


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
            engine = DockerEngine(
                config['image'], agent_network_pool=config.get('agent_network_pool'),
                frontend_network_pool=config.get('frontend_network_pool'),
                ollama_network_pool=config.get('ollama_network_pool'),
                ollama_egress_interface=config.get('ollama_egress_interface'),
                ollama_config=config.get('ollama'),
                firewall=_runtime_firewall(config),
                ollama_firewall=_runtime_ollama_firewall(config))
        if metrics is None:
            metrics = HostMetrics(profile.storage.mountpoint, clock=clock)
        super().__init__(profile, store, volumes, engine, metrics,
                         capacities=tuple(config[k] for k in ('capacity_ram_bytes', 'capacity_cpu_millicores', 'capacity_disk_bytes')),
                         disk_floor_bytes=config['disk_floor_bytes'], initialize=initialize, clock=clock,
                         network_profile_default=config.get(
                             'network_profile_default', RuntimeStore.NETWORK_PROFILE_LEGACY),
                         control_ui_domain=config.get('control_ui_domain'),
                         agent_network_pool=config.get('agent_network_pool'),
                         frontend_network_pool=config.get('frontend_network_pool'),
                         ollama_config=config.get('ollama'))

    def close(self):
        if hasattr(self.metrics, 'close'):
            self.metrics.close()
        self.store.close()


BASE_CONFIG_KEYS = {'profile_path', 'state_dir', 'socket_path', 'token_file', 'image',
                    'capacity_ram_bytes', 'capacity_cpu_millicores', 'capacity_disk_bytes', 'disk_floor_bytes'}
CONFIG_KEYS = BASE_CONFIG_KEYS | {'network_profile_default'}
CONFIG_KEYS_WITH_DOMAIN = CONFIG_KEYS | {'control_ui_domain'}
CONFIG_KEYS_WITH_NETWORKS = CONFIG_KEYS | {
    'control_ui_domain', 'agent_network_pool', 'frontend_network_pool'}
CONFIG_KEY_SETS = (
    BASE_CONFIG_KEYS, CONFIG_KEYS, CONFIG_KEYS_WITH_DOMAIN, CONFIG_KEYS_WITH_NETWORKS,
    BASE_CONFIG_KEYS | {'ollama'}, CONFIG_KEYS | {'ollama'},
    CONFIG_KEYS_WITH_DOMAIN | {'ollama'}, CONFIG_KEYS_WITH_NETWORKS | {'ollama'},
)
CONFIG_KEY_SETS = CONFIG_KEY_SETS + tuple(
    keys | {'ollama_network_pool', 'ollama_egress_interface'} for keys in CONFIG_KEY_SETS)
_CONTROL_UI_DOMAIN_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def _network_pool(value):
    if type(value) is not str:
        raise ValueError('Invalid Control UI network pool')
    try:
        network = ipaddress.IPv4Network(value, strict=True)
    except (ValueError, ipaddress.NetmaskValueError):
        raise ValueError('Invalid Control UI network pool') from None
    private_pools = tuple(ipaddress.IPv4Network(item) for item in (
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if (network.prefixlen > 24
            or not any(network.subnet_of(private) for private in private_pools)):
        raise ValueError('Control UI network pool must be an explicit RFC1918 IPv4 supernet')
    return network


def _validate_ollama_network(config):
    pool_value = config['ollama_network_pool']
    interface = config['ollama_egress_interface']
    if config['ollama'] is None:
        if pool_value is not None or interface is not None:
            raise ValueError('Ollama route settings require an enabled Ollama policy')
        return
    if (config['network_profile_default'] != RuntimeStore.NETWORK_PROFILE_PROXY
            or config['agent_network_pool'] is None
            or config['frontend_network_pool'] is None
            or pool_value is None or interface is None):
        raise ValueError('Ollama requires agent_proxy_v1 and explicit isolated egress network settings')
    try:
        endpoint = urlsplit(config['ollama']['base_url']).hostname
        pool, interface = validate_ollama_route_inputs(
            pool_value, interface, endpoint,
            protected_pools=(config['agent_network_pool'], config['frontend_network_pool']))
    except (TypeError, ValueError):
        raise ValueError('Invalid Ollama egress route settings') from None
    config['ollama_network_pool'] = pool
    config['ollama_egress_interface'] = interface


def load_service_config(path):
    with open(path, 'rb') as stream:
        blob = stream.read(65537)
    if len(blob) > 65536:
        raise ValueError('Invalid service config')
    config = decode_json(blob)
    allowed_keys = CONFIG_KEY_SETS
    if type(config) is not dict or set(config) not in allowed_keys:
        raise ValueError('Invalid service config')
    config.setdefault('network_profile_default', RuntimeStore.NETWORK_PROFILE_LEGACY)
    config.setdefault('control_ui_domain', None)
    config.setdefault('agent_network_pool', None)
    config.setdefault('frontend_network_pool', None)
    config.setdefault('ollama', None)
    config.setdefault('ollama_network_pool', None)
    config.setdefault('ollama_egress_interface', None)
    if config['ollama'] is not None:
        config['ollama'] = asdict(validate_ollama_config(config['ollama']))
    if (type(config['network_profile_default']) is not str
            or config['network_profile_default'] not in RuntimeStore.NETWORK_PROFILES):
        raise ValueError('Invalid default network profile')
    domain = config['control_ui_domain']
    if domain is not None and (type(domain) is not str or len(domain) > 253
            or len(domain.split('.')) < 2
            or any(_CONTROL_UI_DOMAIN_LABEL.fullmatch(label) is None for label in domain.split('.'))):
        raise ValueError('Invalid Control UI domain')
    raw_agent_pool = config['agent_network_pool']
    raw_frontend_pool = config['frontend_network_pool']
    if (raw_agent_pool is None) != (raw_frontend_pool is None):
        raise ValueError('Both Control UI network pools must be provided together')
    if raw_agent_pool is not None:
        agent_pool, frontend_pool = _network_pool(raw_agent_pool), _network_pool(raw_frontend_pool)
        if agent_pool.overlaps(frontend_pool):
            raise ValueError('Control UI network pools must not overlap')
        config['agent_network_pool'] = str(agent_pool)
        config['frontend_network_pool'] = str(frontend_pool)
    if config['network_profile_default'] == RuntimeStore.NETWORK_PROFILE_PROXY:
        if domain is None:
            raise ValueError('Control UI domain required for proxy profile')
        if raw_agent_pool is None:
            raise ValueError('Control UI network pools required for proxy profile')
    _validate_ollama_network(config)
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


def _unix_peer_uid(connection):
    """Return the Linux AF_UNIX peer UID, or None when it cannot be proven."""
    option = getattr(socket, 'SO_PEERCRED', None)
    if type(option) is not int or not hasattr(connection, 'getsockopt'):
        return None
    try:
        credentials = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize('3i'))
        pid, uid, gid = struct.unpack('3i', credentials)
    except (OSError, TypeError, ValueError, struct.error):
        return None
    if pid <= 0 or uid < 0 or gid < 0:
        return None
    return uid


class APIHandler(BaseHTTPRequestHandler):
    server_version = 'Supervisor'
    sys_version = ''
    admin_only = False

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

    def _binary(self, status, result):
        body = result.content
        filename = quote(result.name, safe="")
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Disposition', f"attachment; filename=download; filename*=UTF-8''{filename}")
        self.send_header('X-Content-Type-Options', 'nosniff')
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
            if self.admin_only:
                if _unix_peer_uid(self.request) != 0:
                    raise ServiceError('unauthorized', 403)
                controller = getattr(self, 'controller', None)
                if controller is None:
                    raise ServiceError('runtime_unavailable', 503)
                allowed_paths = set()
                if callable(getattr(controller, 'manage_control_ui_sidecars', None)):
                    allowed_paths.add('/v1/admin/control-ui/sidecars')
                if getattr(controller, 'ollama_config', None) is not None:
                    allowed_paths.add('/v1/admin/ollama/model')
            else:
                allowed_paths = {'/v1/me', '/v1/actions', '/v1/replay',
                                 '/v1/retained/workspace', '/v1/control-ui/target'}
            if self.path not in allowed_paths:
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
            if self.path == '/v1/admin/ollama/model':
                if payload == {'action': 'status'}:
                    operation = getattr(controller, 'ollama_model_status', None)
                    if not callable(operation):
                        raise ServiceError('runtime_unavailable', 503)
                    self._json(200, operation())
                else:
                    operation = getattr(controller, 'change_ollama_model', None)
                    if not callable(operation):
                        raise ServiceError('runtime_unavailable', 503)
                    self._json(200, operation(payload))
            elif self.path == '/v1/admin/control-ui/sidecars':
                operation = getattr(controller, 'manage_control_ui_sidecars', None)
                if not callable(operation):
                    raise ServiceError('runtime_unavailable', 503)
                self._json(200, operation(payload))
            elif self.path == '/v1/retained/workspace':
                result = controller.retained_workspace(payload)
                if isinstance(result, WorkspaceDownload):
                    self._binary(200, result)
                else:
                    self._json(200, result)
            elif self.path == '/v1/control-ui/target':
                resolver = getattr(controller, 'control_ui_target', None)
                if not callable(resolver):
                    raise ServiceError('runtime_unavailable', 503)
                self._json(200, resolver(payload))
            else:
                self._json(200, dispatch[self.path](payload))
        except ServiceError as error:
            self._json(error.status, {'code': error.code, 'message': MESSAGES.get(error.code, MESSAGES['internal_error'])})
        except Exception:
            self._json(500, {'code': 'internal_error', 'message': MESSAGES['internal_error']})

    def do_GET(self):
        self._json(405, {'code': 'method_not_allowed', 'message': MESSAGES['method_not_allowed']})

    do_PUT = do_DELETE = do_PATCH = do_GET


def create_handler(app, token):
    """Export the regular handler for tests; production binds AF_UNIX only."""
    secret = token.encode('ascii') if isinstance(token, str) else token
    if type(secret) is not bytes or not secret or len(secret) > 256:
        raise ValueError('Explicit bounded bearer token required')

    class BoundHandler(APIHandler):
        controller = app
        service_secret = secret

    return BoundHandler


def create_admin_handler(app, token):
    """Export a separate root-peer-only handler for the host maintenance socket."""
    secret = token.encode('ascii') if isinstance(token, str) else token
    if type(secret) is not bytes or not secret or len(secret) > 256:
        raise ValueError('Explicit bounded bearer token required')

    class BoundAdminHandler(APIHandler):
        controller = app
        service_secret = secret
        admin_only = True

    return BoundAdminHandler


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
    admin_socket_path = state / 'control-ui-maintenance.sock'
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
    for target in (Path(config['token_file']), socket_path, admin_socket_path):
        if target.is_symlink():
            raise ValueError('Unsafe service target')
    engine = DockerEngine(
        config['image'], agent_network_pool=config['agent_network_pool'],
        frontend_network_pool=config['frontend_network_pool'],
        firewall=_runtime_firewall(config))
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
    store = server = admin_server = None
    admin_thread = None
    bound_identity = admin_bound_identity = None
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
                                    metrics, capacities=capacities, disk_floor_bytes=config['disk_floor_bytes'],
                                    network_profile_default=config['network_profile_default'],
                                    control_ui_domain=config['control_ui_domain'],
                                    agent_network_pool=config['agent_network_pool'],
                                    frontend_network_pool=config['frontend_network_pool'],
                                    ollama_config=config.get('ollama'))
        if type(config.get('control_ui_domain')) is str:
            from .control_ui_migration import ControlUiSidecarMigration
            controller.sidecar_migration = ControlUiSidecarMigration(
                engine, store, config['control_ui_domain'],
                state / 'control-ui-sidecar-migration.json', controller.lock,
                require_root_owned=True)
        controller._sample()  # Reject explicit ceilings above physical totals.
        if any(used > maximum for used, maximum in zip(store.totals(), capacities)):
            raise ValueError('Existing reservations exceed configured ceilings')
        controller.reconcile()
        def prepare_socket(path):
            if not os.path.lexists(path):
                return
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                raise ValueError('Unsafe socket target')
            # Never unlink a live listener from another service instance.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(1)
                try:
                    probe.connect(str(path))
                except OSError as error:
                    if error.errno != errno.ECONNREFUSED:
                        raise ValueError('Socket target is not safely stale') from None
                else:
                    raise ValueError('Socket is already serving')
            if path.lstat() != info:
                raise ValueError('Socket target changed')
            path.unlink()

        prepare_socket(socket_path)
        prepare_socket(admin_socket_path)

        class UnixServer(socketserver.UnixStreamServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(30)
                return connection, address

        class ThreadedAdminServer(socketserver.ThreadingMixIn, UnixServer):
            daemon_threads = True
            block_on_close = False

            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(21600)
                return connection, address

        server = UnixServer(str(socket_path), create_handler(controller, secret))
        os.chown(socket_path, 0, 0)
        os.chmod(socket_path, 0o660)
        info = socket_path.lstat()
        bound_identity = (info.st_dev, info.st_ino)
        server.controller, server.service_secret = controller, secret

        if controller.sidecar_migration is not None or controller.ollama_config is not None:
            admin_server = ThreadedAdminServer(
                str(admin_socket_path), create_admin_handler(controller, secret))
            os.chown(admin_socket_path, 0, 0)
            os.chmod(admin_socket_path, 0o600)
            admin_info = admin_socket_path.lstat()
            admin_bound_identity = (admin_info.st_dev, admin_info.st_ino)
            admin_server.controller, admin_server.service_secret = controller, secret
            admin_thread = threading.Thread(
                target=admin_server.serve_forever, kwargs={'poll_interval': 0.5}, daemon=True)
            admin_thread.start()
        print('Supervisor listening on private Unix sockets; CPU window warms for 60 seconds.', flush=True)
        server.serve_forever(poll_interval=0.5)
    finally:
        if admin_server:
            if admin_thread is not None and admin_thread.is_alive():
                admin_server.shutdown()
                admin_thread.join(timeout=5)
            admin_server.server_close()
        if server:
            server.server_close()
        if bound_identity and os.path.lexists(socket_path):
            info = socket_path.lstat()
            if (info.st_dev, info.st_ino) == bound_identity:
                socket_path.unlink()
        if admin_bound_identity and os.path.lexists(admin_socket_path):
            info = admin_socket_path.lstat()
            if (info.st_dev, info.st_ino) == admin_bound_identity:
                admin_socket_path.unlink()
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
