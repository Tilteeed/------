"""Root-admin coordinator for durable Control UI Sidecar image migration."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

from .runtime_store import RuntimeStore, canonical


class MigrationError(RuntimeError):
    def __init__(self, code, status=409):
        self.code = code
        self.status = status
        super().__init__(code)


class ControlUiSidecarMigration:
    """Coordinate a plan-bound, resumable Sidecar migration; never touch Gateway data."""
    JOURNAL_VERSION = 1
    MAX_JOURNAL_BYTES = 32 * 1024 * 1024
    _PLAN_HASH = re.compile(r'[0-9a-f]{64}')

    def __init__(self, engine, store, control_ui_domain, journal_path, lifecycle_lock,
                 *, require_root_owned=True, clock=time.time):
        if not callable(getattr(engine, 'plan_control_ui_sidecar_migration', None)):
            raise ValueError('Sidecar migration planner is required')
        if type(control_ui_domain) is not str or not control_ui_domain:
            raise ValueError('Control UI domain is required')
        self.engine = engine
        self.store = store
        self.control_ui_domain = control_ui_domain
        self.journal_path = Path(journal_path)
        self.lifecycle_lock = lifecycle_lock if lifecycle_lock is not None else threading.RLock()
        self.require_root_owned = require_root_owned
        self.clock = clock

    @staticmethod
    def _duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate journal key')
            result[key] = value
        return result

    @staticmethod
    def _reject_constant(_value):
        raise ValueError('invalid journal constant')

    def _active_proxy_instances(self):
        rows = self.store.all_instances()
        if type(rows) is not list or len(rows) > 4096:
            raise MigrationError('migration_inventory_invalid', 503)
        return [row for row in rows if type(row) is dict
                and type(row.get('active')) is int and row['active'] == 1
                and row.get('network_profile') == RuntimeStore.NETWORK_PROFILE_PROXY]

    def _build_plan(self):
        try:
            package = self.engine.plan_control_ui_sidecar_migration(
                self._active_proxy_instances(), self.control_ui_domain)
            if type(package) is not dict or set(package) != {'public', 'prepared'}:
                raise ValueError
            public, prepared = package['public'], package['prepared']
            if type(public) is not dict:
                raise ValueError
            webui = public.get('webui')
            blockers = public.get('blockers')
            if (type(public.get('version')) is not int
                    or public.get('version') != self.JOURNAL_VERSION
                    or (type(webui) is not dict and not (webui is None and type(blockers) is list and blockers))
                    or type(public.get('items')) is not list
                    or type(blockers) is not list
                    or type(public.get('summary')) is not dict
                    or type(prepared) is not list
                    or len(public['items']) > 4096 or len(prepared) > 4096
                    or len(public['items']) != len(prepared)):
                raise ValueError
            public_ids = [item.get('instance_id') if type(item) is dict else None
                          for item in public['items']]
            prepared_ids = [item.get('instance_id') if type(item) is dict else None
                            for item in prepared]
            if (any(type(value) is not str for value in public_ids + prepared_ids)
                    or len(set(public_ids)) != len(public_ids)
                    or set(public_ids) != set(prepared_ids)):
                raise ValueError
            digest = hashlib.sha256(canonical(public).encode('ascii')).hexdigest()
            return public, prepared, digest
        except MigrationError:
            raise
        except Exception:
            raise MigrationError('migration_preflight_failed', 503) from None

    def _plan_response(self):
        public, _prepared, digest = self._build_plan()
        return {**public, 'plan_sha256': digest}

    def handle(self, payload):
        if type(payload) is not dict or type(payload.get('action')) is not str:
            raise MigrationError('invalid_request', 400)
        action = payload['action']
        expected = {'action', 'plan_sha256'} if action == 'apply' else {'action'}
        if (action not in {'plan', 'apply', 'status', 'resume'}
                or set(payload) != expected
                or (action == 'apply' and (type(payload.get('plan_sha256')) is not str
                                           or self._PLAN_HASH.fullmatch(payload['plan_sha256']) is None))):
            raise MigrationError('invalid_request', 400)
        if action == 'status':
            return self.status()
        with self.lifecycle_lock:
            if action == 'plan':
                return self._plan_response()
            if action == 'apply':
                return self.apply(payload['plan_sha256'])
            return self.resume()

    def _load_journal(self):
        path = self.journal_path
        raw = None
        if os.name != 'posix':
            try:
                info = path.lstat()
            except FileNotFoundError:
                return None
            except OSError:
                raise MigrationError('migration_journal_unavailable', 503) from None
            if (not stat.S_ISREG(info.st_mode) or info.st_size > self.MAX_JOURNAL_BYTES
                    or info.st_nlink != 1):
                raise MigrationError('migration_journal_unavailable', 503)
            try:
                raw = path.read_bytes()
            except OSError:
                raise MigrationError('migration_journal_unavailable', 503) from None
            if len(raw) > self.MAX_JOURNAL_BYTES:
                raise MigrationError('migration_journal_unavailable', 503)
        else:
            try:
                parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            except FileNotFoundError:
                return None
            except OSError:
                raise MigrationError('migration_journal_unavailable', 503) from None
            try:
                parent_info = os.fstat(parent_fd)
                if (not stat.S_ISDIR(parent_info.st_mode)
                        or (self.require_root_owned and
                            (parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o700))):
                    raise MigrationError('migration_journal_unavailable', 503)
                try:
                    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
                except FileNotFoundError:
                    return None
                except OSError:
                    raise MigrationError('migration_journal_unavailable', 503) from None
                try:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or info.st_size > self.MAX_JOURNAL_BYTES
                            or (self.require_root_owned and
                                (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600))):
                        raise MigrationError('migration_journal_unavailable', 503)
                    chunks = []
                    remaining = self.MAX_JOURNAL_BYTES + 1
                    while remaining:
                        chunk = os.read(fd, min(65536, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    raw = b''.join(chunks)
                    if len(raw) > self.MAX_JOURNAL_BYTES:
                        raise MigrationError('migration_journal_unavailable', 503)
                finally:
                    os.close(fd)
            finally:
                os.close(parent_fd)
        try:
            journal = json.loads(raw.decode('ascii'), object_pairs_hook=self._duplicate_keys,
                                 parse_constant=self._reject_constant)
            if type(journal) is not dict or canonical(journal).encode('ascii') != raw:
                raise ValueError
            self._validate_journal(journal)
            return journal
        except MigrationError:
            raise
        except Exception:
            raise MigrationError('migration_journal_unavailable', 503) from None


    def _validate_journal(self, journal):
        required = {'version', 'operation_id', 'status', 'mode', 'plan_sha256', 'target_web',
                    'created_at', 'updated_at', 'items', 'last_error'}
        if (set(journal) != required or journal.get('version') != self.JOURNAL_VERSION
                or journal.get('mode') not in {'apply', 'rollback'}
                or type(journal.get('operation_id')) is not str
                or re.fullmatch(r'[0-9a-f]{32}', journal['operation_id']) is None
                or journal.get('status') not in {
                    'in_progress', 'completed', 'needs_attention', 'rolled_back'}
                or type(journal.get('plan_sha256')) is not str
                or self._PLAN_HASH.fullmatch(journal['plan_sha256']) is None
                or type(journal.get('target_web')) is not dict
                or set(journal['target_web']) != {'container_id', 'image_id'}
                or type(journal['target_web'].get('container_id')) is not str
                or re.fullmatch(r'[0-9a-f]{64}', journal['target_web']['container_id']) is None
                or type(journal['target_web'].get('image_id')) is not str
                or re.fullmatch(r'sha256:[0-9a-f]{64}', journal['target_web']['image_id']) is None
                or type(journal.get('created_at')) is not int
                or type(journal.get('updated_at')) is not int
                or type(journal.get('items')) is not list or len(journal['items']) > 4096
                or (journal.get('last_error') is not None
                    and (type(journal.get('last_error')) is not str
                         or re.fullmatch(r'[a-z][a-z0-9_]{0,63}', journal['last_error']) is None))):
            raise ValueError('invalid migration journal schema')
        seen = set()
        item_keys = {
            'instance_id', 'owner_id', 'gateway_id', 'gateway_image_id',
            'old_sidecar_id', 'old_image_id', 'target_image_id',
            'agent_network_id', 'frontend_network_id', 'gateway_ip',
            'sidecar_agent_ip', 'sidecar_frontend_ip', 'web_ip', 'action',
            'gateway_spec', 'gateway_spec_sha256', 'gateway_live_sha256', 'old_sidecar_spec',
            'old_sidecar_config_sha256', 'target_sidecar_spec',
            'target_sidecar_config_sha256', 'network_plan', 'network_ids',
            'web_container_id', 'sidecar_was_running', 'stage', 'result',
        }
        stages = {'planned', 'already_current', 'web_attached', 'stopping_old',
                  'old_stopped', 'deleting_old', 'old_removed', 'creating_new',
                  'new_created', 'starting_new', 'new_running', 'complete',
                  'rollback_deleting_new', 'rolled_back'}
        object_id = re.compile(r'[0-9a-f]{64}')
        image_id = re.compile(r'sha256:[0-9a-f]{64}')
        for item in journal['items']:
            if (type(item) is not dict or not item_keys <= set(item)
                    or set(item) - item_keys - {'new_sidecar_id'}
                    or type(item.get('instance_id')) is not str
                    or re.fullmatch(r'[0-9a-f]{32}', item['instance_id']) is None
                    or item['instance_id'] in seen
                    or type(item.get('owner_id')) is not str
                    or any(type(item.get(key)) is not str or object_id.fullmatch(item[key]) is None
                           for key in ('gateway_id', 'old_sidecar_id', 'agent_network_id',
                                       'frontend_network_id', 'web_container_id'))
                    or (item.get('new_sidecar_id') is not None
                        and (type(item['new_sidecar_id']) is not str
                             or object_id.fullmatch(item['new_sidecar_id']) is None))
                    or any(type(item.get(key)) is not str or image_id.fullmatch(item[key]) is None
                           for key in ('gateway_image_id', 'old_image_id', 'target_image_id'))
                    or any(type(item.get(key)) is not str
                           or re.fullmatch(r'[0-9a-f]{64}', item[key]) is None
                           for key in ('gateway_spec_sha256', 'gateway_live_sha256',
                                       'old_sidecar_config_sha256', 'target_sidecar_config_sha256'))
                    or type(item.get('gateway_spec')) is not dict
                    or type(item.get('old_sidecar_spec')) is not dict
                    or type(item.get('target_sidecar_spec')) is not dict
                    or type(item.get('network_plan')) is not dict
                    or type(item.get('network_ids')) is not dict
                    or type(item.get('sidecar_was_running')) is not bool
                    or item.get('action') not in {'replace', 'already_current'}
                    or item.get('stage') not in stages
                    or (item.get('result') is not None
                        and item.get('result') not in {
                            'no_change', 'verified', 'old_sidecar_restored_control_ui_closed',
                            'rollback_failed'})):
                raise ValueError('invalid migration journal item')
            seen.add(item['instance_id'])

    def _write_journal(self, journal):
        self._validate_journal(journal)
        raw = canonical(journal).encode('ascii')
        if len(raw) > self.MAX_JOURNAL_BYTES:
            raise MigrationError('migration_journal_unavailable', 503)
        path = self.journal_path
        temp_name = '.' + path.name + '.' + uuid.uuid4().hex + '.tmp'
        if os.name != 'posix':
            temp_path = path.parent / temp_name
            fd = None
            try:
                parent = path.parent.lstat()
                if not stat.S_ISDIR(parent.st_mode):
                    raise MigrationError('migration_journal_unavailable', 503)
                fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError('short journal write')
                    view = view[written:]
                os.fsync(fd)
                os.close(fd)
                fd = None
                os.replace(temp_path, path)
            except MigrationError:
                raise
            except OSError:
                raise MigrationError('migration_journal_unavailable', 503) from None
            finally:
                if fd is not None:
                    os.close(fd)
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
            return
        try:
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise MigrationError('migration_journal_unavailable', 503) from None
        fd = None
        try:
            parent_info = os.fstat(parent_fd)
            if (not stat.S_ISDIR(parent_info.st_mode)
                    or (self.require_root_owned and os.name == 'posix'
                        and (parent_info.st_uid != 0
                             or stat.S_IMODE(parent_info.st_mode) != 0o700))):
                raise MigrationError('migration_journal_unavailable', 503)
            fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=parent_fd)
            if self.require_root_owned and os.name == 'posix':
                os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError('short journal write')
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(temp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        except MigrationError:
            raise
        except OSError:
            raise MigrationError('migration_journal_unavailable', 503) from None
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            os.close(parent_fd)

    def status(self):
        journal = self._load_journal()
        if journal is None:
            return {'status': 'idle', 'operation_id': None, 'items': [], 'last_error': None}
        # Do not expose the private saved specs or host paths from the journal.
        return {
            'status': journal['status'],
            'mode': journal['mode'],
            'operation_id': journal['operation_id'],
            'plan_sha256': journal['plan_sha256'],
            'target_web': journal['target_web'],
            'items': [{key: item.get(key) for key in (
                'instance_id', 'stage', 'result', 'old_sidecar_id',
                'new_sidecar_id', 'old_image_id', 'target_image_id')}
                for item in journal['items']],
            'last_error': journal['last_error'],
        }

    @staticmethod
    def _error_code(error, fallback='migration_step_failed'):
        code = getattr(error, 'code', fallback)
        if type(code) is not str or re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code) is None:
            return fallback
        return code

    def _verify_store_binding(self, journal, item):
        if item['action'] == 'already_current':
            return
        try:
            record = self.store.instance(item['instance_id'])
            storage = json.loads(record['storage']) if type(record.get('storage')) is str else None
            gateway_spec = item.get('gateway_spec')
            expected_origin = (
                f"https://{item['instance_id']}.{self.control_ui_domain}")
            if (record.get('active') != 1
                    or record.get('network_profile') != RuntimeStore.NETWORK_PROFILE_PROXY
                    or record.get('actor') != item.get('owner_id')
                    or record.get('container_id') != item.get('gateway_id')
                    or type(storage) is not dict
                    or storage.get('host_path') != gateway_spec.get('host_path')
                    or gateway_spec.get('control_ui_origin') != expected_origin):
                raise ValueError
        except Exception:
            raise MigrationError('migration_runtime_identity_changed', 409) from None

    def _checkpoint(self, journal, item, stage, **values):
        if stage not in {
                'planned', 'already_current', 'web_attached', 'stopping_old',
                'old_stopped', 'deleting_old', 'old_removed', 'creating_new',
                'new_created', 'starting_new', 'new_running', 'complete',
                'rollback_deleting_new', 'rolled_back'}:
            raise MigrationError('migration_stage_invalid', 503)
        item['stage'] = stage
        for key in ('new_sidecar_id', 'result'):
            if key in values:
                item[key] = values[key]
        journal['updated_at'] = int(self.clock())
        self._write_journal(journal)

    def _rollback(self, journal):
        journal['mode'] = 'rollback'
        journal['status'] = 'in_progress'
        self._write_journal(journal)
        rollback = getattr(self.engine, 'rollback_control_ui_sidecar', None)
        if not callable(rollback):
            journal['status'] = 'needs_attention'
            journal['last_error'] = 'rollback_unavailable'
            journal['updated_at'] = int(self.clock())
            self._write_journal(journal)
            return self.status()
        for item in reversed(journal['items']):
            if item['action'] == 'already_current' or item['stage'] == 'rolled_back':
                continue
            def checkpoint(stage, **values):
                self._checkpoint(journal, item, stage, **values)
            try:
                self._verify_store_binding(journal, item)
                result = rollback(item, checkpoint)
                if (type(result) is not dict or result.get('gateway_id') != item['gateway_id']
                        or type(result.get('sidecar_id')) is not str
                        or re.fullmatch(r'[0-9a-f]{64}', result['sidecar_id']) is None):
                    raise MigrationError('rollback_verification_failed', 503)
                checkpoint('rolled_back', new_sidecar_id=result['sidecar_id'],
                           result='old_sidecar_restored_control_ui_closed')
            except Exception:
                item['result'] = 'rollback_failed'
                journal['status'] = 'needs_attention'
                journal['last_error'] = 'rollback_failed'
                journal['updated_at'] = int(self.clock())
                self._write_journal(journal)
                return self.status()
        journal['status'] = 'rolled_back'
        journal['updated_at'] = int(self.clock())
        self._write_journal(journal)
        return self.status()

    def _run_apply(self, journal):
        migrate = getattr(self.engine, 'migrate_control_ui_sidecar', None)
        if not callable(migrate):
            raise MigrationError('migration_engine_unavailable', 503)
        journal['mode'] = 'apply'
        journal['status'] = 'in_progress'
        self._write_journal(journal)
        for item in journal['items']:
            if item['action'] == 'already_current' or item['stage'] == 'complete':
                continue
            def checkpoint(stage, **values):
                self._checkpoint(journal, item, stage, **values)
            try:
                self._verify_store_binding(journal, item)
                result = migrate(item, checkpoint)
                if (type(result) is not dict or result.get('gateway_id') != item['gateway_id']
                        or type(result.get('sidecar_id')) is not str
                        or re.fullmatch(r'[0-9a-f]{64}', result['sidecar_id']) is None
                        or item.get('new_sidecar_id') != result['sidecar_id']):
                    raise MigrationError('migration_verification_failed', 503)
                checkpoint('complete', new_sidecar_id=result['sidecar_id'], result='verified')
            except Exception as error:
                journal['last_error'] = self._error_code(error)
                journal['mode'] = 'rollback'
                journal['status'] = 'in_progress'
                journal['updated_at'] = int(self.clock())
                self._write_journal(journal)
                return self._rollback(journal)
        journal['status'] = 'completed'
        journal['last_error'] = None
        journal['updated_at'] = int(self.clock())
        self._write_journal(journal)
        return self.status()

    def apply(self, plan_sha256):
        public, prepared, current_hash = self._build_plan()
        if current_hash != plan_sha256:
            raise MigrationError('migration_plan_changed', 409)
        if public['blockers']:
            raise MigrationError('migration_preflight_blocked', 409)
        if not any(item.get('action') == 'replace' for item in public['items']):
            return {'status': 'completed', 'mode': 'apply', 'operation_id': None,
                    'plan_sha256': current_hash, 'target_web': public['webui'],
                    'items': [], 'last_error': None}
        previous = self._load_journal()
        if previous is not None and previous['status'] in {'in_progress', 'needs_attention'}:
            raise MigrationError('migration_in_progress', 409)
        if (previous is not None and previous['status'] == 'completed'
                and previous['plan_sha256'] == current_hash):
            return self.status()
        now = int(self.clock())
        items = []
        for prepared_item in prepared:
            item = dict(prepared_item)
            item['stage'] = 'already_current' if item.get('action') == 'already_current' else 'planned'
            item['result'] = 'no_change' if item['stage'] == 'already_current' else None
            items.append(item)
        journal = {
            'version': self.JOURNAL_VERSION,
            'operation_id': uuid.uuid4().hex,
            'status': 'in_progress', 'mode': 'apply',
            'plan_sha256': current_hash,
            'target_web': public['webui'],
            'created_at': now, 'updated_at': now,
            'items': items, 'last_error': None,
        }
        self._write_journal(journal)
        return self._run_apply(journal)

    def resume(self):
        journal = self._load_journal()
        if journal is None:
            raise MigrationError('migration_not_found', 404)
        if journal['status'] in {'completed', 'rolled_back'}:
            return self.status()
        if journal['mode'] == 'rollback':
            return self._rollback(journal)
        return self._run_apply(journal)

    def in_progress_instances(self):
        journal = self._load_journal()
        if journal is None or journal['status'] not in {'in_progress', 'needs_attention'}:
            return set()
        terminal_stages = {'already_current', 'complete', 'rolled_back'}
        return {item['instance_id'] for item in journal['items']
                if item['stage'] not in terminal_stages}
