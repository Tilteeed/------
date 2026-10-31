"""Private web -> host-supervisor bridge; never forwards browser credentials.

Only the configured Unix socket is used. No URLs, Docker API, redirects or
client-selected targets are accepted. The service credential stays server-side.
"""
import http.client
import json
import os
from pathlib import Path
import re
import socket


class RuntimeUnavailable(Exception):
    pass


class RuntimeRejected(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message
        super().__init__(code)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=120):
        super().__init__('localhost', timeout=timeout)
        self.path = path

    def connect(self):
        family = getattr(socket, 'AF_UNIX', None)
        if family is None:
            raise OSError('Unix sockets unavailable')
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate response key')
        result[key] = value
    return result


class SupervisorClient:
    def __init__(self, socket_path, token_file):
        if not socket_path or not token_file:
            raise ValueError('Both supervisor socket and credential file are required')
        self.socket_path, self.token_file = str(socket_path), Path(token_file)

    def _request(self, path, payload):
        connection = UnixConnection(self.socket_path)
        try:
            with self.token_file.open('rb') as source:
                raw_token = source.read(257)
            token = raw_token.decode('ascii').strip()
            if len(raw_token) > 256 or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', token):
                raise ValueError('Invalid service credential')
            body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            if len(body) > 65536:
                raise ValueError('Oversized supervisor request')
            connection.request('POST', path, body=body, headers={
                'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                'Accept': 'application/json', 'Connection': 'close',
            })
            response = connection.getresponse()
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError('Oversized supervisor response')
            data = json.loads(raw, object_pairs_hook=_unique)
            if type(data) is not dict:
                raise ValueError('Invalid supervisor response')
            if response.status not in (200, 201, 202):
                # Never expose service diagnostics or arbitrary messages to browsers.
                code = data.get('code', 'supervisor_rejected')
                if type(code) is not str or re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code) is None:
                    code = 'supervisor_rejected'
                messages = {
                    'metrics_not_ready': 'Сборщик CPU ещё набирает 60-секундное окно. Подождите.',
                    'admission_denied': 'Создание или запуск отклонены ресурсной политикой.',
                    'capacity_exceeded': 'Недостаточно свободного бюджета для нового экземпляра.',
                    'one_instance_limit': 'У вас уже есть экземпляр или незавершённое создание.',
                    'idempotency_conflict': 'Ключ запроса уже использован. Обновите состояние.',
                    'profile_version_conflict': 'Администратор должен проверить версию профиля.',
                    'storage_unavailable': 'Хранилище или персональная квота не прошли проверку.',
                }
                status = response.status if response.status in (400, 404, 409, 422, 429, 503) else 503
                raise RuntimeRejected(status, code, messages.get(code, 'Supervisor отклонил операцию. Проверьте состояние экземпляра.'))
            runtime, capabilities = data.get('runtime'), data.get('capabilities')
            if type(runtime) is not dict or type(capabilities) is not dict:
                raise ValueError('Invalid supervisor response shape')
            # Deliberate response allowlist: no token, paths, environment or raw inspect.
            safe_runtime = {k: v for k, v in runtime.items() if k in (
                'state', 'gateway', 'model', 'telegram', 'instance_id', 'container_id',
                'settings_revision', 'operation_status', 'error_code', 'retained_data',
                'pending_create_key', 'pending_create_revision',
                'pending_purge_key', 'pending_purge_revision',
            ) and type(v) in (str, int, bool, type(None))}
            safe_caps = {k: capabilities.get(k) is True for k in ('provisioning', 'chat', 'telegram', 'metrics')}
            retained = data.get('retained', [])
            if type(retained) is not list or len(retained) > 100:
                raise ValueError('Invalid retained data list')
            safe_retained = []
            for item in retained:
                if (type(item) is not dict
                        or type(item.get('instance_id')) is not str
                        or re.fullmatch(r'[0-9a-f]{32}', item['instance_id']) is None
                        or type(item.get('name')) is not str or len(item['name']) > 80
                        or type(item.get('disk_bytes')) is not int
                        or not 0 < item['disk_bytes'] <= 2**63 - 1
                        or item.get('state') not in {'removed', 'purging'}):
                    raise ValueError('Invalid retained data entry')
                pending_key, pending_revision = item.get('pending_purge_key'), item.get('pending_purge_revision')
                if pending_key is not None and (type(pending_key) is not str
                        or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', pending_key) is None):
                    raise ValueError('Invalid retained operation key')
                if pending_revision is not None and (type(pending_revision) is not int
                        or not 0 <= pending_revision <= 2**63 - 1):
                    raise ValueError('Invalid retained operation revision')
                safe_retained.append({
                    'instance_id': item['instance_id'], 'name': item['name'],
                    'disk_bytes': item['disk_bytes'], 'state': item['state'],
                    'pending_purge_key': pending_key,
                    'pending_purge_revision': pending_revision,
                })
            result = {'runtime': safe_runtime, 'capabilities': safe_caps, 'retained': safe_retained}
            operation = data.get('operation')
            if type(operation) is dict:
                result['operation'] = {k: operation[k] for k in ('id', 'status') if type(operation.get(k)) is str}
            return result
        except RuntimeRejected:
            raise
        except (OSError, ValueError, UnicodeError, RecursionError, http.client.HTTPException):
            raise RuntimeUnavailable('Supervisor unavailable') from None
        finally:
            connection.close()

    def get(self, actor_id):
        return self._request('/v1/me', {'actor_id': actor_id})

    def replay(self, actor_id, payload):
        return self._request('/v1/replay', dict(payload, actor_id=actor_id))

    def action(self, actor_id, payload, draft):
        return self._request('/v1/actions', dict(payload, actor_id=actor_id, settings={
            'name': draft['name'], 'instructions': draft['instructions'],
        }))


def configured_client():
    path = os.environ.get('AGENT_PLATFORM_SUPERVISOR_SOCKET')
    token = os.environ.get('AGENT_PLATFORM_SUPERVISOR_TOKEN_FILE')
    if not path and not token:
        return None
    return SupervisorClient(path, token)
