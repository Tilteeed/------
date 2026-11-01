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


MAX_JSON_RESPONSE_BYTES = 65536
MAX_PREVIEW_TEXT_BYTES = 256 * 1024
# Supervisor JSON is emitted with ensure_ascii=True. In the worst case each
# input byte becomes a six-byte \\uXXXX escape, plus a small object envelope.
MAX_PREVIEW_JSON_RESPONSE_BYTES = MAX_PREVIEW_TEXT_BYTES * 6 + 64


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

    def _request(self, path, payload, *, response_kind='runtime',
                 response_limit=MAX_JSON_RESPONSE_BYTES):
        if (type(response_limit) is not int
                or not MAX_JSON_RESPONSE_BYTES <= response_limit <= MAX_PREVIEW_JSON_RESPONSE_BYTES):
            raise RuntimeUnavailable('Invalid supervisor response limit')
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
            # Error envelopes remain on the normal small-response budget even
            # when the request is allowed to return a large text preview.
            limit = (response_limit if response.status in (200, 201, 202)
                     else MAX_JSON_RESPONSE_BYTES)
            raw = response.read(limit + 1)
            if len(raw) > limit:
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
                    'file_not_found': 'Файл в сохранённой рабочей папке не найден.',
                    'file_too_large': 'Файл превышает допустимый размер скачивания.',
                    'invalid_file_path': 'Недопустимый путь к файлу.',
                    'preview_not_supported': 'Файл нельзя показать как текст; попробуйте скачать его.',
                    'workspace_unavailable': 'Сохранённая рабочая папка не прошла проверку.',
                }
                status = response.status if response.status in (400, 404, 409, 413, 415, 422, 429, 503) else 503
                raise RuntimeRejected(status, code, messages.get(code, 'Supervisor отклонил операцию. Проверьте состояние экземпляра.'))
            if response_kind == 'json':
                if type(data) is not dict:
                    raise ValueError('Invalid supervisor JSON response shape')
                return data
            if response_kind != 'runtime':
                raise ValueError('Invalid expected supervisor response kind')
            runtime, capabilities = data.get('runtime'), data.get('capabilities')
            if type(runtime) is not dict or type(capabilities) is not dict:
                raise ValueError('Invalid supervisor response shape')
            # Deliberate response allowlist: no token, paths, environment or raw inspect.
            safe_runtime = {k: v for k, v in runtime.items() if k in (
                'state', 'gateway', 'model', 'telegram', 'instance_id', 'container_id',
                'settings_revision', 'operation_status', 'error_code', 'retained_data',
                'pending_create_key', 'pending_create_revision',
                'pending_restore_key', 'pending_restore_revision',
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

    def workspace_list(self, actor_id, instance_id, directory, offset):
        if type(offset) is not int or not 0 <= offset <= 10000:
            raise RuntimeUnavailable('Invalid workspace offset')
        data = self._request('/v1/retained/workspace', {
            'actor_id': actor_id, 'instance_id': instance_id,
            'action': 'list', 'directory': directory, 'offset': offset,
        }, response_kind='json')
        entries = data.get('entries')
        next_offset = data.get('next_offset')
        if (set(data) != {'directory', 'entries', 'next_offset'} or data.get('directory') != directory
                or type(entries) is not list or len(entries) > 50
                or (next_offset is not None and (type(next_offset) is not int or next_offset != offset + len(entries)))):
            raise RuntimeUnavailable('Invalid workspace listing')
        safe_entries = []
        for item in entries:
            if type(item) is not dict or set(item) != {'name', 'kind', 'size'}:
                raise RuntimeUnavailable('Invalid workspace entry')
            name, kind, size = item['name'], item['kind'], item['size']
            if type(name) is str and (chr(92) in name or chr(0) in name):
                raise RuntimeUnavailable('Invalid workspace entry')
            if type(kind) is not str:
                raise RuntimeUnavailable('Invalid workspace entry')
            if (type(name) is not str or not name or name.startswith('.') or '/' in name or '\\\\' in name
                    or len(name.encode('utf-8')) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in name)
                    or kind not in {'file', 'directory'} or type(size) is not int or not 0 <= size <= 2**63 - 1):
                raise RuntimeUnavailable('Invalid workspace entry')
            safe_entries.append({'name': name, 'kind': kind, 'size': size})
        return {'directory': directory, 'entries': safe_entries, 'next_offset': next_offset}

    def workspace_preview(self, actor_id, instance_id, path):
        data = self._request('/v1/retained/workspace', {
            'actor_id': actor_id, 'instance_id': instance_id,
            'action': 'preview', 'path': path,
        }, response_kind='json', response_limit=MAX_PREVIEW_JSON_RESPONSE_BYTES)
        text = data.get('text')
        if type(text) is str and chr(0) in text:
            raise RuntimeUnavailable('Invalid workspace preview')
        if (set(data) != {'text'} or type(text) is not str or '\\x00' in text
                or len(text.encode('utf-8')) > 256 * 1024):
            raise RuntimeUnavailable('Invalid workspace preview')
        return {'text': text}

    def workspace_download(self, actor_id, instance_id, path):

        connection = UnixConnection(self.socket_path)
        try:
            with self.token_file.open('rb') as source:
                raw_token = source.read(257)
            token = raw_token.decode('ascii').strip()
            if len(raw_token) > 256 or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', token):
                raise ValueError('Invalid service credential')
            payload = {'actor_id': actor_id, 'instance_id': instance_id,
                       'action': 'download', 'path': path}
            body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            if len(body) > 65536:
                raise ValueError('Oversized supervisor request')
            connection.request('POST', '/v1/retained/workspace', body=body, headers={
                'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                'Accept': 'application/octet-stream', 'Connection': 'close',
            })
            response = connection.getresponse()
            content = response.read(16 * 1024 * 1024 + 1)
            if response.status != 200:
                if len(content) > 65536:
                    raise ValueError('Oversized supervisor error response')
                data = json.loads(content, object_pairs_hook=_unique)
                code = data.get('code', 'supervisor_rejected') if type(data) is dict else 'supervisor_rejected'
                if type(code) is not str or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code):
                    code = 'supervisor_rejected'
                messages = {
                    'file_not_found': 'Файл в сохранённой рабочей папке не найден.',
                    'file_too_large': 'Файл превышает допустимый размер скачивания.',
                    'invalid_file_path': 'Недопустимый путь к файлу.',
                    'workspace_unavailable': 'Сохранённая рабочая папка не прошла проверку.',
                }
                status = response.status if response.status in (400, 404, 409, 413, 415, 503) else 503
                raise RuntimeRejected(status, code, messages.get(code, 'Supervisor отклонил чтение файла.'))
            if (len(content) > 16 * 1024 * 1024
                    or response.getheader('Content-Type', '').split(';', 1)[0].lower() != 'application/octet-stream'
                    or response.getheader('Cache-Control') != 'no-store'
                    or response.getheader('X-Content-Type-Options') != 'nosniff'
                    or not response.getheader('Content-Disposition', '').startswith('attachment;')):
                raise ValueError('Invalid or oversized workspace download response')
            return content
        except RuntimeRejected:
            raise
        except (OSError, ValueError, UnicodeError, RecursionError, http.client.HTTPException):
            raise RuntimeUnavailable('Supervisor unavailable') from None
        finally:
            connection.close()

    def action(self, actor_id, payload, draft):
        request = dict(payload, actor_id=actor_id)
        if payload['action'] != 'restore':
            request['settings'] = {'name': draft['name'], 'instructions': draft['instructions']}
        return self._request('/v1/actions', request)


def configured_client():
    path = os.environ.get('AGENT_PLATFORM_SUPERVISOR_SOCKET')
    token = os.environ.get('AGENT_PLATFORM_SUPERVISOR_TOKEN_FILE')
    if not path and not token:
        return None
    return SupervisorClient(path, token)
