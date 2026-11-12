#!/usr/bin/env python3
"""Root-only operator CLI for reading or changing the persisted Ollama model."""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from supervisor.ollama_config import MODEL_NAMES
from supervisor.service import load_service_config


ADMIN_PATH = '/v1/admin/ollama/model'
MAX_RESPONSE_BYTES = 65536


class UnixAdminConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=21600):
        super().__init__('localhost', timeout=timeout)
        self.path = str(path)

    def connect(self):
        family = getattr(socket, 'AF_UNIX', None)
        if not isinstance(family, int):
            raise OSError('Unix sockets unavailable')
        connection = socket.socket(family, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self.path)
        except BaseException:
            connection.close()
            raise
        self.sock = connection


def build_payload(action, expected_model_id=None, new_model_id=None):
    if action == 'status' and expected_model_id is None and new_model_id is None:
        return {'action': 'status'}
    if (action != 'set' or type(expected_model_id) is not str
            or expected_model_id not in MODEL_NAMES
            or type(new_model_id) is not str or new_model_id not in MODEL_NAMES):
        raise ValueError('set requires two approved model IDs')
    return {'expected_model_id': expected_model_id, 'new_model_id': new_model_id}


def _service_token(path):
    nofollow = getattr(os, 'O_NOFOLLOW', None)
    if type(nofollow) is not int:
        raise ValueError('Secure host credential access is unavailable')
    flags = os.O_RDONLY | nofollow | getattr(os, 'O_CLOEXEC', 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise ValueError('Host service credential is unavailable') from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o640):
            raise ValueError('Host service credential failed permission checks')
        raw = os.read(fd, 257)
    finally:
        os.close(fd)
    if len(raw) > 256 or re.fullmatch(rb'[A-Za-z0-9_-]{32,256}', raw) is None:
        raise ValueError('Host service credential is invalid')
    return raw.decode('ascii')


def request(config, payload):
    state_dir = Path(config['state_dir'])
    socket_path = state_dir / 'control-ui-maintenance.sock'
    token = _service_token(Path(config['token_file']))
    body = json.dumps(payload, ensure_ascii=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii')
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError('Admin request exceeds the size limit')
    connection = UnixAdminConnection(socket_path)
    try:
        connection.request('POST', ADMIN_PATH, body=body, headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Connection': 'close',
        })
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError('Supervisor response exceeds the size limit')
        result = json.loads(raw.decode('ascii'))
        if type(result) is not dict:
            raise ValueError('Invalid Supervisor response')
        if response.status != 200:
            code = result.get('code')
            if type(code) is not str or re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code) is None:
                code = 'supervisor_rejected'
            raise RuntimeError(code)
        return result
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'set'))
    parser.add_argument('--config', required=True, help='Trusted root-controlled runtime.json')
    parser.add_argument('--model-id', choices=sorted(MODEL_NAMES),
                        help='New administrator-selected model (required for set)')
    parser.add_argument('--enable-host-maintenance', action='store_true',
                        help='Explicitly authorize this root-only maintenance command')
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or os.geteuid() != 0 or not args.enable_host_maintenance:
        parser.error('Linux, root, and --enable-host-maintenance are required')
    if (args.action == 'set') != (args.model_id is not None):
        parser.error('--model-id is required only for set')
    try:
        config = load_service_config(args.config)
        if config.get('ollama') is None:
            parser.error('The trusted runtime config has no Ollama policy')
        if args.action == 'status':
            result = request(config, build_payload('status'))
        else:
            current = request(config, build_payload('status'))
            current_model = current.get('model_id') if type(current) is dict else None
            if type(current_model) is not str or current_model not in MODEL_NAMES:
                raise ValueError('Supervisor returned an invalid model selection')
            result = request(config, build_payload('set', current_model, args.model_id))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, 'Model maintenance failed: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
