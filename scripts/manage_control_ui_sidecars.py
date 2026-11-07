#!/usr/bin/env python3
"""Host-root CLI for plan/apply/status/resume of Control UI Sidecars."""
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

from supervisor.service import load_service_config


ADMIN_PATH = '/v1/admin/control-ui/sidecars'
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class UnixAdminConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=21600):
        super().__init__('localhost', timeout=timeout)
        self.path = str(path)

    def connect(self):
        family = getattr(socket, 'AF_UNIX', None)
        if type(family) is not int:
            raise OSError('Unix sockets unavailable')
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


def build_payload(action, plan_sha256=None):
    if action in {'plan', 'status', 'resume'}:
        if plan_sha256 is not None:
            raise ValueError('Only apply accepts a plan hash')
        return {'action': action}
    if action != 'apply' or type(plan_sha256) is not str \
            or re.fullmatch(r'[0-9a-f]{64}', plan_sha256) is None:
        raise ValueError('apply requires a lowercase SHA-256 plan hash')
    return {'action': 'apply', 'plan_sha256': plan_sha256}


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
            # The service token is root-owned, mode 0640, inside a mode-0700 directory.
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
    token_path = Path(config['token_file'])
    token = _service_token(token_path)
    connection = UnixAdminConnection(socket_path)
    body = json.dumps(payload, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
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
        data = json.loads(raw.decode('ascii'))
        if type(data) is not dict:
            raise ValueError('Invalid Supervisor response')
        if response.status != 200:
            code = data.get('code')
            if type(code) is not str or re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code) is None:
                code = 'supervisor_rejected'
            raise RuntimeError(code)
        return data
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'status', 'resume'))
    parser.add_argument('--config', required=True, help='Trusted host runtime.json')
    parser.add_argument('--plan-sha256', default=None,
                        help='Exact hash printed by plan; required for apply')
    parser.add_argument('--enable-host-maintenance', action='store_true',
                        help='Explicitly authorize the root-only maintenance command')
    args = parser.parse_args(argv)
    if (sys.platform != 'linux' or os.geteuid() != 0
            or not args.enable_host_maintenance):
        parser.error('Linux, root, and --enable-host-maintenance are required')
    try:
        payload = build_payload(args.action, args.plan_sha256)
        config = load_service_config(args.config)
        result = request(config, payload)
    except (ValueError, RuntimeError, OSError) as error:
        code = str(error)
        if re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code) is None:
            code = 'maintenance_request_failed'
        print('Control UI Sidecar maintenance failed: ' + code, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
