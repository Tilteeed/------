"""Host-bound, root-owned acceptance receipts for agent_proxy_v1.

Receipts are created only by the explicit Linux acceptance workflow after both
nftables/route and live Docker isolation checks pass. Missing or invalid
receipts never enable the production firewall gate.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from .firewall import FIREWALL_POLICY_VERSION

RECEIPT_FILENAME = 'firewall-acceptance.json'
RECEIPT_SCHEMA_VERSION = 1
REQUIRED_CHECKS = ('linux_proxy_isolated_check', 'linux_docker_proxy_acceptance')
MAX_RECEIPT_BYTES = 4096
_MACHINE_ID = re.compile(r'[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_PRIVATE_POOLS = tuple(ipaddress.IPv4Network(value) for value in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
_RECEIPT_KEYS = {
    'schema_version', 'host_id_sha256', 'policy_version',
    'agent_network_pool', 'frontend_network_pool', 'checks', 'accepted_at_unix',
}
_POSIX_O_DIRECTORY = getattr(os, 'O_DIRECTORY', 0)
_POSIX_O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


def validate_firewall_network_pools(agent_pool, frontend_pool):
    if type(agent_pool) is not str or type(frontend_pool) is not str:
        raise ValueError('Explicit network pools required')
    try:
        agent = ipaddress.IPv4Network(agent_pool, strict=True)
        frontend = ipaddress.IPv4Network(frontend_pool, strict=True)
    except (ValueError, ipaddress.NetmaskValueError):
        raise ValueError('Invalid IPv4 network pool') from None
    if (str(agent) != agent_pool or str(frontend) != frontend_pool
            or agent.prefixlen > 24 or frontend.prefixlen > 24
            or not any(agent.subnet_of(pool) for pool in _PRIVATE_POOLS)
            or not any(frontend.subnet_of(pool) for pool in _PRIVATE_POOLS)
            or agent.overlaps(frontend)):
        raise ValueError('Invalid or overlapping RFC1918 network pools')
    return str(agent), str(frontend)


def machine_id_sha256(path='/etc/machine-id'):
    """Return a digest of the local Linux machine-id without exposing its value."""
    nofollow = getattr(os, 'O_NOFOLLOW', 0)
    if not nofollow:
        raise ValueError('No-follow file access is required')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | nofollow
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size not in (32, 33)):
            raise ValueError('Unsafe machine identity file')
        raw = os.read(fd, 65)
        if len(raw) != info.st_size or len(raw) > 64:
            raise ValueError('Invalid machine identity file')
    finally:
        os.close(fd)
    if raw.endswith(b'\n'):
        raw = raw[:-1]
    try:
        machine_id = raw.decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('Invalid machine identity file') from None
    if _MACHINE_ID.fullmatch(machine_id) is None:
        raise ValueError('Invalid machine identity file')
    return hashlib.sha256(machine_id.encode('ascii')).hexdigest()


def build_firewall_acceptance_receipt(host_id_sha256, agent_pool, frontend_pool,
                                      *, accepted_at_unix=None):
    """Build the strict receipt payload after acceptance checks have passed."""
    if type(host_id_sha256) is not str or _DIGEST.fullmatch(host_id_sha256) is None:
        raise ValueError('Invalid host fingerprint')
    agent_pool, frontend_pool = validate_firewall_network_pools(agent_pool, frontend_pool)
    accepted_at_unix = int(time.time()) if accepted_at_unix is None else accepted_at_unix
    if type(accepted_at_unix) is not int or accepted_at_unix <= 0:
        raise ValueError('Invalid acceptance time')
    return {
        'schema_version': RECEIPT_SCHEMA_VERSION,
        'host_id_sha256': host_id_sha256,
        'policy_version': FIREWALL_POLICY_VERSION,
        'agent_network_pool': agent_pool,
        'frontend_network_pool': frontend_pool,
        'checks': list(REQUIRED_CHECKS),
        'accepted_at_unix': accepted_at_unix,
    }


def firewall_acceptance_receipt_matches(receipt, host_id_sha256, agent_pool,
                                        frontend_pool):
    """Check schema, host, policy, exact tested pools, and completed checks."""
    try:
        expected_agent, expected_frontend = validate_firewall_network_pools(agent_pool, frontend_pool)
        if type(receipt) is not dict or set(receipt) != _RECEIPT_KEYS:
            return False
        if (type(receipt['schema_version']) is not int
                or receipt['schema_version'] != RECEIPT_SCHEMA_VERSION
                or type(receipt['policy_version']) is not int
                or receipt['policy_version'] != FIREWALL_POLICY_VERSION
                or type(receipt['accepted_at_unix']) is not int
                or receipt['accepted_at_unix'] <= 0
                or type(receipt['host_id_sha256']) is not str
                or _DIGEST.fullmatch(receipt['host_id_sha256']) is None
                or type(receipt['checks']) is not list
                or receipt['checks'] != list(REQUIRED_CHECKS)):
            return False
        return (
            receipt['host_id_sha256'] == host_id_sha256
            and receipt['agent_network_pool'] == expected_agent
            and receipt['frontend_network_pool'] == expected_frontend
        )
    except (KeyError, TypeError, ValueError):
        return False


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate receipt key')
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ValueError('Invalid JSON constant')


def _open_state_directory(state_dir, *, create=False):
    if not _POSIX_O_DIRECTORY or not _POSIX_O_NOFOLLOW:
        raise ValueError('Safe POSIX directory access is required')
    path = Path(state_dir)
    if (not path.is_absolute() or str(path) != os.path.normpath(str(path))
            or path == Path('/') or str(path.resolve(strict=False)) != str(path)):
        raise ValueError('Unsafe acceptance state directory')
    if create and not os.path.lexists(path):
        parent = path.parent
        if not parent.exists() or str(parent.resolve(strict=True)) != str(parent):
            raise ValueError('Unsafe acceptance state parent')
        for directory in (parent, *parent.parents):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_mode & 0o022):
                raise ValueError('Root-controlled acceptance state parent required')
        path.mkdir(mode=0o700)
        getattr(os, 'chown')(path, 0, 0, follow_symlinks=False)
        getattr(os, 'chmod')(path, 0o700, follow_symlinks=False)
        parent_fd = os.open(parent, os.O_RDONLY | _POSIX_O_DIRECTORY | _POSIX_O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    if path.exists():
        for directory in (path.parent, *path.parents):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_mode & 0o022):
                raise ValueError('Root-controlled acceptance state ancestors required')
    flags = os.O_RDONLY | _POSIX_O_DIRECTORY | _POSIX_O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('Unsafe acceptance state directory')
        return fd
    except Exception:
        os.close(fd)
        raise


def validate_acceptance_state_path(state_dir):
    """Preflight an existing private state dir or its root-controlled parent."""
    path = Path(state_dir)
    if (not path.is_absolute() or str(path) != os.path.normpath(str(path))
            or path == Path('/') or str(path.resolve(strict=False)) != str(path)):
        raise ValueError('Unsafe acceptance state directory')
    parent = path.parent
    if not parent.exists() or str(parent.resolve(strict=True)) != str(parent):
        raise ValueError('Unsafe acceptance state parent')
    for directory in (parent, *parent.parents):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_mode & 0o022):
            raise ValueError('Root-controlled acceptance state parent required')
    if os.path.lexists(path):
        directory_fd = _open_state_directory(path)
        os.close(directory_fd)
    return path


def _read_receipt(dir_fd):
    flags = os.O_RDONLY | _POSIX_O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(RECEIPT_FILENAME, flags, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > MAX_RECEIPT_BYTES):
            raise ValueError('Unsafe acceptance receipt')
        blob = os.read(fd, MAX_RECEIPT_BYTES + 1)
        if len(blob) != info.st_size or len(blob) > MAX_RECEIPT_BYTES:
            raise ValueError('Invalid acceptance receipt size')
    finally:
        os.close(fd)
    return json.loads(blob.decode('utf-8'), object_pairs_hook=_strict_object,
                      parse_constant=_reject_json_constant)


def load_firewall_acceptance_receipt(state_dir, agent_pool, frontend_pool,
                                     *, machine_id_path='/etc/machine-id'):
    """Return true only for a private receipt matching this host and runtime pools."""
    directory_fd = None
    try:
        host_digest = machine_id_sha256(machine_id_path)
        directory_fd = _open_state_directory(state_dir)
        receipt = _read_receipt(directory_fd)
        return firewall_acceptance_receipt_matches(
            receipt, host_digest, agent_pool, frontend_pool)
    except (OSError, RuntimeError, UnicodeDecodeError, ValueError, TypeError,
            json.JSONDecodeError):
        return False
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def write_firewall_acceptance_receipt(state_dir, agent_pool, frontend_pool,
                                      *, machine_id_path='/etc/machine-id',
                                      expected_host_id_sha256=None):
    """Atomically write a root-owned receipt; call only after both acceptance checks pass."""
    host_digest = machine_id_sha256(machine_id_path)
    if (expected_host_id_sha256 is not None
            and host_digest != expected_host_id_sha256):
        raise ValueError('Host identity changed during acceptance')
    receipt = build_firewall_acceptance_receipt(host_digest, agent_pool, frontend_pool)
    payload = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    directory_fd = _open_state_directory(state_dir, create=True)
    temporary = '.firewall-acceptance-' + secrets.token_hex(8) + '.tmp'
    file_fd = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _POSIX_O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
        file_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        getattr(os, 'fchown')(file_fd, 0, 0)
        getattr(os, 'fchmod')(file_fd, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(file_fd, payload[offset:])
            if written <= 0:
                raise OSError('short receipt write')
            offset += written
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        os.replace(temporary, RECEIPT_FILENAME,
                   src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        if file_fd is not None:
            os.close(file_fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(directory_fd)
    return Path(state_dir) / RECEIPT_FILENAME
