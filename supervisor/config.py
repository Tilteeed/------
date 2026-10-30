"""Trusted site-profile data only; loading a profile never verifies storage.

No hardware defaults, environment overrides or user-supplied Docker settings.
See docs/DEPLOYMENT_CONFIG.md for the boundary between config and enforcement.
"""
from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re


@dataclass(frozen=True, slots=True)
class StorageProfile:
    backend: str
    mountpoint: str
    expected_uuid: str


@dataclass(frozen=True, slots=True)
class AgentLimits:
    ram_bytes: int
    cpu_millicores: int
    pids_limit: int
    disk_bytes: int


@dataclass(frozen=True, slots=True)
class DeploymentProfile:
    schema_version: int
    profile_version: str
    mode: str
    storage: StorageProfile
    agent_limits: AgentLimits


def _require_fields(value, names, section):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError(f'Invalid {section} fields')


def validate_profile(data) -> DeploymentProfile:
    """Validate and snapshot a trusted administrator's profile, not a browser request."""
    _require_fields(data, ('schema_version', 'profile_version', 'mode', 'storage', 'agent_limits'), 'profile')
    _require_fields(data['storage'], ('backend', 'mountpoint', 'expected_uuid'), 'storage')
    _require_fields(data['agent_limits'], ('ram_bytes', 'cpu_millicores', 'pids_limit', 'disk_bytes'), 'agent limits')
    if type(data['schema_version']) is not int or data['schema_version'] != 1:
        raise ValueError('Unsupported profile schema version')
    version = data['profile_version']
    if type(version) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,64}', version) is None:
        raise ValueError('Invalid profile version')
    if type(data['mode']) is not str or data['mode'] not in ('lab', 'final'):
        raise ValueError('Invalid server policy mode')
    # Explicit integer units: bytes, millicores (1000 = one CPU), task count.
    # Positive int64 is a schema bound, not evidence of host/backend capacity.
    for value in data['agent_limits'].values():
        if type(value) is not int or not 0 < value <= 2**63 - 1:
            raise ValueError('Agent limits must be positive int64 values')
    storage = data['storage']
    # Schema v1 supports XFS; actual enforcement is separately checked by volumes.py.
    if type(storage['backend']) is not str or storage['backend'] != 'xfs_project_quota':
        raise ValueError('Unsupported storage backend')
    path = storage['mountpoint']
    # Lexical checks only. Never resolve, create, mount or auto-select this path.
    if (type(path) is not str or len(path) > 4096
            or re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', path) is None
            or '..' in PurePosixPath(path).parts or str(PurePosixPath(path)) != path):
        raise ValueError('Storage mountpoint must be a canonical non-root POSIX path')
    uuid = storage['expected_uuid']
    if (type(uuid) is not str or re.fullmatch(
            r'[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}', uuid) is None):
        raise ValueError('Storage UUID must use the exact hyphenated format')
    return DeploymentProfile(
        schema_version=data['schema_version'],
        profile_version=data['profile_version'],
        mode=data['mode'],
        storage=StorageProfile(**data['storage']),
        agent_limits=AgentLimits(**data['agent_limits']),
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate profile field')
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError('Non-finite JSON number')


def load_profile(path) -> DeploymentProfile:
    """Read only an explicitly supplied admin file; never discover a site profile."""
    # Bound the read itself, not just the decoded JSON after an unbounded read.
    with Path(path).open('rb') as stream:
        blob = stream.read(65536 + 1)
    if len(blob) > 65536:
        raise ValueError('Deployment profile exceeds 65536 bytes')
    try:
        data = json.loads(blob.decode('utf-8'), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ValueError('Invalid deployment profile JSON') from None
    return validate_profile(data)


def _main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='Validate a site profile; never inspect or change host storage.')
    parser.add_argument('--check', required=True, metavar='PATH', help='Explicit trusted JSON profile file')
    args = parser.parse_args()
    try:
        load_profile(args.check)
    except OSError:
        print('Deployment profile rejected: file is unavailable.', file=sys.stderr)
        return 2
    except ValueError as error:
        # Validation errors contain fixed labels, never the file contents or path.
        print(f'Deployment profile rejected: {error}', file=sys.stderr)
        return 2
    print('Deployment profile valid; storage and runtime are NOT verified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())
