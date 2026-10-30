"""Read-only XFS backend preflight, never a per-instance quota verification.

Host paths/identity come from the administrator's validated deployment profile.
No mount, formatting, quota assignment, Docker access or fallback is performed.
"""
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import PurePosixPath
import re
import sys
import subprocess
from .config import DeploymentProfile, load_profile, validate_profile
from .probes import ProbeFailure, run_command


@dataclass(frozen=True, slots=True)
class StorageReport:
    backend_ready: bool
    errors: tuple[str, ...]
    disk_quota_verified: bool = field(default=False, init=False)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate mount field')
        result[key] = value
    return result


def _mount(text, profile):
    if type(text) is not str or len(text.encode('utf-8')) > 65536:
        raise ValueError('Invalid mount output')
    data = json.loads(text, object_pairs_hook=_unique_object)
    if type(data) is not dict or set(data) != {'filesystems'}:
        raise ValueError('Invalid mount metadata')
    mounts = data['filesystems']
    if type(mounts) is not list or len(mounts) != 1 or type(mounts[0]) is not dict:
        raise ValueError('Ambiguous mount')
    mount = mounts[0]
    required = {'target', 'source', 'fstype', 'uuid', 'options', 'fsroot'}
    if not required.issubset(mount) or set(mount) - required - {'children'}:
        raise ValueError('Invalid mount columns')
    if (mount.get('target') != profile.storage.mountpoint or mount.get('fstype') != 'xfs'
            or mount.get('fsroot') != '/' or mount.get('children') not in (None, [])):
        raise ValueError('Wrong mount')
    source, uuid, options = (mount.get(key) for key in ('source', 'uuid', 'options'))
    if (type(source) is not str
            or re.fullmatch(r'/dev/[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*', source) is None
            or '..' in PurePosixPath(source).parts or str(PurePosixPath(source)) != source):
        raise ValueError('Invalid device')
    if (type(uuid) is not str or re.fullmatch(
            r'[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}', uuid) is None
            or uuid.casefold() != profile.storage.expected_uuid.casefold()):
        raise ValueError('Wrong UUID')
    if type(options) is not str or not options or any(ord(c) < 33 or ord(c) > 126 for c in options):
        raise ValueError('Invalid mount options')
    flags = options.split(',')
    if (len(flags) != len(set(flags)) or '' in flags or 'rw' not in flags
            or not {'prjquota', 'pquota'}.intersection(flags)
            or {'ro', 'noquota', 'pqnoenforce', 'bind', 'rbind'}.intersection(flags)):
        raise ValueError('Quota mount options unavailable')
    return mount


def inspect_storage(profile, *, run=None, realpath=None) -> StorageReport:
    if sys.platform != 'linux':
        return StorageReport(False, ('unsupported_platform',))
    if type(profile) is not DeploymentProfile:
        return StorageReport(False, ('invalid_profile',))
    try:
        profile = validate_profile(asdict(profile))
    except ValueError:
        return StorageReport(False, ('invalid_profile',))
    run = run_command if run is None else run
    realpath = (lambda path: os.path.realpath(path, strict=True)) if realpath is None else realpath
    try:
        if realpath(profile.storage.mountpoint) != profile.storage.mountpoint:
            return StorageReport(False, ('noncanonical_target',))
        result = _inspect(profile, run=run)
        if result.backend_ready and realpath(profile.storage.mountpoint) != profile.storage.mountpoint:
            return StorageReport(False, ('target_changed',))
        return result
    except ProbeFailure as error:
        known = {'command_unavailable', 'command_failed', 'command_timeout',
                 'invalid_output', 'output_limit', 'output_timeout'}
        return StorageReport(False, (error.code if error.code in known else 'probe_failed',))
    except (OSError, ValueError, RecursionError, subprocess.TimeoutExpired):
        return StorageReport(False, ('probe_failed',))


def _inspect(profile, *, run):
    target = profile.storage.mountpoint
    command = ['findmnt', '--json', '--mountpoint', target,
               '--output', 'TARGET,SOURCE,FSTYPE,UUID,OPTIONS,FSROOT']
    try:
        first = _mount(run(command), profile)
    except (ValueError, RecursionError):
        return StorageReport(False, ('invalid_mount',))
    quota = run(['xfs_quota', '-x', '-c', 'state -p', target])
    if type(quota) is not str or len(quota.encode('utf-8')) > 65536:
        return StorageReport(False, ('invalid_quota_state',))
    lines = [line.strip() for line in quota.splitlines() if line.strip()]
    header = f"Project quota state on {target} ({first['source']})"
    headers = [line for line in lines if 'quota state' in line]
    accounting = [line for line in lines if line.startswith('Accounting:')]
    enforcement = [line for line in lines if line.startswith('Enforcement:')]
    if (not lines or lines[0] != header or headers != [header]
            or accounting != ['Accounting: ON'] or enforcement != ['Enforcement: ON']):
        return StorageReport(False, ('invalid_quota_state',))
    try:
        second = _mount(run(command), profile)
    except (ValueError, RecursionError):
        return StorageReport(False, ('invalid_mount',))
    if first != second:
        return StorageReport(False, ('mount_changed',))
    return StorageReport(True, ())


def _main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description='Read-only storage backend preflight; never assigns quotas.')
    parser.add_argument('--check', required=True, metavar='PROFILE', help='Explicit trusted deployment profile')
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.check)
    except (OSError, ValueError):
        report = StorageReport(False, ('invalid_profile',))
    else:
        report = inspect_storage(profile)
    result = asdict(report)
    result['status'] = 'backend_ready' if report.backend_ready else 'blocked'
    print(json.dumps(result, sort_keys=True))
    return 0 if report.backend_ready else 2


if __name__ == '__main__':
    raise SystemExit(_main())
