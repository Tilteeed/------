#!/usr/bin/env python3
"""Write explicit host-supervisor config; does NOT start services or set quotas.

Run by the operator on Linux after building the already selected OpenClaw image.
The local image is resolved to its immutable ID; no pull/install is performed.
"""
import argparse
from dataclasses import asdict
import stat
import json
import os
from pathlib import Path
import re
import sys

# Permit execution from the project root without installing this project.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from supervisor.config import load_profile
from supervisor.probes import ProbeFailure, run_command


def amount(value):
    number = int(value)
    if not 0 <= number <= 2**63 - 1:
        raise argparse.ArgumentTypeError('Expected non-negative int64')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--image', required=True, help='Existing local OpenClaw image; never pulled')
    parser.add_argument('--capacity-ram-bytes', type=amount, required=True)
    parser.add_argument('--capacity-cpu-millicores', type=amount, required=True)
    parser.add_argument('--capacity-disk-bytes', type=amount, required=True)
    parser.add_argument('--disk-floor-bytes', type=amount, required=True)
    parser.add_argument('--state-dir', default='/var/lib/personal-agent-supervisor')
    parser.add_argument('--socket-path', default='/run/personal-agent-supervisor/control.sock')
    parser.add_argument('--prepare-host-config', action='store_true')
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or not args.prepare_host_config or os.geteuid() != 0:
        parser.error('Explicit --prepare-host-config, Linux and root required')
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}', args.image) is None:
        parser.error('Explicit local image name or immutable ID required')
    try:
        profile_path = Path(args.profile).resolve(strict=True)
        profile = load_profile(profile_path)
        if profile.agent_limits.disk_bytes % 1024:
            raise ValueError('Disk limit must be an exact number of KiB for this XFS backend')
        for capacity, requested in ((args.capacity_ram_bytes, profile.agent_limits.ram_bytes),
                                    (args.capacity_cpu_millicores, profile.agent_limits.cpu_millicores),
                                    (args.capacity_disk_bytes, profile.agent_limits.disk_bytes)):
            if capacity < requested:
                raise ValueError('Each total capacity must fit at least one configured agent')
        state_dir, socket_path = Path(args.state_dir), Path(args.socket_path)
        if (state_dir == Path('/') or socket_path.parent == Path('/')
                or not state_dir.is_absolute() or not socket_path.is_absolute()
                or socket_path.name != 'control.sock'
                or str(state_dir) != os.path.normpath(str(state_dir))
                or str(socket_path) != os.path.normpath(str(socket_path))):
            raise ValueError('Canonical absolute service paths required; socket name must be control.sock')
        # State and credential must not live inside agent-controlled quota data.
        if (state_dir == Path(profile.storage.mountpoint) or Path(profile.storage.mountpoint) in state_dir.parents
                or socket_path.is_relative_to(state_dir) or state_dir.is_relative_to(socket_path.parent)
                or socket_path.parent.is_relative_to(Path(profile.storage.mountpoint))
                or len(str(socket_path).encode('utf-8')) > 107):
            raise ValueError('Service state must be outside the agent data mount')
        image = run_command(['docker', 'image', 'inspect', '--format', '{{.Id}}', '--', args.image]).strip()
        if re.fullmatch(r'sha256:[0-9a-f]{64}', image) is None:
            raise ValueError('Docker did not return an immutable image ID')
        # Copy the validated profile into root-controlled state; a user checkout
        # is not a safe source for a long-running privileged service.
        for directory in (state_dir.parent, *state_dir.parent.parents):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or str(directory.resolve(strict=True)) != str(directory)):
                raise ValueError('Root-controlled canonical state ancestors required')
        if not os.path.lexists(state_dir):
            state_dir.mkdir(mode=0o700)
            os.chown(state_dir, 0, 0, follow_symlinks=False)
            os.chmod(state_dir, 0o700, follow_symlinks=False)
        info = state_dir.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or str(state_dir.resolve(strict=True)) != str(state_dir)
                or state_dir.stat().st_dev == Path(profile.storage.mountpoint).stat().st_dev):
            raise ValueError('Private root state must be outside the data filesystem')
        output = state_dir / 'runtime.json'
        if os.path.lexists(output):
            raise ValueError('Existing runtime config is never overwritten')
        snapshot = state_dir / 'deployment.json'
        if os.path.lexists(snapshot):
            info = snapshot.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or load_profile(snapshot) != profile):
                raise ValueError('Existing administrative profile differs or is unsafe')
        else:
            fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as target:
                os.fchown(target.fileno(), 0, 0)
                json.dump(asdict(profile), target, indent=2)
                target.write('\n')
                target.flush()
                os.fsync(target.fileno())
        result = {
            'profile_path': str(snapshot), 'state_dir': str(state_dir),
            'socket_path': str(socket_path), 'token_file': str(state_dir / 'service.token'),
            'image': image, 'capacity_ram_bytes': args.capacity_ram_bytes,
            'capacity_cpu_millicores': args.capacity_cpu_millicores,
            'capacity_disk_bytes': args.capacity_disk_bytes, 'disk_floor_bytes': args.disk_floor_bytes,
        }
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
            json.dump(result, target, indent=2)
            target.write('\n')
    except (OSError, ValueError, ProbeFailure):
        print('Configuration not written: check profile, capacities, existing output and local Docker image.', file=sys.stderr)
        return 2
    print('Root-controlled config prepared. No service started; no quotas, mounts or agent data changed.')
    print('Runtime config: ' + str(output))
    print('For the opt-in Compose bridge, set these non-secret paths:')
    print('SUPERVISOR_SOCKET_DIR=' + str(socket_path.parent))
    print('SUPERVISOR_TOKEN_FILE=' + result['token_file'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
