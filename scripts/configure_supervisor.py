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
from supervisor.firewall_acceptance import (
    build_firewall_acceptance_receipt, load_firewall_acceptance_receipt,
)
from supervisor.ollama_config import MODEL_NAMES, validate_ollama_config
from supervisor.runtime_store import RuntimeStore
from supervisor.probes import ProbeFailure, run_command


def amount(value):
    number = int(value)
    if not 0 <= number <= 2**63 - 1:
        raise argparse.ArgumentTypeError('Expected non-negative int64')
    return number


def build_ollama_policy(base_url, default_model_id, max_tokens,
                        context_tokens=8192, think=False):
    """Build an optional trusted model policy; no endpoint means LLM stays disabled."""
    if (base_url is None and default_model_id is None and max_tokens is None
            and context_tokens == 8192 and think is False):
        return None
    if base_url is None or default_model_id is None or max_tokens is None:
        raise ValueError('Ollama URL, admin-selected model and max tokens are required together')
    policy = {
        'base_url': base_url,
        'default_model_id': default_model_id,
        'context_tokens': context_tokens,
        'max_tokens': max_tokens,
        'think': think,
    }
    return asdict(validate_ollama_config(policy))


def validate_network_activation(profile, domain, agent_pool, frontend_pool, state_dir):
    if profile not in RuntimeStore.NETWORK_PROFILES:
        raise ValueError('Invalid default network profile')
    if (agent_pool is None) != (frontend_pool is None):
        raise ValueError('Both agent and frontend network pools are required together')
    if agent_pool is not None:
        try:
            build_firewall_acceptance_receipt(
                '0' * 64, agent_pool, frontend_pool, accepted_at_unix=1)
        except ValueError:
            raise ValueError('Explicit disjoint RFC1918 agent and frontend network pools required') from None
    if profile == RuntimeStore.NETWORK_PROFILE_PROXY:
        if domain is None or agent_pool is None:
            raise ValueError('agent_proxy_v1 requires a Control UI domain and both explicit pools')
        if not load_firewall_acceptance_receipt(state_dir, agent_pool, frontend_pool):
            raise ValueError('A matching host-bound Linux/Docker acceptance receipt is required')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--image', required=True, help='Existing local OpenClaw image; never pulled')
    parser.add_argument('--capacity-ram-bytes', type=amount, required=True)
    parser.add_argument('--capacity-cpu-millicores', type=amount, required=True)
    parser.add_argument('--capacity-disk-bytes', type=amount, required=True)
    parser.add_argument('--disk-floor-bytes', type=amount, required=True)
    parser.add_argument('--control-ui-domain', default=None,
                        help='Trusted wildcard subdomain suffix for isolated Control UI origins')
    parser.add_argument('--network-profile-default', choices=sorted(RuntimeStore.NETWORK_PROFILES),
                        default=RuntimeStore.NETWORK_PROFILE_LEGACY)
    parser.add_argument('--agent-network-pool', default=None)
    parser.add_argument('--frontend-network-pool', default=None)
    parser.add_argument('--ollama-api-url', default=None,
                        help='Private IPv4 Ollama API address; enables the native provider')
    parser.add_argument('--ollama-default-model-id', choices=sorted(MODEL_NAMES), default=None,
                        help='Operator-selected default from the fixed approved model catalog')
    parser.add_argument('--ollama-context-tokens', type=amount, default=8192)
    parser.add_argument('--ollama-max-tokens', type=amount, default=None)
    parser.add_argument('--ollama-think', action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument('--state-dir', default='/var/lib/personal-agent-supervisor')
    parser.add_argument('--socket-path', default='/run/personal-agent-supervisor/control.sock')
    parser.add_argument('--prepare-host-config', action='store_true')
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or not args.prepare_host_config or os.geteuid() != 0:
        parser.error('Explicit --prepare-host-config, Linux and root required')
    try:
        ollama_policy = build_ollama_policy(
            args.ollama_api_url, args.ollama_default_model_id,
            args.ollama_max_tokens, args.ollama_context_tokens, args.ollama_think)
    except ValueError as error:
        parser.error(str(error))
    if args.control_ui_domain is not None:
        labels = args.control_ui_domain.split('.')
        label_re = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
        if (len(args.control_ui_domain) > 253 or len(labels) < 2
                or any(label_re.fullmatch(label) is None for label in labels)):
            parser.error('Control UI domain must be an exact lowercase DNS suffix without wildcards')
    try:
        validate_network_activation(
            args.network_profile_default, args.control_ui_domain,
            args.agent_network_pool, args.frontend_network_pool, args.state_dir)
    except ValueError as error:
        parser.error(str(error))
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
            'network_profile_default': args.network_profile_default,
            'control_ui_domain': args.control_ui_domain,
            'agent_network_pool': args.agent_network_pool,
            'frontend_network_pool': args.frontend_network_pool,
            'ollama': ollama_policy,
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
