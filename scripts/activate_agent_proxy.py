#!/usr/bin/env python3
"""Run both Linux acceptance checks and record a host-bound firewall receipt.

This command is intentionally opt-in. It is for an explicitly disposable
Linux/Docker host; it never pulls images or starts the Supervisor service.
"""
import argparse
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import proxy_packet_acceptance as contract
from scripts.ollama_route_acceptance import command, strict_json
from supervisor.firewall_acceptance import (
    build_firewall_acceptance_receipt,
    machine_id_sha256,
    validate_acceptance_state_path,
    write_firewall_acceptance_receipt,
)

_IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')


def _run_check(label, argv):
    # Reuse the bounded pipe/process helper. Allow the private wrapper's 600s
    # namespace deadline plus teardown time before this outer fail-safe expires.
    try:
        return strict_json(command(argv, timeout=660))
    except (OSError, RuntimeError, ValueError, RecursionError, subprocess.SubprocessError):
        raise RuntimeError(label + ' failed or returned invalid JSON; no acceptance receipt was written') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-pool', required=True,
                        help='Explicit RFC1918 IPv4 pool to be accepted on this host')
    parser.add_argument('--frontend-pool', required=True,
                        help='Second explicit, disjoint RFC1918 IPv4 pool')
    parser.add_argument('--probe-image', required=True,
                        help='Already-local immutable sha256 image; never pulled')
    parser.add_argument('--image-archive', required=True,
                        help='Explicit local image archive for the private daemon; never pulled')
    parser.add_argument('--state-dir', default='/var/lib/personal-agent-supervisor',
                        help='Root-controlled Supervisor state directory')
    parser.add_argument('--execute', action='store_true',
                        help='Actually run the isolated Linux and live Docker checks')
    parser.add_argument('--confirm-disposable-host', action='store_true',
                        help='Confirm the target host contains no user workloads or data')
    args = parser.parse_args(argv)
    if (sys.platform != 'linux' or getattr(os, 'geteuid', lambda: -1)() != 0 or not args.execute
            or not args.confirm_disposable_host):
        parser.error('Linux, root, --execute and --confirm-disposable-host are required')
    if _IMAGE.fullmatch(args.probe_image) is None:
        parser.error('--probe-image must be an immutable sha256 digest')
    try:
        archive = Path(args.image_archive)
        if not archive.is_absolute() or not archive.is_file() or archive.is_symlink():
            raise ValueError('Explicit existing absolute image archive required (no symlinks or pulls)')
        validate_acceptance_state_path(args.state_dir)
        # Reuse the receipt's strict pool validator before running privileged probes.
        build_firewall_acceptance_receipt(
            '0' * 64, args.agent_pool, args.frontend_pool, accepted_at_unix=1)
        host_digest = machine_id_sha256()
        config = contract.binding(args.agent_pool, args.frontend_pool, host_digest)
        caller = str(os.stat('/proc/self/ns/net').st_ino)
        for check in contract.CHECKS:
            run_id = secrets.token_hex(16)
            child = [sys.executable, str(ROOT / 'scripts' / (check + '.py')),
                     '--agent-pool', args.agent_pool,
                     '--frontend-pool', args.frontend_pool,
                     '--execute', '--confirm-disposable-host', '--run-id', run_id]
            if check == 'linux_docker_proxy_acceptance':
                child += ['--probe-image', args.probe_image, '--image-archive', args.image_archive]
            report = contract.validate_report(_run_check(check, child), config, check, run_id)
            if (report['caller_netns_inode'] != caller
                    or str(os.stat('/proc/self/ns/net').st_ino) != caller
                    or machine_id_sha256() != host_digest):
                raise ValueError('Caller namespace or host identity changed; no receipt written')
            print('PASS: ' + check)
        if (machine_id_sha256() != host_digest
                or str(os.stat('/proc/self/ns/net').st_ino) != caller):
            raise ValueError('Caller namespace or host identity changed; no receipt written')
        receipt = write_firewall_acceptance_receipt(
            args.state_dir, args.agent_pool, args.frontend_pool,
            expected_host_id_sha256=host_digest)
    except (OSError, RuntimeError, ValueError) as error:
        print('FAIL: ' + str(error).replace('\n', ' ')[:240], file=sys.stderr)
        return 1
    print('Host-bound acceptance receipt written: ' + str(receipt))
    print('Receipt does not change the configured network profile; legacy_none remains the default.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
