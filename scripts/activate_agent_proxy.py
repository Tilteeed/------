#!/usr/bin/env python3
"""Run both Linux acceptance checks and record a host-bound firewall receipt.

This command is intentionally opt-in. It is for an explicitly disposable
Linux/Docker host; it never pulls images or starts the Supervisor service.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from supervisor.firewall_acceptance import (
    build_firewall_acceptance_receipt,
    machine_id_sha256,
    validate_acceptance_state_path,
    write_firewall_acceptance_receipt,
)

_IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')


def _run_check(label, argv):
    # Child harnesses bound their Docker/nft commands. Do not impose an outer
    # kill timeout: interrupting a child would bypass its cleanup path.
    try:
        result = subprocess.run(
            argv, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            shell=False, check=False)
    except OSError:
        raise RuntimeError(label + ' could not start') from None
    if result.returncode != 0:
        raise RuntimeError(label + ' failed; no acceptance receipt was written')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-pool', required=True,
                        help='Explicit RFC1918 IPv4 pool to be accepted on this host')
    parser.add_argument('--frontend-pool', required=True,
                        help='Second explicit, disjoint RFC1918 IPv4 pool')
    parser.add_argument('--probe-image', required=True,
                        help='Already-local immutable sha256 image; never pulled')
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
        validate_acceptance_state_path(args.state_dir)
        # Reuse the receipt's strict pool validator before running privileged probes.
        build_firewall_acceptance_receipt(
            '0' * 64, args.agent_pool, args.frontend_pool, accepted_at_unix=1)
        host_digest = machine_id_sha256()
        _run_check('isolated Linux route/nftables acceptance', [
            sys.executable, str(ROOT / 'scripts' / 'linux_proxy_isolated_check.py'),
            '--agent-pool', args.agent_pool,
            '--frontend-pool', args.frontend_pool,
        ])
        print('PASS: isolated Linux route/nftables acceptance')
        _run_check('live Docker packet-isolation acceptance', [
            sys.executable, str(ROOT / 'scripts' / 'linux_docker_proxy_acceptance.py'),
            '--agent-pool', args.agent_pool,
            '--frontend-pool', args.frontend_pool,
            '--probe-image', args.probe_image,
            '--execute', '--confirm-disposable-host',
        ])
        print('PASS: live Docker packet-isolation acceptance')
        if machine_id_sha256() != host_digest:
            raise ValueError('Host identity changed during acceptance; no receipt written')
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
