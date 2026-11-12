#!/usr/bin/env python3
"""Opt-in real Linux AND private nested-Docker checks, then host-bound receipt.

No supplied reports, existing acceptance receipts, skipped checks or caller
Docker endpoints are accepted. No production firewall/service is activated.
"""
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.ollama_route_acceptance import CHECKS, binding, command, strict_json, validate_report
from scripts.ollama_route_linux import arguments, prerequisites, require_opt_in
from supervisor.firewall_acceptance import machine_id_sha256, validate_acceptance_state_path
from supervisor.ollama_firewall import write_ollama_route_receipt, load_ollama_route_receipt


def caller_inode():
    return str(os.stat('/proc/self/ns/net').st_ino)


def config_from(args):
    return binding(args.agent_pool, args.frontend_pool, args.ollama_pool,
                   args.endpoint, args.interface, machine_id_sha256())


def activate(args):
    validate_acceptance_state_path(args.state_dir)
    config = config_from(args)
    host = machine_id_sha256()
    if config['host_id_sha256'] != host:
        raise ValueError('Host changed before acceptance')
    original_inode = caller_inode()
    run_id = secrets.token_hex(16)
    common = ['--agent-pool', args.agent_pool, '--frontend-pool', args.frontend_pool,
              '--ollama-pool', args.ollama_pool, '--endpoint', args.endpoint,
              '--interface', args.interface, '--run-id', run_id,
              '--execute', '--confirm-disposable-host']
    for check in CHECKS:
        argv = [sys.executable, str(ROOT / 'scripts' / (check + '.py')), *common]
        if check == CHECKS[1]:
            argv += ['--probe-image', args.probe_image, '--image-archive', args.image_archive]
        # Only the bounded stdout of the successfully exited fixed command is
        # consumed. The command itself validates teardown before emitting JSON.
        report = validate_report(strict_json(command(argv, timeout=660)), config, check, run_id)
        if report['caller_netns_inode'] != original_inode:
            raise ValueError('Report is not from this caller namespace')
    if config_from(args) != config or machine_id_sha256() != host or caller_inode() != original_inode:
        raise ValueError('Host or route bindings changed during acceptance')
    receipt = write_ollama_route_receipt(args.state_dir, args.agent_pool, args.frontend_pool,
        args.ollama_pool, args.endpoint, args.interface, expected_host_id_sha256=host)
    if not load_ollama_route_receipt(args.state_dir, args.agent_pool, args.frontend_pool,
                                    args.ollama_pool, args.endpoint, args.interface):
        raise RuntimeError('Written Ollama route receipt failed production loader readback')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    arguments(parser, docker=True)
    parser.add_argument('--state-dir', default='/var/lib/personal-agent-supervisor')
    args = parser.parse_args(argv)
    require_opt_in(parser, args)
    try:
        prerequisites(args, docker=True)
        activate(args)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL: ' + str(error).replace('\n', ' ')[:300], file=sys.stderr)
        return 1
    print('Host-bound Ollama route receipt written and production-loader readback passed. '
          'Production firewall/profile/services unchanged.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
