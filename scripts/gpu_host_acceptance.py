#!/usr/bin/env python3
"""Explicit busy-host acceptance front door; never activates production services."""
import argparse
import copy
import os
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.acceptance_busy_host import ApprovedBudget
from scripts.gpu_acceptance_receipts import site_binding
from scripts.ollama_route_acceptance import strict_json

_KEYS = {'schema_version', 'site', 'budget', 'probe_image', 'image_archive',
         'production_docker_socket', 'candidate_dir'}


def _path(value):
    if (type(value) is not str or not value.startswith('/') or value.startswith('//')
            or value == '/' or any(ord(c) < 33 or ord(c) > 126 for c in value)
            or '\\' in value or '..' in PurePosixPath(value).parts
            or str(PurePosixPath(value)) != value):
        raise ValueError('Explicit normalized Linux path required')
    return value


def parse_config(value):
    """Pure, strict schema validation, with no host discovery/default site choices."""
    if (type(value) is not dict or set(value) != _KEYS
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise ValueError('Exact acceptance configuration schema required')
    result = copy.deepcopy(value)
    site_binding(result['site'], '0' * 64)
    ApprovedBudget.from_mapping(result['budget'])
    if type(result['probe_image']) is not str or re.fullmatch('sha256:[0-9a-f]{64}', result['probe_image']) is None:
        raise ValueError('Explicit immutable probe image required')
    for key in ('image_archive', 'production_docker_socket', 'candidate_dir'):
        _path(result[key])
    if len({result[key] for key in ('image_archive', 'production_docker_socket', 'candidate_dir')}) != 3:
        raise ValueError('Independent archive, socket and candidate paths required')
    return result


def secure_file(path):
    """Root-controlled, regular, single-link input; no symlink ancestors."""
    import stat
    path = Path(_path(str(path)))
    for directory in (path.parent, *path.parent.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Root-controlled input ancestors required')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
        raise ValueError('Root-controlled regular input required')
    return info


def read_config(path, *, secure=False):
    if secure:
        secure_file(path)
    flags = os.O_RDONLY | (getattr(os, 'O_NOFOLLOW', 0) if secure else 0)
    with open(os.open(path, flags), 'rb', closefd=True) as source:
        raw = source.read(262145)
    if len(raw) > 262144:
        raise ValueError('Acceptance configuration exceeds bound')
    return parse_config(strict_json(raw.decode('utf-8')))


def execute_config(config, *, jobs=None, source=None, store=None,
                   busy_host_approved=False, allow_host_inspection=False):
    """Connected orchestration. Injection is internal test API, never a CLI option."""
    from scripts import gpu_acceptance_receipts as receipts
    from scripts import proxy_packet_acceptance as base
    from scripts import ollama_route_acceptance as route
    if busy_host_approved is not True or allow_host_inspection is not True:
        return {'status': 'incomplete', 'phase': 'permission', 'checks': []}
    config = parse_config(config)
    if jobs is None:
        from scripts import gpu_acceptance_job as job
        try:
            jobs = job.LinuxJobs(config)
        except Exception as error:
            return {
                'status': 'incomplete', 'phase': 'preflight', 'checks': [],
                'job_units': [],
                'diagnostics': [job._diagnostic('host_preflight', error)],
            }
    if source is None:
        source = receipts.ProductionStateSource(docker_socket=config['production_docker_socket'])
    if store is None:
        store = receipts.RootCandidateStore(config['candidate_dir'])

    def validate(report, binding, check, run_id):
        contract = base if check in base.CHECKS else route
        expected = binding['base' if check in base.CHECKS else 'route']
        packet = contract.validate_report(report['evidence'], expected, check, run_id)
        if packet['caller_netns_inode'] != jobs.caller_inode:
            raise ValueError('Packet evidence not from the approved caller namespace')
        return True

    result = receipts.run_candidate_acceptance(config['site'], source=source, store=store,
        check_runner=jobs.run_check, report_validator=validate,
        cleanup_verifier=jobs.cleanup_verifier, busy_host_approved=True, allow_host_inspection=True)
    # Owned names support scoped diagnosis; not a cleanup-success assertion.
    result['job_units'] = [plan.unit for plan in getattr(jobs, 'plans', ())]
    diagnostics = getattr(jobs, 'diagnostics', ())
    if type(diagnostics) is list and diagnostics:
        result['diagnostics'] = copy.deepcopy(diagnostics[:8])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check-config', action='store_true')
    mode.add_argument('--execute', action='store_true')
    parser.add_argument('--approve-busy-host', action='store_true')
    parser.add_argument('--allow-host-inspection', action='store_true')
    args = parser.parse_args(argv)
    if args.execute and (sys.platform != 'linux' or getattr(os, 'geteuid', lambda: -1)() != 0
                         or not args.approve_busy_host or not args.allow_host_inspection):
        parser.error('Linux root, --approve-busy-host and --allow-host-inspection are required')
    try:
        config = read_config(args.config, secure=args.execute)
        if args.check_config:
            print('Configuration schema valid; no host operations performed. This is not acceptance.')
            return 0
        result = execute_config(config, busy_host_approved=True, allow_host_inspection=True)
        import json
        print(json.dumps(result, sort_keys=True))
        return 0 if result['status'] == 'complete' else 1
    except (OSError, ValueError, TypeError, RuntimeError):
        print('FAIL: acceptance incomplete; no activation performed', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('FAIL: acceptance interrupted; no activation performed', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
