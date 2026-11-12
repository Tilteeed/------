#!/usr/bin/env python3
"""Explicitly add Supervisor recovery and administrator-model state to the runtime DB.

Stop the Supervisor first, protect the new backup path, and pass --apply only
when the database contains no unreviewed schema/data changes. Existing
`running`/`paused`/`restarting` states migrate to desired=running; states already
recorded as stopped remain stopped because earlier intent cannot be inferred.
The new administrator-selection table is seeded from runtime.json only when no
operator selection has yet been recorded; later config defaults never overwrite it.
"""
import argparse
import json
from pathlib import Path
import sys

# Permit execution from the project root without installing this project.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from supervisor.runtime_store import RuntimeStore, StoreError


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, help='Existing dedicated Supervisor SQLite database')
    parser.add_argument('--backup', required=True, help='New protected backup path; must not already exist')
    parser.add_argument('--apply', action='store_true',
                        help='confirm the explicit SQLite backup and additive desired-state migration')
    args = parser.parse_args(argv)
    if not args.apply:
        parser.error('no changes made; stop Supervisor, protect the backup destination, then explicitly pass --apply')
    try:
        result = RuntimeStore.migrate_desired_state_schema(args.database, args.backup)
    except StoreError as error:
        parser.exit(2, 'Migration refused: ' + error.code + '\n')
    print(json.dumps({'status': 'migrated', **result}, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
