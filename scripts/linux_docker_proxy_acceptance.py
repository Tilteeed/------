#!/usr/bin/env python3
"""Opt-in independent proxy packet check in a private namespace laboratory.

Docker mode uses only a private daemon and an explicitly provided image archive.
No caller Docker/firewall mutation and no receipt write. For an in-use host use
only the separately resource-bounded GPU acceptance entrypoint.
"""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.proxy_acceptance_linux import main as private_main


def main(argv=None):
    return private_main(argv, docker=True)


if __name__ == '__main__':
    raise SystemExit(main())
