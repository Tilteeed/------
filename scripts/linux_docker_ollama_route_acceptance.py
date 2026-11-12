#!/usr/bin/env python3
"""Real packet acceptance using a private nested dockerd, never caller Docker."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.ollama_route_linux import main as _main


def main(argv=None):
    return _main(argv, docker=True)


if __name__ == '__main__':
    raise SystemExit(main())
