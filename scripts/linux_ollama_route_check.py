#!/usr/bin/env python3
"""Real Ollama packet check in disposable Linux namespaces (never caller netns)."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.ollama_route_linux import main as _main


def main(argv=None):
    return _main(argv, docker=False)


if __name__ == '__main__':
    raise SystemExit(main())
