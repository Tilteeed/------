"""Create a local lab-only environment file without clobbering existing secrets.

No third-party dependencies and no token output. Run once on the Debian VM.
"""
from pathlib import Path
import argparse
import os
import secrets

IMAGE = 'openclaw-stage2:7c12438929e5'


def create_env(path: str | Path) -> Path:
    """Create a restrictive .env atomically; fail if it already exists."""
    destination = Path(path)
    token = secrets.token_hex(32)
    data = (
        '# Local Stage 2 experiment. Do not commit or share.\n'
        f'OPENCLAW_LAB_IMAGE={IMAGE}\n'
        f'OPENCLAW_GATEWAY_TOKEN={token}\n'
        'OPENCLAW_LAB_PORT=18789\n'
        'OPENCLAW_LAB_MEMORY=2g\n'
        'OPENCLAW_LAB_CPUS=1.0\n'
    )
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(data)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', type=Path, default=Path(__file__).resolve().parent / '.env')
    options = parser.parse_args()
    try:
        target = create_env(options.path)
    except FileExistsError:
        parser.exit(1, 'Local Stage 2 .env already exists; no changes made.\n')
    print(f'Created {target} with mode 0600; secrets were not printed.')


if __name__ == '__main__':
    main()
