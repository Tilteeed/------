"""Generate deployment-only secrets without printing or overwriting them."""
import argparse
import os
from pathlib import Path
import secrets


def create_env(path: str | Path) -> Path:
    target = Path(path)
    content = (
        "# Local deployment secrets: DO NOT COMMIT\n"
        f"WEBUI_SECRET_KEY={secrets.token_hex(32)}\n"
        "WEB_PORT=3000\n"
        "AGENT_PLATFORM_PUBLIC_ORIGIN=http://localhost:3000\n"
        "WEB_MEMORY_LIMIT=2g\n"
        "WEB_CPU_LIMIT=2.0\n"
    )
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(content)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=Path(__file__).resolve().parent.parent / ".env")
    args = parser.parse_args()
    try:
        target = create_env(args.path)
    except FileExistsError:
        parser.exit(1, "Configuration already exists; it was not overwritten.\n")
    print(f"Created deployment configuration: {target}. Secret values are not printed.")


if __name__ == "__main__":
    main()
