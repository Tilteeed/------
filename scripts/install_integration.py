"""Insert the management router into one fixed upstream version.

Run during Docker build, never against an arbitrary moving upstream branch.
"""
import argparse
import hashlib
from pathlib import Path

UPSTREAM_MAIN_SHA256 = "c40fa80418d08771783c0158b65481793cc31fe8c92220027a669bdf5cf1b428"
ANCHOR = "app.include_router(auths.router, prefix='/api/v1/auths', tags=['auths'])"
BLOCK = (
    "\n# BEGIN AGENT PLATFORM INTEGRATION\n"
    "from control_plane.openwebui import router as agent_platform_router\n"
    "app.include_router(agent_platform_router)\n"
    "# END AGENT PLATFORM INTEGRATION\n"
)


def patch_main(source: str, *, expected_sha256: str = UPSTREAM_MAIN_SHA256) -> str:
    if source.count(BLOCK) > 1:
        raise ValueError("Duplicate integration blocks")
    original = source.replace(BLOCK, "")
    actual = hashlib.sha256(original.encode("utf-8")).hexdigest()
    if actual != expected_sha256:
        raise ValueError("Open WebUI main.py differs from the reviewed version; refusing to patch")
    if original.count(ANCHOR) != 1:
        raise ValueError("Expected a single upstream integration anchor")
    if BLOCK in source:
        return source
    return original.replace(ANCHOR, ANCHOR + BLOCK, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("main_file", type=Path)
    args = parser.parse_args()
    source = args.main_file.read_bytes().decode("utf-8")
    patched = patch_main(source)
    compile(patched, str(args.main_file), "exec")
    if patched != source:
        temporary = args.main_file.with_name(args.main_file.name + ".agent-platform.tmp")
        try:
            temporary.write_bytes(patched.encode("utf-8"))
            temporary.chmod(args.main_file.stat().st_mode)
            temporary.replace(args.main_file)
        finally:
            temporary.unlink(missing_ok=True)
    print("Reviewed Open WebUI integration applied")


if __name__ == "__main__":
    main()
