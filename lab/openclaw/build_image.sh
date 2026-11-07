#!/usr/bin/env bash
# Stage 2 only. No clone/checkout/download occurs before the source guard.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  printf 'Usage: bash build_image.sh /path/to/checked-out-openclaw\n' >&2
  exit 2
fi
SOURCE_DIR=$1
EXPECTED_SHA=7c12438929e5d198616fe8f602d896e011647d39
IMAGE=openclaw-stage2:7c12438929e5
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PATCH_FILE="$SCRIPT_DIR/patches/7c12438929e5-control-ui-browser-origin.patch"
if command -v cygpath >/dev/null 2>&1; then
  PATCH_FILE=$(cygpath -m -- "$PATCH_FILE")
fi

WORKTREE_ROOT=$(git -C "$SOURCE_DIR" rev-parse --show-toplevel)
# Canonicalize both sides: Git Bash may return C:/... or /c/... paths.
CANONICAL_SOURCE_DIR=$(cd -- "$SOURCE_DIR" && pwd -P)
WORKTREE_ROOT=$(cd -- "$WORKTREE_ROOT" && pwd -P)
if [ "$CANONICAL_SOURCE_DIR" != "$WORKTREE_ROOT" ]; then
  printf 'Refusing build: source directory must be the worktree root.\n' >&2
  exit 1
fi
ACTUAL_SHA=$(git -C "$SOURCE_DIR" rev-parse HEAD)
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  printf 'Refusing build: source commit does not match the Stage 2 baseline.\n' >&2
  exit 1
fi
STATUS=$(git -C "$SOURCE_DIR" status --porcelain --untracked-files=all)
if [ -n "$STATUS" ]; then
  printf 'Refusing build: source worktree is not clean (including untracked files).\n' >&2
  exit 1
fi
if [ ! -f "$PATCH_FILE" ]; then
  printf 'Refusing build: pinned OpenClaw pairing patch is missing.\n' >&2
  exit 1
fi

# Patch an archive, never the checked-out upstream worktree.
BUILD_PARENT=${TMPDIR:-$(dirname -- "$CANONICAL_SOURCE_DIR")}
BUILD_CONTEXT=$(mktemp -d "$BUILD_PARENT/bezr-openclaw-build.XXXXXX")
cleanup_build_context() {
  if [ -n "${BUILD_CONTEXT:-}" ] && [ -d "$BUILD_CONTEXT" ]; then
    rm -rf -- "$BUILD_CONTEXT"
  fi
}
trap cleanup_build_context EXIT

if ! git -C "$SOURCE_DIR" archive "$ACTUAL_SHA" | tar -x -C "$BUILD_CONTEXT"; then
  printf 'Refusing build: could not stage the pinned OpenClaw source.\n' >&2
  exit 1
fi
if ! (
  cd -- "$BUILD_CONTEXT"
  git apply --check "$PATCH_FILE"
); then
  printf 'Refusing build: OpenClaw pairing patch does not match the pinned source.\n' >&2
  exit 1
fi
if ! (
  cd -- "$BUILD_CONTEXT"
  git apply "$PATCH_FILE"
); then
  printf 'Refusing build: could not apply the pinned OpenClaw pairing patch.\n' >&2
  exit 1
fi
IFS=' ' read -r PATCH_SHA256 _ < <(sha256sum "$PATCH_FILE")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sudo docker build \
  --build-arg "GIT_COMMIT=$ACTUAL_SHA" \
  --build-arg "OPENCLAW_BUILD_TIMESTAMP=$BUILD_TIME" \
  --label "org.openclaw.bezr.patch.sha256=$PATCH_SHA256" \
  -t "$IMAGE" "$BUILD_CONTEXT"
