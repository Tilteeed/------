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
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sudo docker build \
  --build-arg "GIT_COMMIT=$ACTUAL_SHA" \
  --build-arg "OPENCLAW_BUILD_TIMESTAMP=$BUILD_TIME" \
  -t "$IMAGE" "$SOURCE_DIR"
