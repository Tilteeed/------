"""Run the actual Bash guard with explicit Git/Docker function doubles, never a build."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SHA = '7c12438929e5d198616fe8f602d896e011647d39'
BASH = shutil.which('bash')

_PATCH_SOURCE_FIXTURE = '''import {
  updatePairedDeviceMetadata,
} from "../../../infra/device-pairing.js";
import { roleScopesAllow } from "../../../shared/operator-scope-compat.js";
import { isBrowserCopilotClient } from "../../../utils/message-channel.js";
import { pruneSupersededSilentPairingsAfterApproval } from "../../device-pairing-prune.js";
import { retireDeviceTokenClients } from "../../device-token-client-lifecycle.js";
  const browserCopilotOrigin = isBrowserCopilotClient(connectParams.client)
    ? normalizeChromeExtensionOrigin(requestOrigin)
    : undefined;
  if (device && devicePublicKey) {
    const formatAuditList = (items: string[] | undefined): string =>
      normalizeSortedUniqueTrimmedStringList(items).join(",") || "<none>";
    const clientPairingMetadata = {
      displayName: connectParams.client.displayName,
      platform: connectParams.client.platform,
      deviceFamily: connectParams.client.deviceFamily,
      clientId: connectParams.client.id,
      clientMode: connectParams.client.mode,
      ...(browserCopilotOrigin ? { browserOrigin: browserCopilotOrigin } : {}),
      role,
      scopes,
      remoteIp: reportedClientIp,
    };
  }
'''
_PATCH_TEST_FIXTURE = '''      testTailscaleWhois.value = null;
    }
  });
});
'''


def _write_origin_patch_fixture(source):
    pairing_source = source / 'src/gateway/server/ws-connection/connect-device-pairing.ts'
    pairing_test = source / 'src/gateway/server/ws-connection/connect-device-pairing.test.ts'
    pairing_source.parent.mkdir(parents=True, exist_ok=True)
    pairing_source.write_text(_PATCH_SOURCE_FIXTURE, encoding='utf-8', newline='\n')
    pairing_test.write_text(_PATCH_TEST_FIXTURE, encoding='utf-8', newline='\n')
    return pairing_source, pairing_test


@unittest.skipUnless(BASH, 'Bash is not available')
class BuildGuardTests(unittest.TestCase):
    def run_guard(self, sha=SHA, dirty='', git_failure=False, subdirectory=False,
                  posix_toplevel=False, patch_mismatch=False):
        if BASH is None:
            self.skipTest('Bash is not available')
        with tempfile.TemporaryDirectory(prefix='stage2-build-guard-') as folder:
            root = Path(folder)
            source = root / 'subdirectory' if subdirectory else root
            source.mkdir(exist_ok=True)
            pairing_source, _ = _write_origin_patch_fixture(source)
            if patch_mismatch:
                broken = _PATCH_SOURCE_FIXTURE.replace(
                    'normalizeChromeExtensionOrigin(requestOrigin)',
                    'normalizeChromeExtensionOrigin("untrusted")',
                )
                pairing_source.write_text(broken, encoding='utf-8', newline='\n')
            startup = root / 'functions.sh'
            startup.write_text('''git() {
  if [ "$1" = apply ] || [ "$3" = apply ]; then command git "$@"; return $?; fi
  if [ "$3" = archive ]; then tar -C "$REVIEW_TOPLEVEL" --exclude='./.git' -cf - .; return $?; fi
  if [ "$REVIEW_GIT_FAILURE" = 1 ]; then return 9; fi
  case "$3" in
    rev-parse)
      case "$4" in
        HEAD) printf '%s\\n' "$REVIEW_SHA" ;;
        --show-toplevel)
          if [ "$REVIEW_POSIX_TOPLEVEL" = 1 ]; then
            (cd -- "$REVIEW_TOPLEVEL" && pwd -P)
          else
            printf '%s\\n' "$REVIEW_TOPLEVEL"
          fi ;;
        *) return 8 ;;
      esac ;;
    status) printf '%s' "$REVIEW_DIRTY" ;;
    *) return 8 ;;
  esac
}
docker() { printf '%s\\n' "$*" >> "$REVIEW_DOCKER_LOG"; }
sudo() { "$@"; }
''', encoding='utf-8', newline='\n')
            log = root / 'docker-arguments.txt'
            env = dict(os.environ, BASH_ENV=startup.as_posix(), REVIEW_SHA=sha,
                       REVIEW_DIRTY=dirty, REVIEW_GIT_FAILURE=str(int(git_failure)),
                       REVIEW_DOCKER_LOG=log.as_posix(), REVIEW_TOPLEVEL=root.as_posix(),
                       REVIEW_POSIX_TOPLEVEL=str(int(posix_toplevel)))
            result = subprocess.run([BASH, (HERE / 'build_image.sh').as_posix(), source.as_posix()],
                                    env=env, capture_output=True, text=True, encoding='utf-8', timeout=20)
            arguments = log.read_text(encoding='utf-8') if log.exists() else ''
            return result, arguments

    def test_locked_patch_digest_matches_the_checked_in_patch(self):
        project_root = HERE.parent.parent
        patch_path = HERE / 'patches/7c12438929e5-control-ui-browser-origin.patch'
        lock = json.loads((project_root / 'upstream.lock.json').read_text(encoding='utf-8'))
        patch = next(item for item in lock['openclaw_theory_baseline']['patches']
                     if item['id'] == 'control-ui-browser-origin-v1')
        self.assertEqual(patch['file'], patch_path.relative_to(project_root).as_posix())
        self.assertEqual(patch['sha256'], hashlib.sha256(patch_path.read_bytes()).hexdigest())

    def test_wrong_commit_never_reaches_docker(self):
        result, arguments = self.run_guard(sha='wrong-commit')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('commit', result.stderr.lower())
        self.assertEqual(arguments, '')

    def test_dirty_tree_never_reaches_docker(self):
        result, arguments = self.run_guard(dirty=' M Dockerfile\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(arguments, '')

    def test_unapplicable_pairing_patch_never_reaches_docker(self):
        result, arguments = self.run_guard(patch_mismatch=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('patch does not match', result.stderr.lower())
        self.assertEqual(arguments, '')

    def test_git_error_never_reaches_docker(self):
        result, arguments = self.run_guard(git_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(arguments, '')

    def test_clean_pinned_source_reaches_build_with_expected_metadata(self):
        result, arguments = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('build --build-arg GIT_COMMIT=' + SHA, arguments)
        self.assertIn('OPENCLAW_BUILD_TIMESTAMP=', arguments)
        self.assertIn('-t openclaw-stage2:7c12438929e5', arguments)

    def test_subdirectory_never_reaches_docker(self):
        result, arguments = self.run_guard(subdirectory=True)
        self.assertEqual(arguments, '', 'Subdirectory context must never reach Docker')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('worktree root', result.stderr.lower())

    def test_accepts_equivalent_native_source_and_posix_toplevel(self):
        result, arguments = self.run_guard(posix_toplevel=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('build --build-arg GIT_COMMIT=' + SHA, arguments)

    def test_build_applies_control_ui_origin_patch_in_temporary_context(self):
        if BASH is None:
            self.skipTest('Bash is not available')
        with tempfile.TemporaryDirectory(prefix='stage2-origin-patch-') as folder:
            root = Path(folder)
            source = root / 'openclaw'
            source.mkdir(parents=True)
            pairing_source, pairing_test = _write_origin_patch_fixture(source)
            original_source = _PATCH_SOURCE_FIXTURE
            original_test = _PATCH_TEST_FIXTURE
            startup = root / 'functions.sh'
            startup.write_text('''git() {
  if [ "$1" = apply ] || [ "$3" = apply ]; then command git "$@"; return $?; fi
  if [ "$3" = archive ]; then tar -C "$REVIEW_TOPLEVEL" --exclude='./.git' -cf - .; return $?; fi
  if [ "$REVIEW_GIT_FAILURE" = 1 ]; then return 9; fi
  case "$3" in
    rev-parse)
      case "$4" in
        HEAD) printf '%s\\n' "$REVIEW_SHA" ;;
        --show-toplevel) printf '%s\\n' "$REVIEW_TOPLEVEL" ;;
        *) return 8 ;;
      esac ;;
    status) printf '%s' "$REVIEW_DIRTY" ;;
    *) return 8 ;;
  esac
}
docker() {
  printf '%s\\n' "$*" >> "$REVIEW_DOCKER_LOG"
  context="${@: -1}"
  cp "$context/src/gateway/server/ws-connection/connect-device-pairing.ts" "$REVIEW_SOURCE_SNAPSHOT"
  cp "$context/src/gateway/server/ws-connection/connect-device-pairing.test.ts" "$REVIEW_TEST_SNAPSHOT"
}
sudo() { "$@"; }
''', encoding='utf-8', newline='\n')
            log = root / 'docker-arguments.txt'
            source_snapshot = root / 'patched-connect-device-pairing.ts'
            test_snapshot = root / 'patched-connect-device-pairing.test.ts'
            env = dict(os.environ, BASH_ENV=startup.as_posix(), REVIEW_SHA=SHA,
                       REVIEW_DIRTY='', REVIEW_GIT_FAILURE='0', REVIEW_DOCKER_LOG=log.as_posix(),
                       REVIEW_TOPLEVEL=source.as_posix(), REVIEW_SOURCE_SNAPSHOT=source_snapshot.as_posix(),
                       REVIEW_TEST_SNAPSHOT=test_snapshot.as_posix())
            result = subprocess.run([BASH, (HERE / 'build_image.sh').as_posix(), source.as_posix()],
                                    env=env, capture_output=True, text=True, encoding='utf-8', timeout=30)
            arguments = log.read_text(encoding='utf-8') if log.exists() else ''
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotEqual(arguments.split()[-1], source.as_posix())
            self.assertIn('--label org.openclaw.bezr.patch.sha256=', arguments)
            self.assertIn('context.browserOrigin?.origin', source_snapshot.read_text(encoding='utf-8'))
            self.assertIn('browserOrigin', test_snapshot.read_text(encoding='utf-8'))
            self.assertEqual(pairing_source.read_text(encoding='utf-8'), original_source)
            self.assertEqual(pairing_test.read_text(encoding='utf-8'), original_test)


if __name__ == '__main__':
    unittest.main()
