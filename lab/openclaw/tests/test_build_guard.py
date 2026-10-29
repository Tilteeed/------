"""Run the actual Bash guard with explicit Git/Docker function doubles, never a build."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SHA = '7c12438929e5d198616fe8f602d896e011647d39'
BASH = shutil.which('bash')


@unittest.skipUnless(BASH, 'Bash is not available')
class BuildGuardTests(unittest.TestCase):
    def run_guard(self, sha=SHA, dirty='', git_failure=False, subdirectory=False,
                  posix_toplevel=False):
        if BASH is None:
            self.skipTest('Bash is not available')
        with tempfile.TemporaryDirectory(prefix='stage2-build-guard-') as folder:
            root = Path(folder)
            source = root / 'subdirectory' if subdirectory else root
            source.mkdir(exist_ok=True)
            startup = root / 'functions.sh'
            startup.write_text('''git() {
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

    def test_wrong_commit_never_reaches_docker(self):
        result, arguments = self.run_guard(sha='wrong-commit')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('commit', result.stderr.lower())
        self.assertEqual(arguments, '')

    def test_dirty_tree_never_reaches_docker(self):
        result, arguments = self.run_guard(dirty=' M Dockerfile\n')
        self.assertNotEqual(result.returncode, 0)
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


if __name__ == '__main__':
    unittest.main()
