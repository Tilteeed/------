"""Stage 2 smoke-contract tests; no Docker daemon or installed dependencies required."""
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('lab_init_env', HERE / 'init_env.py')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_generates_nonempty_random_token_and_restricted_file(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / 'one.env', Path(d) / 'two.env'
            self.module.create_env(a)
            self.module.create_env(b)
            content_a, content_b = a.read_text(), b.read_text()
            self.assertIn('OPENCLAW_GATEWAY_TOKEN=', content_a)
            t1 = next(line.split('=', 1)[1] for line in content_a.splitlines() if line.startswith('OPENCLAW_GATEWAY_TOKEN='))
            t2 = next(line.split('=', 1)[1] for line in content_b.splitlines() if line.startswith('OPENCLAW_GATEWAY_TOKEN='))
            self.assertEqual(len(t1), 64)
            self.assertNotEqual(t1, t2)
            self.assertEqual(stat.S_IMODE(a.stat().st_mode), 0o600)

    def test_will_never_overwrite_existing_secret(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / '.env'
            target.write_text('keep-original\n')
            with self.assertRaises(FileExistsError):
                self.module.create_env(target)
            self.assertEqual(target.read_text(), 'keep-original\n')

    def test_compose_spec_is_separate_and_local_only(self):
        spec = (HERE / 'compose.yaml').read_text()
        self.assertIn('127.0.0.1:${OPENCLAW_LAB_PORT:-18789}:18789', spec)
        self.assertNotIn('/var/run/docker.sock', spec)
        self.assertNotIn('privileged: true', spec)
        self.assertIn('no-new-privileges:true', spec)
        for volume in ('state:', 'workspace:', 'auth_secrets:'):
            self.assertIn(volume, spec)
        self.assertIn('${OPENCLAW_LAB_IMAGE:?', spec)


if __name__ == '__main__':
    unittest.main()
