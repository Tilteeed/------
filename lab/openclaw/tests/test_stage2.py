"""Portable bootstrap tests and an optional real Compose-rendering check."""
import importlib.util
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('lab_init_env', HERE / 'init_env.py')
        if spec is None or spec.loader is None:
            raise RuntimeError('Cannot load Stage 2 bootstrap')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_generates_nonempty_random_token(self):
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

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions must be checked on the Linux VM')
    def test_file_permissions_are_0600_on_posix(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / '.env'
            self.module.create_env(target)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_will_never_overwrite_existing_secret(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / '.env'
            target.write_text('keep-original\n')
            with self.assertRaises(FileExistsError):
                self.module.create_env(target)
            self.assertEqual(target.read_text(), 'keep-original\n')

    @unittest.skipUnless(shutil.which('docker'), 'Docker CLI unavailable; real Compose rendering not checked')
    def test_real_compose_renders_to_safe_structure(self):
        module_spec = importlib.util.spec_from_file_location('lab_validate_compose', HERE / 'validate_compose.py')
        if module_spec is None or module_spec.loader is None:
            raise RuntimeError('Cannot load Stage 2 validation')
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        environment = dict(os.environ, OPENCLAW_LAB_IMAGE=self.module.IMAGE,
                           OPENCLAW_GATEWAY_TOKEN='unit-test-placeholder',
                           OPENCLAW_LAB_PORT='18789', OPENCLAW_LAB_MEMORY='2g',
                           OPENCLAW_LAB_CPUS='1.0', COMPOSE_PROJECT_NAME=module.PROJECT)
        # No real .env or secret is read; config parses YAML but starts no containers.
        rendered = module.render_config(HERE, env=environment, env_file=os.devnull)
        module.validate_spec(rendered)


if __name__ == '__main__':
    unittest.main()
