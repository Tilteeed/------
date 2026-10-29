import tempfile
import unittest
from pathlib import Path
from scripts import init_env


class EnvironmentSetupTests(unittest.TestCase):
    def test_generated_secret_is_random_and_existing_configuration_is_preserved(self):
        self.assertTrue(hasattr(init_env, "create_env"), "Environment generator is missing")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = init_env.create_env(root / "one.env")
            second = init_env.create_env(root / "two.env")
            content = first.read_text(encoding="utf-8")
            self.assertIn("WEBUI_SECRET_KEY=", content)
            key = content.split("WEBUI_SECRET_KEY=", 1)[1].splitlines()[0]
            self.assertGreaterEqual(len(key), 64)
            self.assertNotEqual(first.read_bytes(), second.read_bytes())
            with self.assertRaises(FileExistsError):
                init_env.create_env(first)
            self.assertEqual(first.read_text(encoding="utf-8"), content)


if __name__ == "__main__":
    unittest.main()
