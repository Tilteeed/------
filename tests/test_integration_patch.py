import hashlib
import unittest
from scripts import install_integration


class IntegrationPatchTests(unittest.TestCase):
    def test_patch_is_idempotent_and_rejects_changed_upstream(self):
        self.assertTrue(hasattr(install_integration, "patch_main"), "Upstream patcher is missing")
        source = "# upstream\napp.include_router(auths.router, prefix='/api/v1/auths', tags=['auths'])\n# rest\n"
        expected = hashlib.sha256(source.encode()).hexdigest()
        patched = install_integration.patch_main(source, expected_sha256=expected)
        self.assertIn("app.include_router(agent_platform_router)", patched)
        self.assertEqual(install_integration.patch_main(patched, expected_sha256=expected), patched)
        with self.assertRaises(ValueError):
            install_integration.patch_main(source + "# changed\n", expected_sha256=expected)
        with self.assertRaises(ValueError):
            install_integration.patch_main(patched + "# changed\n", expected_sha256=expected)


if __name__ == "__main__":
    unittest.main()
