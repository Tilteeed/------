import unittest

from scripts.manage_control_ui_sidecars import build_payload


class ControlUiSidecarMigrationCliTests(unittest.TestCase):
    def test_payload_never_accepts_image_or_instance_identity(self):
        digest = 'a' * 64
        self.assertEqual(build_payload('plan'), {'action': 'plan'})
        self.assertEqual(build_payload('status'), {'action': 'status'})
        self.assertEqual(build_payload('resume'), {'action': 'resume'})
        self.assertEqual(build_payload('apply', digest), {
            'action': 'apply', 'plan_sha256': digest})
        with self.assertRaises(ValueError):
            build_payload('apply')
        with self.assertRaises(ValueError):
            build_payload('apply', 'not-a-digest')
        with self.assertRaises(ValueError):
            build_payload('plan', digest)


if __name__ == '__main__':
    unittest.main()
