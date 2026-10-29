"""Run with: python -m unittest discover -s tests -v."""
import unittest

from control_plane import policy


class CreationPolicyTests(unittest.TestCase):
    def test_browser_cannot_supply_container_image(self):
        self.assertTrue(
            hasattr(policy, "validate_agent_input"),
            "Agent input policy is not implemented yet",
        )
        with self.assertRaises(ValueError):
            policy.validate_agent_input({"name": "Помощник", "image": "untrusted/image"})

    def test_valid_input_returns_immutable_normalized_settings(self):
        settings = policy.validate_agent_input({"name": "  Помощник  ", "instructions": "По-русски"})
        self.assertFalse(isinstance(settings, dict), "Raw request dictionaries must not escape validation")
        self.assertEqual(settings.name, "Помощник")
        self.assertEqual(settings.instructions, "По-русски")
        with self.assertRaises((AttributeError, TypeError)):
            settings.name = "Changed"

    def test_invalid_settings_are_rejected_as_validation_errors(self):
        bad_inputs = [
            None, [], "name", {}, {"name": None}, {"name": True},
            {"name": "   "}, {"name": "x" * 81}, {"name": "bad\nname"},
            {"name": "Agent", "instructions": []},
            {"name": "Agent", "instructions": "x" * 8001},
            {"name": "Agent", "instructions": "bad\x00text"},
            {"name": "Agent", "owner_id": "someone-else"},
            {"name": "Agent", "privileged": True},
            {"name": "Agent", "mounts": ["/"]},
            {"name": "Agent", "gateway_url": "http://internal"},
            {"name": "Agent", "tools": {"deny": []}},
        ]
        for payload in bad_inputs:
            with self.subTest(payload=repr(payload)[:100]):
                with self.assertRaises(ValueError):
                    policy.validate_agent_input(payload)


class OwnershipPolicyTests(unittest.TestCase):
    def test_only_verified_owner_may_access_instance(self):
        self.assertTrue(hasattr(policy, "require_owner"), "Ownership policy is missing")
        policy.require_owner("user-a", "user-a")
        denied = [
            ("user-a", "user-b"), (None, "user-a"), ("", "user-a"),
            (None, None), ("", ""), (True, True), ("user-a", None),
            (" ", " "), ("user-a ", "user-a "),
        ]
        for actor, owner in denied:
            with self.subTest(actor=actor, owner=owner):
                with self.assertRaises(PermissionError):
                    policy.require_owner(actor, owner)


if __name__ == "__main__":
    unittest.main()
