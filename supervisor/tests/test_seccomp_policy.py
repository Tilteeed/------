"""Regression checks for the bundled default-deny seccomp profile."""
import json
from pathlib import Path
import unittest


class SeccompPolicyTests(unittest.TestCase):
    def test_tiocspgrp_is_allowed_without_broadening_ioctl(self):
        policy_path = Path(__file__).resolve().parents[1] / 'seccomp.json'
        with policy_path.open('r', encoding='utf-8') as source:
            policy = json.load(source)

        self.assertEqual(policy.get('defaultAction'), 'SCMP_ACT_ERRNO')
        ioctl_rules = [rule for rule in policy['syscalls'] if 'ioctl' in rule.get('names', [])]
        self.assertTrue(ioctl_rules)
        request_codes = set()
        for rule in ioctl_rules:
            self.assertEqual(rule.get('action'), 'SCMP_ACT_ALLOW')
            self.assertEqual(rule.get('names'), ['ioctl'])
            args = rule.get('args')
            self.assertEqual(len(args), 1)
            self.assertEqual(args[0].get('index'), 1)
            self.assertEqual(args[0].get('op'), 'SCMP_CMP_EQ')
            request_codes.add(args[0].get('value'))

        self.assertIn(21520, request_codes, 'ioctl(TIOCSPGRP) must be allowed for tini')
        self.assertEqual(len(request_codes), len(ioctl_rules), 'Do not add duplicate or broad ioctl rules')


if __name__ == '__main__':
    unittest.main()
