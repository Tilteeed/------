import unittest
from pathlib import Path


class ComposeProxyTrustTests(unittest.TestCase):
    def test_forwarded_allow_ips_is_parameterized_and_not_wildcarded(self):
        compose = Path(__file__).resolve().parents[1].joinpath('compose.yaml')
        text = compose.read_text(encoding='utf-8')

        self.assertIn(
            'FORWARDED_ALLOW_IPS: "${FORWARDED_ALLOW_IPS:-127.0.0.1}"', text)
        self.assertNotIn('FORWARDED_ALLOW_IPS: "*"', text)


if __name__ == '__main__':
    unittest.main()
