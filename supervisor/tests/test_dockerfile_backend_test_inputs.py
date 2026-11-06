import unittest
from pathlib import Path


class DockerfileBackendTestInputs(unittest.TestCase):
    def test_backend_test_stage_copies_the_frontend_source_used_by_tests(self):
        dockerfile = Path(__file__).resolve().parents[2] / 'Dockerfile'
        text = dockerfile.read_text(encoding='utf-8')
        self.assertIn(' AS backend-tests\n', text)
        backend_stage = text.split(' AS backend-tests\n', 1)[1].split('\nFROM ', 1)[0]

        self.assertIn('COPY web/agent/app.js ./web/agent/app.js', backend_stage)
        self.assertIn('COPY compose.yaml ./compose.yaml', backend_stage)


if __name__ == '__main__':
    unittest.main()
