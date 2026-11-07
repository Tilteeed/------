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
        self.assertIn('COPY Dockerfile ./Dockerfile', backend_stage)
        self.assertIn('RUN python -m unittest discover -s supervisor/tests -v', backend_stage)
        copy_sequence = [
            'COPY control_plane/ ./control_plane/',
            'COPY scripts/ ./scripts/',
            'COPY supervisor/ ./supervisor/',
            'COPY web/agent/app.js ./web/agent/app.js',
            'COPY compose.yaml ./compose.yaml',
            'COPY Dockerfile ./Dockerfile',
            'COPY ops/ ./ops/',
            'COPY tests/ ./platform_tests/',
        ]
        copy_positions = [backend_stage.index(line) for line in copy_sequence]
        self.assertEqual(copy_positions, sorted(copy_positions))
        self.assertIn('python -c "import aiohttp; import control_plane.proxy_sidecar"', backend_stage)


if __name__ == '__main__':
    unittest.main()
