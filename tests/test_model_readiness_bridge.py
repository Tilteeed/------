import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from control_plane.runtime import SupervisorClient


class ReadinessBridgeTests(unittest.TestCase):
    def test_model_status_is_allowlisted_and_chat_stays_false(self):
        class Connection:
            def request(self, *args, **kwargs): pass
            def getresponse(self):
                class Response:
                    status = 200
                    def read(self, limit):
                        return json.dumps({'runtime': {'model': value}, 'capabilities': {'chat': False}}).encode()
                return Response()
            def close(self): pass
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / 'token'
            token.write_text('x' * 32)
            client = SupervisorClient('unused', token)
            with patch('control_plane.runtime.UnixConnection', return_value=Connection()):
                for value, expected in [('model_present', 'model_present'), ('secret-upstream-error', 'unavailable')]:
                    result = client.get('alice')
                    self.assertEqual(result['runtime']['model'], expected)
                    self.assertFalse(result['capabilities']['chat'])
