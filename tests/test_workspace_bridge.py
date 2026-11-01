"""Private control-plane bridge checks for retained-workspace responses."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from control_plane.runtime import RuntimeUnavailable, SupervisorClient


class WorkspaceBridgeTests(unittest.TestCase):
    def test_json_methods_keep_owner_target_and_bounded_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = SupervisorClient("unused.sock", Path(tmp) / "token")
            calls = []
            def request(path, payload, *, response_kind='runtime', response_limit=65536):
                calls.append((path, payload, response_kind))
                if payload['action'] == 'list':
                    return {'directory': 'notes', 'entries': [{'name': 'note.md', 'kind': 'file', 'size': 5}],
                            'next_offset': None}
                return {'text': 'hello'}
            client._request = request
            listing = client.workspace_list('alice', 'a' * 32, 'notes', 0)
            preview = client.workspace_preview('alice', 'a' * 32, 'notes/note.md')
            self.assertEqual(listing['entries'][0]['name'], 'note.md')
            self.assertEqual(preview, {'text': 'hello'})
            self.assertEqual(calls[0][0], '/v1/retained/workspace')
            self.assertEqual(calls[0][1], {'actor_id': 'alice', 'instance_id': 'a' * 32,
                                            'action': 'list', 'directory': 'notes', 'offset': 0})
            self.assertTrue(all(call[2] == 'json' for call in calls))

            def oversized_or_secret_response(*_args, **_kwargs):
                return {'directory': 'notes', 'entries': [{'name': '../secret', 'kind': 'file', 'size': 1}],
                        'next_offset': None}
            client._request = oversized_or_secret_response
            with self.assertRaises(RuntimeUnavailable):
                client.workspace_list('alice', 'a' * 32, 'notes', 0)

    def test_preview_accepts_text_larger_than_default_json_response_limit(self):
        class Response:
            status = 200
            def __init__(self, content):
                self.content = content
            def read(self, limit):
                return self.content[:limit]
        class Connection:
            def __init__(self, response):
                self.response = response
            def request(self, *_args, **_kwargs):
                pass
            def getresponse(self):
                return self.response
            def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "service.token"
            token_file.write_text('A' * 32, encoding='ascii')
            client = SupervisorClient('unused.sock', token_file)
            text = 'Привет мир! ' * 7000
            encoded = json.dumps({'text': text}, ensure_ascii=True, separators=(',', ':')).encode('ascii')
            self.assertGreater(len(text.encode('utf-8')), 65536)
            self.assertGreater(len(encoded), 65536)
            with patch('control_plane.runtime.UnixConnection', return_value=Connection(Response(encoded))):
                self.assertEqual(client.workspace_preview('alice', 'a' * 32, 'large.txt'), {'text': text})
            too_large_text = 'Привет мир! ' * 14000
            oversized_preview = json.dumps({'text': too_large_text}, ensure_ascii=True,
                                           separators=(',', ':')).encode('ascii')
            self.assertLess(len(oversized_preview), 6 * 256 * 1024 + 64)
            with patch('control_plane.runtime.UnixConnection', return_value=Connection(Response(oversized_preview))):
                with self.assertRaises(RuntimeUnavailable):
                    client.workspace_preview('alice', 'a' * 32, 'too-large.txt')
            with patch('control_plane.runtime.UnixConnection', return_value=Connection(Response(encoded))):
                with self.assertRaises(RuntimeUnavailable):
                    client._request('/v1/me', {}, response_kind='json')

    def test_download_uses_service_bearer_and_requires_safe_binary_headers(self):
        class Response:
            status = 200
            def __init__(self, content, headers):
                self.content = content
                self.headers = headers
            def read(self, limit):
                return self.content[:limit]
            def getheader(self, name, default=None):
                return self.headers.get(name, default)

        class Connection:
            def __init__(self, response):
                self.response = response
                self.request_args = ((), {})
            def request(self, *args, **kwargs):
                self.request_args = (args, kwargs)
            def getresponse(self):
                return self.response
            def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "service.token"
            token_file.write_text('A' * 32, encoding='ascii')
            client = SupervisorClient('unused.sock', token_file)
            response = Response(b'\x00data', {
                'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store',
                'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'attachment; filename=download',
            })
            connection = Connection(response)
            with patch('control_plane.runtime.UnixConnection', return_value=connection):
                content = client.workspace_download('alice', 'b' * 32, 'notes/report.bin')
            self.assertEqual(content, b'\x00data')
            args, kwargs = connection.request_args
            self.assertEqual(args[:2], ('POST', '/v1/retained/workspace'))
            self.assertEqual(kwargs['headers']['Authorization'], 'Bearer ' + 'A' * 32)
            self.assertEqual(json.loads(kwargs['body']), {
                'actor_id': 'alice', 'instance_id': 'b' * 32,
                'action': 'download', 'path': 'notes/report.bin',
            })

            bad = Connection(Response(b'file', {'Content-Type': 'text/html'}))
            with patch('control_plane.runtime.UnixConnection', return_value=bad):
                with self.assertRaises(RuntimeUnavailable):
                    client.workspace_download('alice', 'b' * 32, 'notes/report.bin')


if __name__ == '__main__':
    unittest.main()
