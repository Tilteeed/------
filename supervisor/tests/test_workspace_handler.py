"""Supervisor HTTP transport tests for retained-workspace downloads."""
from http.client import HTTPConnection
from http.server import HTTPServer
import json
import threading
import unittest

from supervisor.service import WorkspaceDownload, create_handler


class WorkspaceHttpHandlerTests(unittest.TestCase):
    def test_download_is_bounded_attachment_and_requires_service_bearer(self):
        class Controller:
            def me(self, _payload):
                return {}
            def action(self, _payload):
                return {}
            def replay(self, _payload):
                return {}
            def retained_workspace(self, payload):
                self.payload = payload
                return WorkspaceDownload("отчёт.bin", b"\x00payload")

        controller = Controller()
        token = "service-test-token"
        server = HTTPServer(("127.0.0.1", 0), create_handler(controller, token))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        payload = {'actor_id': 'alice', 'instance_id': 'a' * 32,
                   'action': 'download', 'path': 'report.bin'}
        connection = HTTPConnection(*server.server_address, timeout=5)
        self.addCleanup(connection.close)
        connection.request('POST', '/v1/retained/workspace', body=json.dumps(payload), headers={
            'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"\x00payload")
        self.assertEqual(response.getheader('Content-Type'), 'application/octet-stream')
        self.assertEqual(response.getheader('Cache-Control'), 'no-store')
        self.assertEqual(response.getheader('X-Content-Type-Options'), 'nosniff')
        self.assertIn("filename*=UTF-8''%D0%BE%D1%82%D1%87%D1%91%D1%82.bin",
                      response.getheader('Content-Disposition'))
        self.assertEqual(controller.payload, payload)

        unauthorized = HTTPConnection(*server.server_address, timeout=5)
        self.addCleanup(unauthorized.close)
        unauthorized.request('POST', '/v1/retained/workspace', body=json.dumps(payload), headers={
            'Authorization': 'Bearer wrong-token', 'Content-Type': 'application/json'})
        denied = unauthorized.getresponse()
        self.assertEqual(denied.status, 401)
        self.assertNotEqual(denied.read(), b"\x00payload")


if __name__ == '__main__':
    unittest.main()
