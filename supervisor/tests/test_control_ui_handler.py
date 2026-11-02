from http.client import HTTPConnection
from http.server import HTTPServer
import json
import threading
import unittest

from supervisor.service import create_handler


class ControlUiHandlerTests(unittest.TestCase):
    def test_owner_scoped_target_route_uses_service_bearer(self):
        class Controller:
            def me(self, _payload):
                return {}
            def action(self, _payload):
                return {}
            def replay(self, _payload):
                return {}
            def control_ui_target(self, payload):
                self.payload = payload
                return {'ready': False, 'target': None}

        controller = Controller()
        token = 'service-test-token'
        server = HTTPServer(('127.0.0.1', 0), create_handler(controller, token))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        payload = {'actor_id': 'alice', 'instance_id': 'a' * 32}
        host, port = str(server.server_address[0]), int(server.server_address[1])
        connection = HTTPConnection(host, port, timeout=5)
        self.addCleanup(connection.close)
        connection.request('POST', '/v1/control-ui/target', body=json.dumps(payload), headers={
            'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read()), {'ready': False, 'target': None})
        self.assertEqual(controller.payload, payload)

        denied = HTTPConnection(host, port, timeout=5)
        self.addCleanup(denied.close)
        denied.request('POST', '/v1/control-ui/target', body=json.dumps(payload), headers={
            'Authorization': 'Bearer wrong-token', 'Content-Type': 'application/json'})
        self.assertEqual(denied.getresponse().status, 401)


if __name__ == '__main__':
    unittest.main()
