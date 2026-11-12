from http.client import HTTPConnection
from http.server import HTTPServer
import json
import struct
import threading
import unittest
from unittest.mock import patch

from supervisor.service import (
    RuntimeService, ServiceError, _unix_peer_uid,
    create_admin_handler, create_handler,
)


class ControlUiMaintenanceHandlerTests(unittest.TestCase):
    def _request(self, handler_factory, path, payload, *, controller=None):
        class Controller:
            def me(self, _payload):
                return {}

            def action(self, _payload):
                return {}

            def replay(self, _payload):
                return {}

            def manage_control_ui_sidecars(self, value):
                return {'action': value['action'], 'status': 'ok'}

        app = Controller() if controller is None else controller
        server = HTTPServer(('127.0.0.1', 0), handler_factory(app, 'service-test-token'))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        connection = HTTPConnection(str(server.server_address[0]),
                                    int(server.server_address[1]), timeout=5)
        self.addCleanup(connection.close)
        connection.request('POST', path, body=json.dumps(payload), headers={
            'Authorization': 'Bearer service-test-token', 'Content-Type': 'application/json'})
        response = connection.getresponse()
        return response.status, json.loads(response.read())

    def test_admin_migration_endpoint_rejects_non_unix_transport(self):
        status, body = self._request(
            create_admin_handler, '/v1/admin/control-ui/sidecars', {'action': 'plan'})
        self.assertEqual(status, 403)
        self.assertEqual(body['code'], 'unauthorized')

    def test_web_service_handler_does_not_expose_admin_migration_endpoint(self):
        status, body = self._request(
            create_handler, '/v1/admin/control-ui/sidecars', {'action': 'plan'})
        self.assertEqual(status, 404)
        self.assertEqual(body['code'], 'not_found')

    def test_admin_handler_dispatches_after_root_peer_proof(self):
        with patch('supervisor.service._unix_peer_uid', return_value=0):
            status, body = self._request(
                create_admin_handler, '/v1/admin/control-ui/sidecars', {'action': 'plan'})
        self.assertEqual(status, 200)
        self.assertEqual(body, {'action': 'plan', 'status': 'ok'})

    def test_model_change_endpoint_is_root_admin_only_and_not_public(self):
        class OllamaController:
            ollama_config = {'default_model_id': 'qwen3.5:9b'}
            def me(self, _payload):
                return {}
            def action(self, _payload):
                return {}
            def replay(self, _payload):
                return {}
            def change_ollama_model(self, payload):
                return {'status': 'updated', 'model_id': payload['new_model_id']}
            def ollama_model_status(self):
                return {'model_id': 'qwen3.5:9b'}

        controller = OllamaController()
        selected = 'hf.co/DavidAU/Qwen3.5-9B-The-Defiant-Fable-Uncensored-Heretic-NEO-IMATRIX-MAX-MTP-GGUF:Q4_K_M'
        payload = {'expected_model_id': 'qwen3.5:9b', 'new_model_id': selected}
        with patch('supervisor.service._unix_peer_uid', return_value=0):
            status, body = self._request(
                create_admin_handler, '/v1/admin/ollama/model', {'action': 'status'}, controller=controller)
        self.assertEqual(status, 200)
        self.assertEqual(body, {'model_id': 'qwen3.5:9b'})
        with patch('supervisor.service._unix_peer_uid', return_value=0):
            status, body = self._request(
                create_admin_handler, '/v1/admin/ollama/model', payload, controller=controller)
        self.assertEqual(status, 200)
        self.assertEqual(body['model_id'], selected)

        status, body = self._request(
            create_handler, '/v1/admin/ollama/model', payload, controller=controller)
        self.assertEqual(status, 404)
        self.assertEqual(body['code'], 'not_found')

    def test_peer_uid_helper_distinguishes_root_from_nonroot(self):
        class Peer:
            def __init__(self, uid):
                self.uid = uid

            def getsockopt(self, level, option, length):
                return struct.pack('3i', 123, self.uid, 0)

        with patch('supervisor.service.socket.SO_PEERCRED', 17, create=True):
            self.assertEqual(_unix_peer_uid(Peer(0)), 0)
            self.assertEqual(_unix_peer_uid(Peer(1000)), 1000)

    def test_public_ticket_resolver_fails_closed_for_maintenance_instances(self):
        class PendingMigration:
            def in_progress_instances(self):
                return {'a' * 32}

        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.sidecar_migration = PendingMigration()

        result = service.control_ui_target({'actor_id': 'alice', 'instance_id': 'a' * 32})

        self.assertEqual(result, {'ready': False, 'target': None})

    def test_lifecycle_action_is_blocked_while_migration_is_pending(self):
        class PendingMigration:
            def status(self):
                return {'status': 'in_progress'}

        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.sidecar_migration = PendingMigration()
        request = {
            'actor_id': 'alice', 'action': 'restart', 'idempotency_key': 'restart-1',
            'settings_revision': 1, 'settings': {'name': 'Agent', 'instructions': ''},
        }

        with self.assertRaises(ServiceError) as raised:
            service.action(request)

        self.assertEqual(raised.exception.code, 'maintenance_in_progress')

    def test_reconcile_does_not_inspect_gateways_in_maintenance_journal(self):
        instance_id = 'a' * 32

        class PendingMigration:
            def in_progress_instances(self):
                return {instance_id}

        class Store:
            def all_instances(self):
                return [{'id': instance_id, 'active': 1}]

        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.sidecar_migration = PendingMigration()
        service.store = Store()
        service._inspect = lambda instance_id: (_ for _ in ()).throw(
            AssertionError('reconcile inspected a migrating instance'))

        service.reconcile()


if __name__ == '__main__':
    unittest.main()
