"""Synthetic tests for the one-time Control UI origin handoff."""
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from control_plane.store import DraftStore


class ControlUiHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DraftStore(Path(self.temp.name) / 'platform.sqlite3')
        self.instance_id = 'a' * 32
        self.audience = f'https://{self.instance_id}.agents.example.test'

    def make_client(self, *, host=None):
        from control_plane.access_proxy import create_handoff_router
        app = FastAPI()
        app.include_router(create_handoff_router(
            self.store, public_origin='https://bezr.example.test',
            control_ui_domain='agents.example.test'))
        return TestClient(app, base_url=host or self.audience)

    def test_entry_get_does_not_offer_anonymous_gateway_access(self):
        client = self.make_client()
        self.addCleanup(client.close)
        response = client.get('/_bezr/enter')
        self.assertEqual(response.status_code, 405)

    def test_ticket_exchange_sets_host_only_secure_cookie_and_redirects_cleanly(self):
        ticket = self.store.issue_control_ui_ticket(
            'alice', self.instance_id, self.audience)['ticket']
        client = self.make_client()
        self.addCleanup(client.close)
        response = client.post('/_bezr/enter', headers={'Origin': 'https://bezr.example.test'},
                               data={'ticket': ticket}, follow_redirects=False)
        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers['location'], '/')
        self.assertEqual(response.headers['cache-control'], 'no-store')
        cookie = response.headers['set-cookie']
        self.assertIn('__Host-bezr-control-ui=', cookie)
        self.assertIn('HttpOnly', cookie)
        self.assertIn('Secure', cookie)
        self.assertIn('samesite=lax', cookie.lower())
        self.assertIn('Path=/', cookie)
        self.assertNotIn('Domain=', cookie)
        session_id = client.cookies.get('__Host-bezr-control-ui')
        self.assertTrue(session_id)
        session = self.store.validate_control_ui_session(session_id, audience=self.audience)
        self.assertIsNotNone(session)
        assert session is not None
        self.assertEqual(session['owner_id'], 'alice')
        replay = client.post('/_bezr/enter', headers={'Origin': 'https://bezr.example.test'},
                             data={'ticket': ticket}, follow_redirects=False)
        self.assertEqual(replay.status_code, 404)

    def test_entry_rejects_wrong_origin_host_and_body(self):
        ticket = self.store.issue_control_ui_ticket(
            'alice', self.instance_id, self.audience)['ticket']
        client = self.make_client()
        self.addCleanup(client.close)
        wrong_origin = client.post('/_bezr/enter', headers={'Origin': 'https://attacker.invalid'},
                                   data={'ticket': ticket})
        self.assertEqual(wrong_origin.status_code, 403)
        self.assertEqual(wrong_origin.headers['cache-control'], 'no-store')
        extra = client.post('/_bezr/enter', headers={'Origin': 'https://bezr.example.test'},
                            data={'ticket': ticket, 'instance_id': 'b' * 32})
        self.assertEqual(extra.status_code, 400)
        other = self.make_client(host='https://' + 'b' * 32 + '.agents.example.test')
        self.addCleanup(other.close)
        self.assertEqual(other.get('/_bezr/enter').status_code, 405)
        self.assertEqual(other.post('/_bezr/enter', headers={'Origin': 'https://bezr.example.test'},
                                    data={'ticket': ticket}).status_code, 404)


if __name__ == '__main__':
    unittest.main()
