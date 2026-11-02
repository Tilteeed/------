"""Synthetic tests for the one-time Control UI origin handoff."""
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from control_plane.store import DraftStore


class ControlUiHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DraftStore(Path(self.temp.name) / 'platform.sqlite3')
        self.instance_id = 'a' * 32
        self.audience = f'https://{self.instance_id}.agents.example.test'

    def make_client(self, *, host=None, proxy_ready=True):
        from control_plane.access_proxy import create_handoff_router
        app = FastAPI()
        app.include_router(create_handoff_router(
            self.store, public_origin='https://bezr.example.test',
            control_ui_domain='agents.example.test', proxy_ready=proxy_ready))
        return TestClient(app, base_url=host or self.audience)

    def test_entry_get_does_not_offer_anonymous_gateway_access(self):
        client = self.make_client()
        self.addCleanup(client.close)
        response = client.get('/_bezr/enter')
        self.assertEqual(response.status_code, 405)

    def test_handoff_is_disabled_until_proxy_is_ready(self):
        ticket = self.store.issue_control_ui_ticket(
            'alice', self.instance_id, self.audience)['ticket']
        client = self.make_client(proxy_ready=False)
        self.addCleanup(client.close)
        response = client.post('/_bezr/enter', headers={'Origin': 'https://bezr.example.test'},
                               data={'ticket': ticket}, follow_redirects=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.store.consume_control_ui_ticket(ticket, audience=self.audience), {
            'owner_id': 'alice', 'instance_id': self.instance_id, 'audience': self.audience,
        })

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


class AccessProxyRequestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DraftStore(Path(self.temp.name) / 'proxy.sqlite3')
        self.instance_id = 'f' * 32
        self.origin = f'https://{self.instance_id}.agents.example.test'
        ticket = self.store.issue_control_ui_ticket('alice', self.instance_id, self.origin)['ticket']
        self.session_id = self.store.redeem_control_ui_ticket(ticket, audience=self.origin)['session_id']
        self.forwarded_headers = {
            'X-Forwarded-For': '198.51.100.7',
            'X-Forwarded-Proto': 'https',
        }

    def make_app(self, *, state='running', profile='agent_proxy_v1', ws_recheck_seconds: float = 15.0):
        import asyncio
        import aiohttp
        from control_plane.access_proxy import create_control_ui_access_proxy

        class Runtime:
            def get(self, owner_id):
                if owner_id != 'alice':
                    return {'runtime': {'state': 'not_created', 'instance_id': None}}
                return {'runtime': {'state': state, 'gateway': 'ready',
                                    'instance_id': self_instance, 'network_profile': profile}}

        class FakeWebSocket:
            protocol = 'openclaw'
            def __init__(self):
                self.messages = asyncio.Queue()
            async def send_str(self, value):
                await self.messages.put(SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=value))
            async def send_bytes(self, value):
                await self.messages.put(SimpleNamespace(type=aiohttp.WSMsgType.BINARY, data=value))
            def __aiter__(self):
                return self
            async def __anext__(self):
                message = await self.messages.get()
                if message is None:
                    raise StopAsyncIteration
                return message
            async def close(self):
                await self.messages.put(None)

        class Transport:
            def __init__(self):
                self.calls = []
                self.ws_calls = []
            async def request(self, target, method, path, headers, body):
                self.calls.append((target, method, path, headers, body))
                return 200, {'Content-Type': 'text/html'}, b'<main>agent</main>'
            @asynccontextmanager
            async def websocket(self, target, path, headers, protocols):
                self.ws_calls.append((target, path, headers, protocols))
                upstream = FakeWebSocket()
                try:
                    yield upstream
                finally:
                    await upstream.close()

        self_instance = self.instance_id
        runtime = Runtime()
        transport = Transport()
        target = {'ip': '172.31.0.2', 'port': 18790, 'proxy_token': 'T' * 43}
        app = create_control_ui_access_proxy(
            self.store, runtime, public_origin='https://bezr.example.test',
            control_ui_domain='agents.example.test', target_resolver=lambda _owner, _instance: target,
            transport=transport, proxy_ready=True,
            ws_session_recheck_seconds=ws_recheck_seconds)
        return app, transport

    def test_every_http_request_checks_session_and_current_owner_runtime_before_proxying(self):
        app, transport = self.make_app()
        client = TestClient(app, base_url=self.origin, client=('198.51.100.7', 12345))
        self.addCleanup(client.close)
        response = client.get('/assets/app.js', headers={
            **self.forwarded_headers,
            'Cookie': '__Host-bezr-control-ui=' + self.session_id,
            'Origin': self.origin,
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, b'<main>agent</main>')
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(len(transport.calls), 1)
        target, method, path, headers, body = transport.calls[0]
        self.assertEqual(target['ip'], '172.31.0.2')
        self.assertEqual((method, path, body), ('GET', '/assets/app.js', b''))
        self.assertEqual(headers['authorization'], 'Bearer ' + 'T' * 43)
        self.assertEqual(headers['x-bezr-host'], self.instance_id + '.agents.example.test')
        self.assertEqual(headers['x-bezr-client-ip'], '198.51.100.7')
        self.assertNotIn('x-forwarded-for', headers)

        denied = client.get('/assets/app.js', headers={'Cookie': '__Host-bezr-control-ui=invalid'})
        self.assertEqual(denied.status_code, 404)
        self.assertEqual(len(transport.calls), 1)

    def test_access_proxy_rejects_plain_http_origin_before_relay(self):
        app, transport = self.make_app()
        client = TestClient(app, base_url='http://' + self.instance_id + '.agents.example.test',
                            client=('198.51.100.7', 12345))
        self.addCleanup(client.close)
        response = client.get('/', headers={
            **self.forwarded_headers,
            'Cookie': '__Host-bezr-control-ui=' + self.session_id,
            'Origin': self.origin,
        })
        self.assertEqual(response.status_code, 404)
        self.assertEqual(transport.calls, [])

    def test_proxy_rejects_missing_or_untrusted_frontend_forwarded_identity(self):
        app, transport = self.make_app()
        client = TestClient(app, base_url=self.origin, client=('198.51.100.7', 12345))
        self.addCleanup(client.close)
        invalid_forwarded = (
            {},
            {'X-Forwarded-For': '198.51.100.8', 'X-Forwarded-Proto': 'https'},
            {'X-Forwarded-For': '198.51.100.7, 198.51.100.8', 'X-Forwarded-Proto': 'https'},
            {'X-Forwarded-For': '198.51.100.7', 'X-Forwarded-Proto': 'http'},
        )
        for forwarded in invalid_forwarded:
            with self.subTest(forwarded=forwarded):
                response = client.get('/', headers={
                    'Cookie': '__Host-bezr-control-ui=' + self.session_id,
                    'Origin': self.origin,
                    **forwarded,
                })
                self.assertEqual(response.status_code, 403)
        self.assertEqual(transport.calls, [])

    def test_host_dispatch_sends_agent_origin_to_proxy_and_keeps_main_origin_in_webui(self):
        from control_plane.access_proxy import ControlUiHostMiddleware
        app, transport = self.make_app()
        root = FastAPI()
        root.add_middleware(ControlUiHostMiddleware, proxy_app=app,
                            control_ui_domain='agents.example.test')
        @root.get('/')
        def main_page():
            return {'main': True}
        client = TestClient(root, base_url='https://bezr.example.test', client=('198.51.100.7', 12345))
        self.addCleanup(client.close)
        agent = client.get('/', headers={
            **self.forwarded_headers,
            'Host': self.instance_id + '.agents.example.test',
            'Cookie': '__Host-bezr-control-ui=' + self.session_id,
            'Origin': self.origin,
        })
        self.assertEqual(agent.status_code, 200, agent.text)
        self.assertEqual(agent.content, b'<main>agent</main>')
        self.assertEqual(len(transport.calls), 1)
        main = client.get('/', headers={'Host': 'bezr.example.test'})
        self.assertEqual(main.json(), {'main': True})

    def test_websocket_upgrade_checks_session_origin_and_roundtrips_messages(self):
        import aiohttp
        app, transport = self.make_app()
        client = TestClient(app, base_url=self.origin, client=('198.51.100.7', 12345))
        self.addCleanup(client.close)
        try:
            with client.websocket_connect(self.origin.replace('https://', 'wss://') + '/ws', headers={
                **self.forwarded_headers,
                'Cookie': '__Host-bezr-control-ui=' + self.session_id,
                'Origin': self.origin,
            }, subprotocols=['openclaw']) as websocket:
                self.assertEqual(websocket.accepted_subprotocol, 'openclaw')
                websocket.send_text('agent-rpc')
                self.assertEqual(websocket.receive_text(), 'agent-rpc')
        except WebSocketDisconnect as error:
            self.fail(f'Authorized proxy WebSocket closed: {error.code} {error.reason}')
        self.assertEqual(len(transport.ws_calls), 1)
        bad_origin = client.websocket_connect(self.origin.replace('https://', 'wss://') + '/ws', headers={
            'Cookie': '__Host-bezr-control-ui=' + self.session_id,
            'Origin': 'https://attacker.invalid',
        })
        with self.assertRaises(Exception):
            with bad_origin:
                pass
        self.assertEqual(len(transport.ws_calls), 1)

    def test_live_websocket_closes_promptly_after_session_revocation(self):
        app, _transport = self.make_app(ws_recheck_seconds=0.05)
        client = TestClient(app, base_url=self.origin, client=('198.51.100.7', 12345))
        self.addCleanup(client.close)
        with client.websocket_connect(self.origin.replace('https://', 'wss://') + '/ws', headers={
            **self.forwarded_headers,
            'Cookie': '__Host-bezr-control-ui=' + self.session_id,
            'Origin': self.origin,
        }) as websocket:
            self.store.revoke_control_ui_sessions('alice')
            with self.assertRaises(WebSocketDisconnect) as caught:
                websocket.receive_text()
            self.assertEqual(caught.exception.code, 4401)

    def test_proxy_fails_closed_when_gateway_is_stopped_or_wrong_profile(self):
        for state, profile in (('stopped', 'agent_proxy_v1'), ('running', 'legacy_none')):
            with self.subTest(state=state, profile=profile):
                app, transport = self.make_app(state=state, profile=profile)
                client = TestClient(app, base_url=self.origin, client=('198.51.100.7', 12345))
                self.addCleanup(client.close)
                response = client.get('/', headers={
                    **self.forwarded_headers,
                    'Cookie': '__Host-bezr-control-ui=' + self.session_id,
                    'Origin': self.origin,
                })
                self.assertEqual(response.status_code, 404)
                self.assertEqual(transport.calls, [])


if __name__ == '__main__':
    unittest.main()
