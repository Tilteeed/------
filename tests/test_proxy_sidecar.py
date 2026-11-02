import unittest
from unittest.mock import patch

from control_plane.proxy_sidecar import (
    SidecarConfigError,
    authorize_internal_request,
    build_gateway_headers,
    normalize_target_path,
    validate_sidecar_config,
)


class SidecarPolicyTests(unittest.TestCase):
    def test_gateway_headers_drop_client_auth_and_forwarded_identity(self):
        incoming = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer browser-token',
            'Cookie': '__Host-bezr-control-ui=browser-session',
            'X-Forwarded-User': 'attacker',
            'X-Forwarded-Host': 'evil.invalid',
            'X-Forwarded-Proto': 'http',
            'X-Bezr-Proxy-Token': 'spoofed',
        }
        origin = 'https://' + 'a' * 32 + '.agents.example.test'
        headers = build_gateway_headers(incoming, owner_id='owner-7', public_origin=origin,
                                        client_ip='198.51.100.9')
        self.assertEqual(headers['x-forwarded-user'], 'owner-7')
        self.assertEqual(headers['x-forwarded-proto'], 'https')
        self.assertEqual(headers['x-forwarded-host'], 'a' * 32 + '.agents.example.test')
        self.assertEqual(headers['x-forwarded-for'], '198.51.100.9')
        self.assertEqual(headers['origin'], origin)
        self.assertEqual(headers['accept'], 'application/json')
        self.assertEqual(headers['content-type'], 'application/json')
        for name in ('authorization', 'cookie', 'x-bezr-proxy-token'):
            self.assertNotIn(name, headers)

    def test_internal_sidecar_request_requires_secret_and_exact_host_origin(self):
        config = validate_sidecar_config({
            'owner_id': 'owner-7',
            'public_origin': 'https://' + 'b' * 32 + '.agents.example.test',
            'gateway_ip': '172.31.0.3',
            'listen_ip': '172.31.0.2',
            'proxy_token': 'T' * 43,
        })
        good = {'authorization': 'Bearer ' + 'T' * 43,
                'x-bezr-host': 'b' * 32 + '.agents.example.test',
                'x-bezr-origin': config.public_origin,
                'x-bezr-client-ip': '198.51.100.9'}
        self.assertTrue(authorize_internal_request(good, config))
        for bad in (
            {**good, 'authorization': 'Bearer wrong'},
            {**good, 'x-bezr-host': 'c' * 32 + '.agents.example.test'},
            {**good, 'x-bezr-origin': 'https://attacker.invalid'},
        ):
            self.assertFalse(authorize_internal_request(bad, config))

    def test_sidecar_config_and_target_path_fail_closed(self):
        valid = {'owner_id': 'owner-7', 'public_origin': 'https://' + 'c' * 32 + '.agents.example.test',
                 'gateway_ip': '172.31.0.3', 'listen_ip': '172.31.0.2', 'proxy_token': 'K' * 43}
        self.assertEqual(validate_sidecar_config(valid).gateway_ip, '172.31.0.3')
        for changes in ({'listen_ip': '127.0.0.1'}, {'gateway_ip': '127.0.0.1'},
                        {'public_origin': 'http://example.test'}, {'owner_id': ''},
                        {'proxy_token': 'short'}):
            with self.subTest(changes=changes), self.assertRaises(SidecarConfigError):
                validate_sidecar_config({**valid, **changes})
        self.assertEqual(normalize_target_path('/assets/app.js?x=1'), '/assets/app.js?x=1')
        for path in ('//attacker.invalid', '/a\\b', '/%00', 'https://attacker.invalid/x'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_target_path(path)


class SidecarLocalHttpWebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        try:
            import aiohttp
            from aiohttp import web
            from aiohttp.test_utils import TestClient, TestServer
        except ImportError:
            self.skipTest('aiohttp is provided by the pinned Open WebUI runtime image')
        from control_plane import proxy_sidecar
        self.aiohttp = aiohttp
        self.web = web
        self.TestClient = TestClient
        self.TestServer = TestServer
        gateway = web.Application()

        async def echo(request):
            return web.json_response({
                'owner': request.headers.get('x-forwarded-user'),
                'origin': request.headers.get('origin'),
                'host': request.headers.get('x-forwarded-host'),
                'proto': request.headers.get('x-forwarded-proto'),
                'client_ip': request.headers.get('x-forwarded-for'),
                'authorization': request.headers.get('authorization'),
                'cookie': request.headers.get('cookie'),
            })

        async def websocket(request):
            ws = web.WebSocketResponse(protocols=('openclaw',))
            await ws.prepare(request)
            async for message in ws:
                if message.type == aiohttp.WSMsgType.TEXT:
                    await ws.send_str(message.data)
            return ws

        gateway.router.add_route('*', '/{path:.*}', echo)
        gateway.router.add_route('*', '/', echo)
        gateway.router.add_get('/ws', websocket)
        self.gateway_server = TestServer(gateway, host='127.0.0.1')
        await self.gateway_server.start_server()
        self.addAsyncCleanup(self.gateway_server.close)
        self.port_patch = patch('control_plane.proxy_sidecar.GATEWAY_PORT', self.gateway_server.port)
        self.port_patch.start()
        self.addCleanup(self.port_patch.stop)
        config = proxy_sidecar.SidecarConfig(
            'owner-7', 'https://' + 'e' * 32 + '.agents.example.test',
            'e' * 32 + '.agents.example.test', '127.0.0.1', '127.0.0.1', 'P' * 43,
        )
        proxy = proxy_sidecar._create_app(config)
        self.client = TestClient(TestServer(proxy, host='127.0.0.1'))
        await self.client.start_server()
        self.addAsyncCleanup(self.client.close)
        self.internal_headers = {
            'Authorization': 'Bearer ' + 'P' * 43,
            'X-Bezr-Host': config.public_host,
            'X-Bezr-Origin': config.public_origin,
            'X-Bezr-Client-IP': '198.51.100.9',
        }
        self.origin = config.public_origin

    async def test_http_proxy_rewrites_trust_headers_and_strips_session_secrets(self):
        response = await self.client.get('/ui/index.html', headers={
            **self.internal_headers, 'Origin': self.origin,
            'Authorization': 'Bearer ' + 'P' * 43,
            'Cookie': '__Host-bezr-control-ui=should-not-reach-gateway',
        })
        self.assertEqual(response.status, 200)
        data = await response.json()
        self.assertEqual(data['owner'], 'owner-7')
        self.assertEqual(data['origin'], self.origin)
        self.assertEqual(data['host'], self.origin.split('://', 1)[1])
        self.assertEqual(data['proto'], 'https')
        self.assertEqual(data['client_ip'], '198.51.100.9')
        self.assertIsNone(data['authorization'])
        self.assertIsNone(data['cookie'])
        self.assertEqual(response.headers['cache-control'], 'no-store')

    async def test_websocket_proxy_requires_origin_and_round_trips_frames(self):
        async with self.client.ws_connect('/ws', headers={
            **self.internal_headers, 'Origin': self.origin,
        }, protocols=('openclaw',)) as ws:
            self.assertEqual(ws.protocol, 'openclaw')
            await ws.send_str('agent-rpc')
            message = await ws.receive(timeout=3)
            self.assertEqual(message.type, self.aiohttp.WSMsgType.TEXT)
            self.assertEqual(message.data, 'agent-rpc')


if __name__ == '__main__':
    unittest.main()
