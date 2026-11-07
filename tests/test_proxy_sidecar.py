import unittest
from unittest.mock import patch
import io
import os
import sys
from contextlib import ExitStack
from urllib.error import HTTPError

from control_plane.proxy_sidecar import (
    SidecarConfigError,
    authorize_internal_request,
    build_gateway_headers,
    normalize_target_path,
    validate_sidecar_config,
)


class SidecarPolicyTests(unittest.TestCase):
    def test_environment_config_reads_proxy_secret_from_private_file(self):
        from types import SimpleNamespace
        from control_plane import proxy_sidecar
        token = 'S' * 43
        env = {
            'BEZR_SIDECAR_OWNER_ID': 'owner-7',
            'BEZR_SIDECAR_PUBLIC_ORIGIN': 'https://' + 'd' * 32 + '.agents.example.test',
            'BEZR_SIDECAR_GATEWAY_IP': '172.31.0.3',
            'BEZR_SIDECAR_LISTEN_IP': '172.31.0.2',
            'BEZR_SIDECAR_PROXY_TOKEN_FILE': '/run/secrets/bezr-proxy-token',
        }
        flags_seen = []
        nofollow_flag = 0x20000
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, env, clear=True))
            stack.enter_context(patch.object(proxy_sidecar.os, 'O_NOFOLLOW', 0x20000, create=True))
            stack.enter_context(patch.object(proxy_sidecar.os, 'open',
                side_effect=lambda path, flags: (flags_seen.append((path, flags)) or 73)))
            stack.enter_context(patch.object(proxy_sidecar.os, 'fstat', return_value=SimpleNamespace(
                st_mode=0o100600, st_uid=1000, st_nlink=1, st_size=len(token))))
            stack.enter_context(patch.object(proxy_sidecar.os, 'read', return_value=token.encode('ascii')))
            stack.enter_context(patch.object(proxy_sidecar.os, 'close'))
            stack.enter_context(patch.object(proxy_sidecar.os, 'geteuid', return_value=1000, create=True))
            config = proxy_sidecar._environment_config()
        self.assertEqual(config.proxy_token, token)
        self.assertEqual(flags_seen[0][0], env['BEZR_SIDECAR_PROXY_TOKEN_FILE'])
        self.assertTrue(flags_seen[0][1] & nofollow_flag)

    def test_environment_config_rejects_insecure_proxy_secret_file(self):
        from types import SimpleNamespace
        from control_plane import proxy_sidecar
        env = {
            'BEZR_SIDECAR_OWNER_ID': 'owner-7',
            'BEZR_SIDECAR_PUBLIC_ORIGIN': 'https://' + 'd' * 32 + '.agents.example.test',
            'BEZR_SIDECAR_GATEWAY_IP': '172.31.0.3',
            'BEZR_SIDECAR_LISTEN_IP': '172.31.0.2',
            'BEZR_SIDECAR_PROXY_TOKEN_FILE': '/run/secrets/bezr-proxy-token',
        }
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, env, clear=True))
            stack.enter_context(patch.object(proxy_sidecar.os, 'O_NOFOLLOW', 0x20000, create=True))
            stack.enter_context(patch.object(proxy_sidecar.os, 'open', return_value=73))
            stack.enter_context(patch.object(proxy_sidecar.os, 'fstat', return_value=SimpleNamespace(
                st_mode=0o100644, st_uid=1000, st_nlink=1, st_size=43)))
            stack.enter_context(patch.object(proxy_sidecar.os, 'close'))
            stack.enter_context(patch.object(proxy_sidecar.os, 'geteuid', return_value=1000, create=True))
            with self.assertRaises(SidecarConfigError):
                proxy_sidecar._environment_config()

    def test_module_entrypoint_propagates_healthcheck_failure(self):
        from control_plane import proxy_sidecar
        with patch.object(proxy_sidecar, 'main', return_value=1):
            with self.assertRaises(SystemExit) as caught:
                proxy_sidecar._entrypoint()
        self.assertEqual(caught.exception.code, 1)

    def test_healthcheck_never_follows_redirect_to_another_endpoint(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        from control_plane import proxy_sidecar
        hits = []
        class Sink(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(204)
                self.end_headers()
            def log_message(self, format, *args):
                pass
        sink = ThreadingHTTPServer(('127.0.0.1', 0), Sink)
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{sink.server_port}/second-hop')
                self.end_headers()
            def log_message(self, format, *args):
                pass
        redirect = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        threads = [threading.Thread(target=server.serve_forever, daemon=True)
                   for server in (sink, redirect)]
        for thread in threads:
            thread.start()
        self.addCleanup(redirect.server_close)
        self.addCleanup(sink.server_close)
        self.addCleanup(redirect.shutdown)
        self.addCleanup(sink.shutdown)
        config = proxy_sidecar.SidecarConfig(
            'owner-7', 'https://' + 'd' * 32 + '.agents.example.test',
            'd' * 32 + '.agents.example.test', '172.31.0.3', '127.0.0.1', 'S' * 43)
        with patch.object(proxy_sidecar, 'SIDECAR_PORT', redirect.server_port):
            self.assertFalse(proxy_sidecar._healthcheck(config))
        self.assertEqual(hits, [])

    def test_healthcheck_sends_exact_configured_headers_and_accepts_204(self):
        from control_plane import proxy_sidecar
        env = {'BEZR_SIDECAR_OWNER_ID': 'owner-7',
               'BEZR_SIDECAR_PUBLIC_ORIGIN': 'https://' + 'd' * 32 + '.agents.example.test',
               'BEZR_SIDECAR_GATEWAY_IP': '172.31.0.3', 'BEZR_SIDECAR_LISTEN_IP': '172.31.0.2',
               'BEZR_SIDECAR_PROXY_TOKEN_FILE': '/run/secrets/bezr-proxy-token'}
        class Reply:
            status = 204
        class Connection:
            def __init__(self, host, port, timeout):
                self.host, self.port, self.timeout = host, port, timeout
                self.request_args = None
                self.closed = False
            def request(self, method, path, *, headers):
                self.request_args = (method, path, headers)
            def getresponse(self):
                return Reply()
            def close(self):
                self.closed = True
        connections = []
        def connect(*args, **kwargs):
            item = Connection(*args, **kwargs)
            connections.append(item)
            return item
        with ExitStack() as stack:
            stack.enter_context(patch.object(sys, 'argv', ['proxy_sidecar', '--healthcheck']))
            stack.enter_context(patch.dict(os.environ, env, clear=True))
            stack.enter_context(patch.object(proxy_sidecar, '_read_proxy_token_file', return_value='S' * 43))
            stack.enter_context(patch.object(proxy_sidecar.http.client, 'HTTPConnection', side_effect=connect))
            self.assertEqual(proxy_sidecar.main(), 0)
        self.assertEqual(len(connections), 1)
        connection = connections[0]
        self.assertEqual((connection.host, connection.port), ('172.31.0.2', 18790))
        self.assertEqual(connection.request_args[:2], ('GET', '/_bezr/health'))
        headers = connection.request_args[2]
        self.assertEqual(headers['Authorization'], 'Bearer ' + 'S' * 43)
        self.assertEqual(headers['Host'], 'd' * 32 + '.agents.example.test')
        self.assertEqual(headers['X-Bezr-Host'], 'd' * 32 + '.agents.example.test')
        self.assertEqual(headers['X-Bezr-Origin'], env['BEZR_SIDECAR_PUBLIC_ORIGIN'])
        self.assertTrue(connection.closed)

    def test_healthcheck_rejects_wrong_origin_response_and_redacts_secret(self):
        from control_plane import proxy_sidecar
        env = {'BEZR_SIDECAR_OWNER_ID': 'owner-7',
               'BEZR_SIDECAR_PUBLIC_ORIGIN': 'https://' + 'd' * 32 + '.agents.example.test',
               'BEZR_SIDECAR_GATEWAY_IP': '172.31.0.3', 'BEZR_SIDECAR_LISTEN_IP': '172.31.0.2',
               'BEZR_SIDECAR_PROXY_TOKEN_FILE': '/run/secrets/bezr-proxy-token'}
        class Reply:
            status = 404
        class Connection:
            def __init__(self, *_args, **_kwargs): pass
            def request(self, *_args, **_kwargs): pass
            def getresponse(self): return Reply()
            def close(self): pass
        with ExitStack() as stack:
            stack.enter_context(patch.object(sys, 'argv', ['proxy_sidecar', '--healthcheck']))
            stack.enter_context(patch.dict(os.environ, env, clear=True))
            stack.enter_context(patch.object(proxy_sidecar, '_read_proxy_token_file', return_value='S' * 43))
            stack.enter_context(patch.object(proxy_sidecar.http.client, 'HTTPConnection', Connection))
            stderr = stack.enter_context(patch('sys.stderr', new_callable=io.StringIO))
            self.assertEqual(proxy_sidecar.main(), 1)
        self.assertNotIn('S' * 43, stderr.getvalue())

    def test_healthcheck_rejects_malformed_environment_without_network(self):
        from control_plane import proxy_sidecar
        with ExitStack() as stack:
            stack.enter_context(patch.object(sys, 'argv', ['proxy_sidecar', '--healthcheck']))
            stack.enter_context(patch.dict(os.environ, {'BEZR_SIDECAR_PROXY_TOKEN': 'secret'}, clear=True))
            connection = stack.enter_context(patch.object(proxy_sidecar.http.client, 'HTTPConnection'))
            stderr = stack.enter_context(patch('sys.stderr', new_callable=io.StringIO))
            self.assertEqual(proxy_sidecar.main(), 1)
        connection.assert_not_called()
        self.assertNotIn('secret', stderr.getvalue())

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
            'X-OpenClaw-Scopes': 'operator.admin,operator.talk.secrets',
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
        self.assertEqual(headers['x-openclaw-scopes'],
                         'operator.read,operator.write,operator.approvals,operator.questions,operator.pairing')
        self.assertNotIn('operator.admin', headers['x-openclaw-scopes'])
        for name in ('authorization', 'cookie', 'x-bezr-proxy-token'):
            self.assertNotIn(name, headers)

    def test_gateway_forwarded_client_address_rejects_local_and_mapped_loopback(self):
        origin = 'https://' + 'a' * 32 + '.agents.example.test'
        for client_ip in ('127.0.0.1', '::1', '::ffff:127.0.0.1',
                          '169.254.0.1', 'fe80::1'):
            with self.subTest(client_ip=client_ip), self.assertRaises(ValueError):
                build_gateway_headers({}, owner_id='owner-7', public_origin=origin,
                                      client_ip=client_ip)

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
            import asyncio
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
        self.pairing_pending = [{
            'requestId': 'req_1234567890123456',
            'deviceId': 'a' * 64,
            'roles': ['operator'],
            'scopes': ['operator.read', 'operator.write',
                       'operator.approvals', 'operator.questions', 'operator.pairing'],
            'clientId': 'openclaw-control-ui',
            'displayName': 'Alice browser',
            'platform': 'Linux',
            'browserOrigin': 'https://' + 'e' * 32 + '.agents.example.test',
            'silent': False,
            'ts': 1780000000000,
            'publicKey': 'must-not-be-returned',
        }]
        self.pairing_paired = []
        self.admin_rpc_calls = []

        async def admin_rpc(request):
            body = await request.json()
            self.admin_rpc_calls.append((body, dict(request.headers)))
            method = body.get('method')
            params = body.get('params') or {}
            if method == 'device.pair.list':
                return web.json_response({'ok': True, 'payload': {
                    'pending': self.pairing_pending,
                    'paired': self.pairing_paired,
                }})
            if method == 'device.pair.approve':
                request_id = params.get('requestId')
                matched = next((item for item in self.pairing_pending
                                if item['requestId'] == request_id), None)
                if matched is None:
                    return web.json_response({'ok': False, 'error': {'code': 'not_found'}})
                self.pairing_pending.remove(matched)
                self.pairing_paired.append({key: value for key, value in matched.items()
                                            if key not in {'requestId', 'silent', 'publicKey'}})
                return web.json_response({'ok': True, 'payload': {'requestId': request_id}})
            return web.json_response({'ok': False, 'error': {'code': 'unsupported'}})

        async def echo(request):
            return web.json_response({
                'owner': request.headers.get('x-forwarded-user'),
                'origin': request.headers.get('origin'),
                'host': request.headers.get('x-forwarded-host'),
                'proto': request.headers.get('x-forwarded-proto'),
                'client_ip': request.headers.get('x-forwarded-for'),
                'path_qs': request.rel_url.raw_path_qs,
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

        async def streamed_javascript(request):
            compressed = bytes.fromhex(
                '5be6fb81df388c63c4ab163fa7861d334c680967be76beba104926f950a6c043'
                '2ed4c3879b0fa063a80901e3422a6dacf321a65c6aeb63ae7deefb0400')
            response = web.StreamResponse(status=200, headers={
                'Content-Type': 'application/javascript; charset=utf-8',
                'Content-Encoding': 'br',
                'Content-Length': str(len(compressed)),
            })
            await response.prepare(request)
            for offset in range(0, len(compressed), 7):
                await response.write(compressed[offset:offset + 7])
                await asyncio.sleep(0.01)
            await response.write_eof()
            return response

        gateway.router.add_post('/api/v1/admin/rpc', admin_rpc)
        gateway.router.add_get('/assets/app.js', streamed_javascript)
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
        self.proxy_server = TestServer(proxy, host='127.0.0.1')
        self.client = TestClient(self.proxy_server)
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

    async def test_streamed_brotli_javascript_is_returned_with_matching_size_and_hash(self):
        import hashlib

        source = b"window.__agentAsset='" + b'abcdefghijklmnopqrstuvwxyz' * 5000 + b"';"
        compressed = bytes.fromhex(
            '5be6fb81df388c63c4ab163fa7861d334c680967be76beba104926f950a6c043'
            '2ed4c3879b0fa063a80901e3422a6dacf321a65c6aeb63ae7deefb0400')
        self.assertEqual(len(source), 130023)
        self.assertEqual(hashlib.sha256(source).hexdigest(),
                         '0103c441177b09e572b9d5b602fc2aea29e242f3ace5dbb116c4cff3e989feac')
        self.assertEqual(len(compressed), 61)
        expected_digest = 'e7e531b73c265a294d05e9f24e1be90c9be4ed7718132c5a1e074fb2a4c78ccb'

        async with self.aiohttp.ClientSession(
                auto_decompress=False,
                timeout=self.aiohttp.ClientTimeout(total=5, connect=2, sock_read=1)) as session:
            async with session.get(self.proxy_server.make_url('/assets/app.js'), headers={
                **self.internal_headers, 'Origin': self.origin,
            }) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers['Content-Encoding'], 'br')
                self.assertEqual(response.headers['Content-Length'], str(len(compressed)))
                body = await response.read()

        self.assertEqual(len(body), len(compressed))
        self.assertEqual(hashlib.sha256(body).hexdigest(), expected_digest)
        self.assertEqual(body, compressed)

    async def test_public_admin_rpc_route_is_never_relayed(self):
        for path in ('/api/v1/admin/rpc', '/api/v1/admin/rpc/extra',
                     '/_bezr/pairing-rpc/extra'):
            response = await self.client.post(path, headers={
                **self.internal_headers, 'Origin': self.origin,
                'Content-Type': 'application/json',
            }, json={'method': 'device.pair.list', 'params': {}})
            self.assertEqual(response.status, 404)
        self.assertEqual(self.admin_rpc_calls, [])

    async def test_pairing_rpc_lists_sanitized_pending_browser_requests_with_limited_scopes(self):
        response = await self.client.post('/_bezr/pairing-rpc', headers={
            **self.internal_headers, 'Origin': self.origin,
            'Content-Type': 'application/json',
        }, json={'action': 'list'})
        self.assertEqual(response.status, 200, await response.text())
        data = await response.json()
        self.assertEqual(len(data['requests']), 1)
        item = data['requests'][0]
        self.assertEqual(item['request_id'], 'req_1234567890123456')
        self.assertEqual(item['device_id'], 'a' * 64)
        self.assertEqual(item['role'], 'operator')
        self.assertEqual(item['client_id'], 'openclaw-control-ui')
        self.assertEqual(item['display_name'], 'Alice browser')
        self.assertTrue(item['approvable'])
        self.assertNotIn('publicKey', await response.text())
        body, headers = self.admin_rpc_calls[0]
        self.assertEqual(body, {'method': 'device.pair.list', 'params': {}})
        self.assertEqual(headers['x-forwarded-user'], 'owner-7')
        self.assertEqual(headers['x-openclaw-scopes'],
                         'operator.read,operator.write,operator.approvals,operator.questions,operator.pairing')

    async def test_pairing_rpc_rechecks_and_approves_only_exact_pending_browser_request(self):
        scopes = sorted(self.pairing_pending[0]['scopes'])
        response = await self.client.post('/_bezr/pairing-rpc', headers={
            **self.internal_headers, 'Origin': self.origin,
            'Content-Type': 'application/json',
        }, json={
            'action': 'approve',
            'requestId': 'req_1234567890123456',
            'expectedDeviceId': 'a' * 64,
            'expectedRole': 'operator',
            'expectedScopes': scopes,
            'expectedClientId': 'openclaw-control-ui',
        })
        self.assertEqual(response.status, 200, await response.text())
        self.assertEqual(await response.json(), {
            'approved': True, 'device_id': 'a' * 64, 'scopes': scopes,
        })
        self.assertEqual([call[0]['method'] for call in self.admin_rpc_calls], [
            'device.pair.list', 'device.pair.approve', 'device.pair.list',
        ])
        approve_body = self.admin_rpc_calls[1][0]
        self.assertEqual(approve_body['params'], {'requestId': 'req_1234567890123456'})
        self.assertNotIn('operator.admin', self.admin_rpc_calls[1][1]['x-openclaw-scopes'])

    async def test_pairing_rpc_rejects_admin_scope_before_approval(self):
        self.pairing_pending[0]['scopes'] = ['operator.read', 'operator.admin']
        response = await self.client.post('/_bezr/pairing-rpc', headers={
            **self.internal_headers, 'Origin': self.origin,
            'Content-Type': 'application/json',
        }, json={'action': 'list'})
        self.assertEqual(response.status, 200)
        item = (await response.json())['requests'][0]
        self.assertFalse(item['approvable'])
        self.assertEqual(item['reason'], 'unsupported_scope')
        approval = await self.client.post('/_bezr/pairing-rpc', headers={
            **self.internal_headers, 'Origin': self.origin,
            'Content-Type': 'application/json',
        }, json={
            'action': 'approve', 'requestId': 'req_1234567890123456',
            'expectedDeviceId': 'a' * 64, 'expectedRole': 'operator',
            'expectedScopes': ['operator.read', 'operator.admin'],
            'expectedClientId': 'openclaw-control-ui',
        })
        self.assertEqual(approval.status, 400)
        self.assertFalse(any(call[0]['method'] == 'device.pair.approve'
                             for call in self.admin_rpc_calls))

    async def test_pairing_rpc_rejects_stale_confirmation_without_approval(self):
        response = await self.client.post('/_bezr/pairing-rpc', headers={
            **self.internal_headers, 'Origin': self.origin,
            'Content-Type': 'application/json',
        }, json={
            'action': 'approve', 'requestId': 'req_1234567890123456',
            'expectedDeviceId': 'a' * 64, 'expectedRole': 'operator',
            'expectedScopes': ['operator.read'],
            'expectedClientId': 'openclaw-control-ui',
        })
        self.assertEqual(response.status, 409)
        self.assertEqual([call[0]['method'] for call in self.admin_rpc_calls],
                         ['device.pair.list'])

    async def test_pairing_rpc_missing_browser_origin_cannot_be_approved(self):
        pending = dict(self.pairing_pending[0])
        pending.pop('browserOrigin')
        self.pairing_pending = [pending]
        headers = {
            **self.internal_headers, 'Origin': self.origin,
            'Content-Type': 'application/json',
        }
        response = await self.client.post('/_bezr/pairing-rpc', headers=headers,
                                          json={'action': 'list'})
        self.assertEqual(response.status, 200)
        item = (await response.json())['requests'][0]
        self.assertFalse(item['approvable'])
        self.assertEqual(item['reason'], 'origin_mismatch')

        approval = await self.client.post('/_bezr/pairing-rpc', headers=headers, json={
            'action': 'approve', 'requestId': pending['requestId'],
            'expectedDeviceId': pending['deviceId'], 'expectedRole': 'operator',
            'expectedScopes': sorted(pending['scopes']),
            'expectedClientId': 'openclaw-control-ui',
        })
        self.assertEqual(approval.status, 409)
        self.assertFalse(any(call[0]['method'] == 'device.pair.approve'
                             for call in self.admin_rpc_calls))

    async def test_pairing_rpc_marks_untrusted_browser_metadata_as_unapprovable(self):
        base = dict(self.pairing_pending[0])
        cases = (
            ({'browserOrigin': 'https://attacker.invalid'}, 'origin_mismatch'),
            ({'silent': True}, 'silent_request'),
            ({'silent': 'false'}, 'invalid_request'),
            ({'clientId': 'openclaw-cli'}, 'not_control_ui'),
            ({'roles': ['operator', 'node']}, 'unsupported_role'),
        )
        for changes, reason in cases:
            with self.subTest(changes=changes):
                self.pairing_pending = [{**base, **changes}]
                self.admin_rpc_calls.clear()
                response = await self.client.post('/_bezr/pairing-rpc', headers={
                    **self.internal_headers, 'Origin': self.origin,
                    'Content-Type': 'application/json',
                }, json={'action': 'list'})
                self.assertEqual(response.status, 200)
                item = (await response.json())['requests'][0]
                self.assertFalse(item['approvable'])
                self.assertEqual(item['reason'], reason)
                self.assertEqual([call[0]['method'] for call in self.admin_rpc_calls],
                                 ['device.pair.list'])

    async def test_http_proxy_preserves_raw_query_parameters(self):
        raw_query = '/api/messages?limit=20&before=abc'
        response = await self.client.get(raw_query, headers={
            **self.internal_headers, 'Origin': self.origin,
        })
        self.assertEqual(response.status, 200)
        data = await response.json()
        self.assertEqual(data['path_qs'], raw_query)

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
