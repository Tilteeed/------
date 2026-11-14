"""Concurrent Control UI requests share only an in-progress live proof."""
import asyncio
import threading
import unittest

import httpx

from control_plane.access_proxy import create_control_ui_access_proxy


class ConcurrentLookupTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_session_is_checked_and_completed_proofs_are_not_cached(self):
        instance = 'a' * 32
        domain = 'agents.example.test'
        origin = f'https://{instance}.{domain}'
        entered, release = asyncio.Event(), asyncio.Event()
        counts = {'session': 0, 'runtime': 0, 'target': 0, 'forwarded': 0}
        lock = threading.Lock()

        class Store:
            def validate_control_ui_session(self, token, *, audience):
                with lock:
                    counts['session'] += 1
                if token != 'S' * 43 or audience != origin:
                    return None
                return {'instance_id': instance, 'owner_id': 'alice'}

        class Runtime:
            def get(self, owner):
                with lock:
                    counts['runtime'] += 1
                return {'runtime': {'state': 'running', 'gateway': 'ready',
                                    'network_profile': 'agent_proxy_v1', 'instance_id': instance}}

        async def target(owner, actual_instance):
            counts['target'] += 1
            entered.set()
            await release.wait()
            return {'ip': '172.31.0.2', 'port': 18790, 'proxy_token': 'T' * 43}

        class Transport:
            async def request(self, target, method, path, headers, body):
                counts['forwarded'] += 1
                return 200, {'Content-Type': 'text/plain'}, b'ok'

        app = create_control_ui_access_proxy(
            Store(), Runtime(), public_origin='https://example.test', control_ui_domain=domain,
            target_resolver=target, transport=Transport(), proxy_ready=True)
        transport = httpx.ASGITransport(app=app, client=('198.51.100.7', 12345))
        headers = {'Cookie': '__Host-bezr-control-ui=' + 'S' * 43,
                   'X-Forwarded-For': '198.51.100.7', 'X-Forwarded-Proto': 'https'}
        async with httpx.AsyncClient(transport=transport, base_url=origin, headers=headers) as client:
            tasks = [asyncio.create_task(client.get(f'/assets/{i}.js')) for i in range(12)]
            await asyncio.wait_for(entered.wait(), 5)
            for _ in range(500):
                with lock:
                    finished = counts['session'] == 12
                if finished:
                    break
                await asyncio.sleep(.01)
            self.assertTrue(finished, 'all sessions must be checked independently')
            denied = await client.get('/assets/denied.js', headers={
                'Cookie': '__Host-bezr-control-ui=' + 'X' * 43})
            self.assertEqual(denied.status_code, 404)
            release.set()
            responses = await asyncio.wait_for(asyncio.gather(*tasks), 5)
            self.assertEqual([r.status_code for r in responses], [200] * 12)
            self.assertEqual((counts['runtime'], counts['target'], counts['forwarded']), (1, 1, 12))
            response = await client.get('/assets/next.js')
            self.assertEqual(response.status_code, 200)
            self.assertEqual((counts['session'], counts['runtime'], counts['target']), (14, 2, 2))

    async def test_failed_live_proof_is_not_reused(self):
        instance = 'b' * 32
        domain = 'agents.example.test'
        origin = f'https://{instance}.{domain}'
        calls = []

        class Store:
            def validate_control_ui_session(self, token, *, audience):
                return {'instance_id': instance, 'owner_id': 'alice'}

        class Runtime:
            def get(self, owner):
                return {'runtime': {'state': 'running', 'gateway': 'ready',
                                    'network_profile': 'agent_proxy_v1', 'instance_id': instance}}

        def target(owner, actual_instance):
            calls.append(1)
            raise RuntimeError('private error')

        app = create_control_ui_access_proxy(Store(), Runtime(), public_origin='https://example.test',
            control_ui_domain=domain, target_resolver=target, proxy_ready=True)
        transport = httpx.ASGITransport(app=app, client=('198.51.100.7', 12345))
        headers = {'Cookie': '__Host-bezr-control-ui=' + 'S' * 43,
                   'X-Forwarded-For': '198.51.100.7', 'X-Forwarded-Proto': 'https'}
        async with httpx.AsyncClient(transport=transport, base_url=origin, headers=headers) as client:
            for _ in range(2):
                response = await client.get('/assets/a.js')
                self.assertEqual(response.status_code, 503)
                self.assertNotIn('private error', response.text)
        self.assertEqual(len(calls), 2)
