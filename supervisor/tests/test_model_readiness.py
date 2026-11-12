import unittest
from unittest.mock import patch

from supervisor.model_readiness import model_status


class ModelReadinessTests(unittest.TestCase):
    def test_truncated_content_length_rejects_valid_json(self):
        from http.client import HTTPResponse
        from io import BytesIO
        body = b'{"models":[{"name":"qwen3.5:9b"}]}'
        class Socket:
            def makefile(self, *args):
                return BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body) + 10).encode() + b'\r\n\r\n' + body)
            def shutdown(self, *args): pass
        class Connection:
            def __init__(self, *args, **kwargs): self.sock = Socket()
            def connect(self): pass
            def request(self, *args, **kwargs): pass
            def getresponse(self):
                response = HTTPResponse(self.sock)
                response.begin()
                return response
            def close(self): pass
        with patch('supervisor.model_readiness.http.client.HTTPConnection', Connection):
            self.assertEqual(model_status('http://example.test:11434', 'qwen3.5:9b'), 'unavailable')

    def test_matching_tags_indicate_presence_not_inference(self):
        class Response:
            status = 200
            def read1(self, size):
                if hasattr(self, 'done'):
                    return b''
                self.done = True
                return b'{"models":[{"name":"qwen3.5:9b"}]}'
        class Connection:
            def __init__(self, *args, **kwargs): self.sock = None
            def connect(self): pass
            def request(self, method, path, headers):
                assert (method, path) == ('GET', '/api/tags')
            def getresponse(self): return Response()
            def close(self): pass
        with patch('supervisor.model_readiness.http.client.HTTPConnection', Connection):
            self.assertEqual(model_status('http://10.0.0.1:11434', 'qwen3.5:9b'), 'model_present')

    def test_slow_probe_does_not_hold_service_lock(self):
        import threading
        from supervisor.service import RuntimeService, ServiceError
        from types import SimpleNamespace
        service = RuntimeService.__new__(RuntimeService)
        from supervisor.model_readiness import CachedModelStatus
        service.model_status_cache = CachedModelStatus(lambda *args: model_status_proxy(*args))
        service.lock = threading.RLock()
        service.ollama_config = {'base_url': 'http://10.0.0.1:11434', 'default_model_id': 'qwen3.5:9b'}
        service.store = SimpleNamespace(retained=lambda actor: [], restore_retry=lambda _: None, purge_retry=lambda _: None)
        def unavailable(): raise ServiceError('runtime_unavailable', 503)
        service._sample = unavailable
        instance = {'id': 'a', 'actor': 'alice', 'state': 'running', 'active': True, 'revision': 1}
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        def slow(*args):
            entered.set()
            release.wait(2)
            return 'unavailable'
        def view():
            with service.lock:
                service._view(instance)
        model_status_proxy = slow
        try:
            with patch('supervisor.service.model_status', side_effect=slow):
                worker = threading.Thread(target=view, daemon=True)
                worker.start()
                self.assertTrue(entered.wait(1))
                def other_action():
                    with service.lock:
                        done.set()
                threading.Thread(target=other_action, daemon=True).start()
                self.assertTrue(done.wait(.3), 'slow readiness probe blocked another action')
        finally:
            release.set()
            worker.join(3)
            service.model_status_cache.close()

    def test_cache_expires_and_never_reuses_status_for_another_model(self):
        import threading
        from supervisor.model_readiness import CachedModelStatus
        now = [0]
        called = threading.Event()
        calls = []
        def probe(url, model):
            calls.append(model)
            called.set()
            return 'model_present'
        cache = CachedModelStatus(probe, clock=lambda: now[0])
        try:
            self.assertEqual(cache.get('endpoint', 'old'), 'unavailable')
            self.assertTrue(called.wait(1))
            # Synchronize with publication, not only the probe callback.
            for _ in range(1000):
                with cache._lock:
                    if not cache._running: break
                threading.Event().wait(.001)
            self.assertEqual(cache.get('endpoint', 'old'), 'model_present')
            self.assertEqual(cache.get('endpoint', 'new'), 'unavailable')
            self.assertEqual(calls, ['old'])
            now[0] = 15
            self.assertEqual(cache.get('endpoint', 'new'), 'unavailable')
            for _ in range(1000):
                with cache._lock:
                    if not cache._running: break
                threading.Event().wait(.001)
            self.assertEqual(cache.get('endpoint', 'new'), 'model_present')
            self.assertEqual(cache.get('endpoint', 'old'), 'unavailable')
            now[0] = 31
            self.assertEqual(cache.get('endpoint', 'new'), 'unavailable')
        finally:
            cache.close()

    def test_probe_failure_and_missing_are_sanitized(self):
        class Response:
            status = 200
            def __init__(self, body): self.body = body
            def read1(self, size):
                chunk, self.body = self.body[:size], self.body[size:]
                return chunk
        class Connection:
            body = b''
            def __init__(self, *args, **kwargs): self.sock = None
            def connect(self): pass
            def request(self, *args, **kwargs): pass
            def getresponse(self): return Response(self.body)
            def close(self): pass
        with patch('supervisor.model_readiness.http.client.HTTPConnection', Connection):
            for body, expected in [(b'{"models":[]}', 'model_missing'), (b'secret malformed', 'unavailable'), (b'{"models":[{}]}', 'unavailable'), (b'x' * (1024 * 1024 + 1), 'unavailable')]:
                with self.subTest(expected=expected):
                    Connection.body = body
                    self.assertEqual(model_status('http://10.0.0.1:11434', 'qwen3.5:9b'), expected)
        with patch('supervisor.model_readiness.http.client.HTTPConnection', side_effect=OSError('secret')):
            self.assertEqual(model_status('http://10.0.0.1:11434', 'qwen3.5:9b'), 'unavailable')

    def test_no_active_instance_is_configured_without_network_probe(self):
        from supervisor.service import RuntimeService, ServiceError
        service = RuntimeService.__new__(RuntimeService)
        service.ollama_config = {'base_url': 'http://10.0.0.1:11434', 'default_model_id': 'qwen3.5:9b'}
        def unavailable(): raise ServiceError('runtime_unavailable', 503)
        service._sample = unavailable
        with patch('supervisor.service.model_status') as probe:
            view = service._view()
        probe.assert_not_called()
        self.assertEqual(view['runtime']['model'], 'configured')
        self.assertFalse(view['capabilities']['chat'])

    def test_probe_network_deadline_rejects_late_connect(self):
        class Connection:
            def __init__(self, *args, **kwargs): pass
            def connect(self): pass
            def close(self): pass
        with patch('supervisor.model_readiness.http.client.HTTPConnection', Connection), patch('supervisor.model_readiness.time.monotonic', side_effect=[0, 5]):
            self.assertEqual(model_status('http://10.0.0.1:11434', 'qwen3.5:9b'), 'unavailable')
