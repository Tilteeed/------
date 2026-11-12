"""Bounded host-side Ollama inventory probe; it does not test inference."""
import http.client
import json
import socket
import threading
import time
from urllib.parse import urlsplit

MAX_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 5


def model_status(base_url, model_id):
    """Return only a fixed public status, never upstream diagnostics."""
    connection = None
    timer = None
    try:
        deadline = time.monotonic() + TIMEOUT_SECONDS
        address = urlsplit(base_url)
        connection = http.client.HTTPConnection(address.hostname, address.port, timeout=TIMEOUT_SECONDS)
        connection.connect()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 'unavailable'
        sock = connection.sock
        def abort():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(remaining, abort)
        timer.daemon = True
        timer.start()
        connection.request('GET', '/api/tags', headers={'Accept': 'application/json', 'Connection': 'close'})
        response = connection.getresponse()
        if response.status != 200:
            return 'unavailable'
        body = bytearray()
        while True:
            chunk = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
            if time.monotonic() >= deadline:
                return 'unavailable'
            if not chunk:
                if getattr(response, 'length', None) not in (None, 0):
                    return 'unavailable'
                break
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                return 'unavailable'
        data = json.loads(body)
        models = data.get('models') if type(data) is dict else None
        if type(models) is not list or any(type(item) is not dict or type(item.get('name')) is not str for item in models):
            return 'unavailable'
        return 'model_present' if any(item['name'] == model_id for item in models) else 'model_missing'
    except (OSError, ValueError, TypeError, http.client.HTTPException, RecursionError):
        return 'unavailable'
    finally:
        if timer is not None:
            timer.cancel()
        if connection is not None:
            connection.close()


class CachedModelStatus:
    """Single-flight, rate-limited inventory cache; never waits for network."""
    def __init__(self, probe=model_status, *, interval=5, max_age=15, clock=time.monotonic):
        self._probe, self._interval, self._max_age, self._clock = probe, interval, max_age, clock
        self._lock = threading.Lock()
        self._key = self._value = None
        self._finished = self._started = float('-inf')
        self._running = self._closed = False

    def get(self, base_url, model_id):
        key = (base_url, model_id)
        with self._lock:
            now = self._clock()
            if self._closed:
                return 'unavailable'
            if not self._running and now - self._started >= self._interval:
                self._running = True
                self._started = now
                try:
                    threading.Thread(target=self._run, args=(key,), daemon=True,
                                     name='model-inventory').start()
                except RuntimeError:
                    self._running = False
            if self._key == key and now - self._finished < self._max_age:
                return self._value
            return 'unavailable'

    def _run(self, key):
        try:
            result = self._probe(*key)
            if result not in ('model_present', 'model_missing', 'unavailable'):
                result = 'unavailable'
        except Exception:
            result = 'unavailable'
        with self._lock:
            if not self._closed:
                self._key, self._value, self._finished = key, result, self._clock()
            self._running = False

    def close(self):
        # A daemon worker may finish its bounded I/O independently of shutdown.
        with self._lock:
            self._closed = True
            self._key = self._value = None
