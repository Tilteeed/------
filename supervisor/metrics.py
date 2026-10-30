"""Explicit Linux /proc collector. Construction/import never starts a thread."""
from collections import deque
import os
from pathlib import Path
import threading
import time


class MetricsUnavailable(Exception):
    pass


class HostMetrics:
    def __init__(self, pool, *, clock=time.monotonic, proc='/proc'):
        self.pool, self.clock, self.proc = pool, clock, Path(proc)
        self._history = deque()
        self._snapshot = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def collect(self):
        now = self.clock()
        # Linux guest/guest_nice are already included in user/nice.
        with (self.proc / 'stat').open(encoding='ascii') as stream:
            fields = stream.readline().split()
        if fields[0] != 'cpu' or len(fields) < 9:
            raise MetricsUnavailable()
        ticks = [int(value) for value in fields[1:9]]
        total, idle = sum(ticks), ticks[3] + ticks[4]
        memory = {}
        with (self.proc / 'meminfo').open(encoding='ascii') as stream:
            for line in stream:
                key, value = line.split(':', 1)
                if key in ('MemTotal', 'MemAvailable'):
                    number, unit = value.split()
                    if unit != 'kB':
                        raise MetricsUnavailable()
                    memory[key] = int(number) * 1024
        disk = os.statvfs(self.pool)
        with self._lock:
            if self._history and (now <= self._history[-1][0] or total < self._history[-1][1]):
                self._history.clear()
            self._history.append((now, total, idle))
            # Keep the closest sample at or before 60s; age/freshness is separate.
            while len(self._history) > 1 and self._history[1][0] <= now - 60:
                self._history.popleft()
            first = self._history[0]
            elapsed, delta = now - first[0], total - first[1]
            cpu = 100 * (delta - (idle - first[2])) / delta if delta > 0 else 0.0
            self._snapshot = dict(sampled_at=now, cpu_window_seconds=elapsed,
                                  cpu_percent=max(0.0, min(100.0, cpu)),
                                  total_ram_bytes=memory['MemTotal'],
                                  available_ram_bytes=memory['MemAvailable'],
                                  total_cpu_millicores=(os.cpu_count() or 0) * 1000,
                                  total_disk_bytes=disk.f_blocks * disk.f_frsize,
                                  free_disk_bytes=disk.f_bavail * disk.f_frsize)

    def snapshot(self):
        with self._lock:
            if self._snapshot is None:
                raise MetricsUnavailable()
            return dict(self._snapshot)

    def _run(self):
        while not self._stop.is_set():
            try:
                self.collect()
            except (OSError, ValueError, KeyError, MetricsUnavailable):
                # Preserve sample timestamp: stale observations must fail policy.
                pass
            self._stop.wait(1)

    def start(self):
        if self._thread is not None:
            raise RuntimeError('Collector already started')
        self.collect()
        self._thread = threading.Thread(target=self._run, name='host-metrics', daemon=True)
        self._thread.start()

    def close(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
