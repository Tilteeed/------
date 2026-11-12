"""Portable command lifecycle tests; these are not Linux namespace evidence."""
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from scripts import ollama_route_acceptance as acceptance


class CommandLifecycleTests(unittest.TestCase):
    def test_blocked_stdin_deadline_reaps_child_and_leaves_no_io_thread(self):
        # Finite sleep also bounds the RED run against the old blocking writer.
        children = []
        popen = subprocess.Popen
        before = set(threading.enumerate())

        def spawn(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        started = time.monotonic()
        with mock.patch.object(acceptance.subprocess, 'Popen', side_effect=spawn):
            with self.assertRaises((subprocess.TimeoutExpired, RuntimeError, BrokenPipeError)):
                acceptance.command([sys.executable, '-c', 'import time; time.sleep(1.5)'],
                                   timeout=0.15, input_text='x' * (4 * 1024 * 1024))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0, 'stdin writing escaped the command deadline')
        self.assertIsNotNone(children[0].poll())
        self.assertEqual(set(threading.enumerate()) - before, set())


if __name__ == '__main__':
    unittest.main()
