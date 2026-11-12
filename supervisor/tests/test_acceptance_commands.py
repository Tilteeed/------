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
        self.assertTrue(children[0].stdin.closed)
        self.assertTrue(children[0].stdout.closed)
        self.assertEqual(set(threading.enumerate()) - before, set())

    def test_full_duplex_large_input_and_bounded_output(self):
        text = 'Я' * (2 * 1024 * 1024)
        output = acceptance.command([sys.executable, '-c',
            'import sys; sys.stdout.buffer.write(b"r" * 100000); sys.stdout.flush(); '
            'data=sys.stdin.buffer.read(); print(len(data))'], input_text=text, timeout=5)
        self.assertEqual(output.strip(), 'r' * 100000 + str(len(text.encode('utf-8'))))

    def test_sleep_timeout_reaps_child_and_closes_pipes(self):
        self._assert_failed_child('import time; time.sleep(5)', subprocess.TimeoutExpired,
                                  timeout=.15)

    def test_output_overflow_reaps_child_and_closes_pipes(self):
        self._assert_failed_child('import sys,time; sys.stdout.buffer.write(b"x" * 300000); '
                                  'sys.stdout.flush(); time.sleep(5)', RuntimeError, timeout=2)

    def _assert_failed_child(self, source, error, **kwargs):
        popen = subprocess.Popen
        children = []
        before = set(threading.enumerate())

        def spawn(*args, **options):
            child = popen(*args, **options)
            children.append(child)
            return child

        with mock.patch.object(acceptance.subprocess, 'Popen', side_effect=spawn):
            with self.assertRaises(error):
                acceptance.command([sys.executable, '-c', source], **kwargs)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertEqual(set(threading.enumerate()) - before, set())

    def test_inherited_session_is_explicit_and_direct_child_is_reaped(self):
        children = []
        popen = subprocess.Popen

        def spawn(*args, **kwargs):
            self.assertIs(kwargs['start_new_session'], False)
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        with mock.patch.object(acceptance.subprocess, 'Popen', side_effect=spawn):
            with self.assertRaises(subprocess.TimeoutExpired):
                acceptance.command([sys.executable, '-c', 'import time; time.sleep(5)'],
                                   timeout=.15, start_new_session=False)
        self.assertIsNotNone(children[0].poll())

    def test_inherited_session_cleanup_never_signals_callers_group(self):
        child = mock.Mock()
        child.poll.return_value = None
        with mock.patch.object(acceptance.os, 'name', 'posix'), \
                mock.patch.object(acceptance.os, 'killpg', create=True) as killpg:
            acceptance._kill_command(child, start_new_session=False)
        killpg.assert_not_called()
        child.kill.assert_called_once_with()

    def test_owned_session_cleanup_signals_owned_group_even_after_leader_exits(self):
        child = mock.Mock(pid=456)
        child.poll.return_value = 0
        with mock.patch.object(acceptance.os, 'name', 'posix'), \
                mock.patch.object(acceptance.signal, 'SIGKILL', 9, create=True), \
                mock.patch.object(acceptance.os, 'killpg', create=True) as killpg:
            acceptance._kill_command(child)
        killpg.assert_called_once_with(456, 9)
        child.kill.assert_not_called()


class ParentDeathSetupTests(unittest.TestCase):
    """Mocked Linux syscall shape only, explicitly not live-OS proof."""

    def test_linux_hook_arms_sigkill_and_checks_original_parent(self):
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(acceptance.signal, 'SIGKILL', 9, create=True), \
                mock.patch('ctypes.CDLL', return_value=libc), \
                mock.patch.object(acceptance.os, 'getpid', return_value=123), \
                mock.patch.object(acceptance.os, 'getppid', return_value=123, create=True), \
                mock.patch.object(acceptance.os, 'kill') as kill:
            hook = acceptance._parent_death_setup()
            assert hook is not None
            hook()
        libc.prctl.assert_called_once_with(1, 9, 0, 0, 0)
        kill.assert_not_called()

    def test_linux_hook_race_guard_kills_child_not_parent(self):
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(acceptance.signal, 'SIGKILL', 9, create=True), \
                mock.patch('ctypes.CDLL', return_value=libc), \
                mock.patch.object(acceptance.os, 'getpid', side_effect=[123, 456]), \
                mock.patch.object(acceptance.os, 'getppid', return_value=1, create=True), \
                mock.patch.object(acceptance.os, 'kill') as kill:
            hook = acceptance._parent_death_setup()
            assert hook is not None
            hook()
        kill.assert_called_once_with(456, 9)

    def test_prctl_failure_exits_before_exec(self):
        libc = mock.Mock()
        libc.prctl.return_value = -1
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(acceptance.signal, 'SIGKILL', 9, create=True), \
                mock.patch('ctypes.CDLL', return_value=libc), \
                mock.patch.object(acceptance.os, '_exit', side_effect=SystemExit) as exit_child, \
                mock.patch.object(acceptance.os, 'getppid', create=True) as parent:
            hook = acceptance._parent_death_setup()
            assert hook is not None
            with self.assertRaises(SystemExit):
                hook()
        exit_child.assert_called_once_with(127)
        parent.assert_not_called()

    def test_non_linux_never_loads_prctl(self):
        with mock.patch.object(sys, 'platform', 'win32'), mock.patch('ctypes.CDLL') as cdll:
            self.assertIsNone(acceptance._parent_death_setup())
        cdll.assert_not_called()

    def test_command_passes_parent_death_hook_to_popen(self):
        popen = subprocess.Popen
        seen = []

        def spawn(*args, **kwargs):
            seen.append(kwargs.pop('preexec_fn'))
            return popen(*args, **kwargs)

        hook = mock.Mock()
        with mock.patch.object(acceptance, '_parent_death_setup', return_value=hook), \
                mock.patch.object(acceptance.subprocess, 'Popen', side_effect=spawn):
            self.assertEqual(acceptance.command([sys.executable, '-c', 'print("ready")']).strip(), 'ready')
        self.assertEqual(seen, [hook])


if __name__ == '__main__':
    unittest.main()
