"""Bounded subprocess transport for trusted, fixed read-only probe commands.

This is not a command sandbox: callers must construct their own allowlisted argv.
No shell, inherited stdin, unbounded communicate(), or raw stderr in exceptions.
"""
import os
import subprocess
from threading import Thread


class ProbeFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def run_command(argv, *, timeout: float = 10, max_output_bytes: int = 65536):
    """Return bounded UTF-8 stdout; code callers, not clients, own all arguments."""
    if (type(timeout) not in (int, float) or not 0 < timeout <= 10
            or type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 65536):
        raise ValueError('Invalid trusted probe limits')
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False,
                                   env=dict(os.environ, LC_ALL='C'))
    except OSError:
        raise ProbeFailure('command_unavailable') from None
    result = {}

    def kill():
        try:
            process.kill()
        except OSError:
            pass

    def read():
        assert process.stdout is not None
        try:
            data = process.stdout.read(max_output_bytes + 1)
            if len(data) > max_output_bytes:
                result['error'] = 'output_limit'
                kill()
            else:
                result['data'] = data
        except OSError:
            result['error'] = 'invalid_output'
        finally:
            # The reader owns closing the stream; never close a blocked read from
            # the main thread (that can wait indefinitely on the buffered I/O lock).
            process.stdout.close()

    reader = Thread(target=read, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        reader.join(timeout=1)
        raise ProbeFailure('command_timeout') from None
    reader.join(timeout=1)
    if reader.is_alive():
        # An unexpected descendant may hold stdout open; never wait forever.
        raise ProbeFailure('output_timeout')
    if 'error' in result:
        raise ProbeFailure(result['error'])
    if process.returncode != 0:
        raise ProbeFailure('command_failed')
    try:
        return result['data'].decode('utf-8')
    except (KeyError, UnicodeError):
        raise ProbeFailure('invalid_output') from None
