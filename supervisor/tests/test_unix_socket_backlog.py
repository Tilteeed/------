"""A real Unix socket must accept a browser-sized burst without dropping it."""
import os
import socket
import socketserver
import tempfile
import unittest

from supervisor.service import _BoundedUnixServer


@unittest.skipUnless(os.name == 'posix' and hasattr(socket, 'AF_UNIX'), 'Unix sockets required')
class UnixSocketBacklogTests(unittest.TestCase):
    def test_accepts_twelve_connections_before_servicing_any(self):
        with tempfile.TemporaryDirectory(prefix='bezr-q-') as directory:
            path = os.path.join(directory, 'socket')
            with _BoundedUnixServer(path, socketserver.BaseRequestHandler):
                sockets = []
                try:
                    for _ in range(12):
                        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sockets.append(connection)
                        connection.settimeout(1)
                        connection.connect(path)
                finally:
                    for connection in sockets:
                        connection.close()
