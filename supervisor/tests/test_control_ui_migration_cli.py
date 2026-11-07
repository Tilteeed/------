import unittest
from enum import IntEnum
from unittest.mock import patch

from scripts import manage_control_ui_sidecars as cli
from scripts.manage_control_ui_sidecars import build_payload


class FakeAddressFamily(IntEnum):
    UNIX = 1


class ControlUiSidecarMigrationCliTests(unittest.TestCase):
    def test_unix_connection_accepts_int_enum_address_family(self):
        class FakeSocket:
            def __init__(self):
                self.timeout = None
                self.path = None
                self.closed = False

            def settimeout(self, timeout):
                self.timeout = timeout

            def connect(self, path):
                self.path = path

            def close(self):
                self.closed = True

        fake_socket = FakeSocket()
        with patch.object(cli.socket, 'AF_UNIX', FakeAddressFamily.UNIX, create=True):
            with patch.object(cli.socket, 'socket', return_value=fake_socket) as create_socket:
                connection = cli.UnixAdminConnection(
                    '/run/supervisor/control-ui-maintenance.sock')
                connection.connect()

        create_socket.assert_called_once_with(FakeAddressFamily.UNIX, cli.socket.SOCK_STREAM)
        self.assertIs(connection.sock, fake_socket)
        self.assertEqual(fake_socket.path, '/run/supervisor/control-ui-maintenance.sock')
        self.assertFalse(fake_socket.closed)

    def test_payload_never_accepts_image_or_instance_identity(self):
        digest = 'a' * 64
        self.assertEqual(build_payload('plan'), {'action': 'plan'})
        self.assertEqual(build_payload('status'), {'action': 'status'})
        self.assertEqual(build_payload('resume'), {'action': 'resume'})
        self.assertEqual(build_payload('apply', digest), {
            'action': 'apply', 'plan_sha256': digest})
        with self.assertRaises(ValueError):
            build_payload('apply')
        with self.assertRaises(ValueError):
            build_payload('apply', 'not-a-digest')
        with self.assertRaises(ValueError):
            build_payload('plan', digest)


if __name__ == '__main__':
    unittest.main()
