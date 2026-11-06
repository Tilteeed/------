import socket
import ssl
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from ops.control_ui_preflight import ControlUiPreflightError, preflight_control_ui


class FakeSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeTlsContext:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED

    def __init__(self):
        self.server_hostnames = []

    def wrap_socket(self, sock, *, server_hostname):
        self.server_hostnames.append(server_hostname)
        return sock


class FakeResponse:
    def __init__(self, status):
        self.status = status
        self.read_called = False

    def read(self, *_args, **_kwargs):
        self.read_called = True
        raise AssertionError('Preflight must not read a response body')

    def close(self):
        pass


class FakeConnection:
    response_status = 415
    instances = []

    def __init__(self, host, port, *, context, timeout):
        self.host = host
        self.port = port
        self.context = context
        self.timeout = timeout
        self.request_data = None
        self.response = FakeResponse(self.response_status)
        self.closed = False
        self.sock = None
        type(self).instances.append(self)

    def request(self, method, path, body=None, headers=None):
        self.request_data = (method, path, body, headers)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True
        if self.sock is not None:
            self.sock.close()


class ControlUiPreflightTests(unittest.TestCase):
    def setUp(self):
        FakeConnection.response_status = 415
        FakeConnection.instances = []
        self.kwargs = {
            'instance_id': 'b461df60222441b1903c30db1d6adeda',
            'domain': 'agents.example.test',
            'proxy_ips': ('192.0.2.20',),
            'app_origin': 'https://bezr.example.test',
        }

    @contextmanager
    def _mock_network(self, dns_ip):
        raw_socket = FakeSocket()
        tls_context = FakeTlsContext()
        with patch('ops.control_ui_preflight.socket.getaddrinfo') as getaddrinfo, \
             patch('ops.control_ui_preflight.socket.create_connection') as create_connection, \
             patch('ops.control_ui_preflight.ssl.create_default_context') as create_context, \
             patch('ops.control_ui_preflight.http.client.HTTPSConnection', FakeConnection):
            getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', (dns_ip, 443))]
            create_connection.return_value = raw_socket
            create_context.return_value = tls_context
            yield getaddrinfo, create_connection, tls_context, raw_socket

    def test_dns_tls_origin_and_forwarded_scheme_probe_passes_only_on_415(self):
        with self._mock_network('192.0.2.20') as (
                getaddrinfo, create_connection, tls_context, raw_socket):
            result = preflight_control_ui(**self.kwargs)

        self.assertEqual(result['dns_ips'], ('192.0.2.20',))
        self.assertEqual(result['handoff_status'], 415)
        self.assertEqual(len(FakeConnection.instances), 1)
        connection = FakeConnection.instances[0]
        self.assertEqual(connection.host,
                         self.kwargs['instance_id'] + '.' + self.kwargs['domain'])
        self.assertEqual(connection.port, 443)
        create_connection.assert_called_once_with(('192.0.2.20', 443), timeout=5.0)
        self.assertEqual(tls_context.server_hostnames, [connection.host])
        self.assertTrue(raw_socket.closed)
        method, path, body, headers = connection.request_data
        self.assertEqual((method, path, body), ('POST', '/_bezr/enter', b'preflight'))
        self.assertEqual(headers['Origin'], self.kwargs['app_origin'])
        self.assertEqual(headers['Content-Type'], 'text/plain')
        self.assertEqual(headers['X-Forwarded-For'], '198.51.100.254')
        self.assertEqual(headers['X-Forwarded-Proto'], 'http')
        self.assertNotIn('ticket', path.lower())
        self.assertTrue(connection.context.check_hostname)
        self.assertEqual(connection.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(connection.closed)
        self.assertFalse(connection.response.read_called)

    def test_dns_mismatch_fails_before_https_request(self):
        with self._mock_network('192.0.2.21') as (
                getaddrinfo, create_connection, _tls_context, _raw_socket):
            with self.assertRaises(ControlUiPreflightError):
                preflight_control_ui(**self.kwargs)

        self.assertEqual(FakeConnection.instances, [])
        create_connection.assert_not_called()

    def test_403_404_and_redirects_are_not_mistaken_for_success(self):
        for status in (403, 404, 301):
            with self.subTest(status=status):
                FakeConnection.response_status = status
                FakeConnection.instances = []
                with self._mock_network('192.0.2.20'):
                    with self.assertRaises(ControlUiPreflightError):
                        preflight_control_ui(**self.kwargs)
                self.assertFalse(FakeConnection.instances[0].response.read_called)

    def test_rejects_invalid_identifier_domain_and_non_origin_before_dns(self):
        with patch('ops.control_ui_preflight.socket.getaddrinfo') as getaddrinfo:
            with self.assertRaises(ControlUiPreflightError):
                preflight_control_ui(
                    instance_id='../bad', domain=self.kwargs['domain'],
                    proxy_ips=self.kwargs['proxy_ips'], app_origin=self.kwargs['app_origin'])
            with self.assertRaises(ControlUiPreflightError):
                preflight_control_ui(
                    instance_id=self.kwargs['instance_id'], domain='agents.example.test\n.evil.test',
                    proxy_ips=self.kwargs['proxy_ips'], app_origin=self.kwargs['app_origin'])
            with self.assertRaises(ControlUiPreflightError):
                preflight_control_ui(
                    instance_id=self.kwargs['instance_id'], domain=self.kwargs['domain'],
                    proxy_ips=self.kwargs['proxy_ips'], app_origin='https://bezr.example.test/path')
            with self.assertRaises(ControlUiPreflightError):
                preflight_control_ui(
                    instance_id=self.kwargs['instance_id'], domain=self.kwargs['domain'],
                    proxy_ips=('255.255.255.255',), app_origin=self.kwargs['app_origin'])
            with self.assertRaises(ControlUiPreflightError):
                preflight_control_ui(
                    instance_id=self.kwargs['instance_id'], domain=self.kwargs['domain'],
                    proxy_ips=self.kwargs['proxy_ips'], app_origin='http://bezr.example.test')
            getaddrinfo.assert_not_called()


if __name__ == '__main__':
    unittest.main()
