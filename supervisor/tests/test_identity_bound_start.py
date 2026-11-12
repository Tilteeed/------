import unittest
from unittest.mock import Mock

from supervisor.docker_engine import DockerEngine, DockerEngineError


class IdentityBoundStartTests(unittest.TestCase):
    def test_replacement_is_not_started(self):
        engine = object.__new__(DockerEngine)
        engine._find = Mock(return_value={'Id': 'b' * 64, 'Config': {'Labels': {engine.SPEC_LABEL: '{"version": 1}'}}})
        engine._verify = Mock(return_value='b' * 64)
        engine._request = Mock()
        with self.assertRaises(DockerEngineError):
            engine.start_bound('a' * 32, 'a' * 64)
        engine._request.assert_not_called()

    def test_legacy_start_addresses_verified_full_id(self):
        engine = object.__new__(DockerEngine)
        identity = 'a' * 64
        engine._find = Mock(return_value={'Id': identity, 'Config': {'Labels': {engine.SPEC_LABEL: '{"version": 1}'}}})
        engine._verify = Mock(return_value=identity)
        engine._request = Mock()
        engine.inspect = Mock(return_value={'container_id': identity, 'state': 'running'})
        engine.start_bound('a' * 32, identity)
        engine._request.assert_called_once_with('POST', '/containers/' + identity + '/start', ok=(204, 304))

    def test_proxy_start_is_refused_without_identity_bound_pair(self):
        engine = object.__new__(DockerEngine)
        identity = 'a' * 64
        engine._find = Mock(return_value={'Id': identity, 'Config': {'Labels': {engine.SPEC_LABEL: '{"version": 3}'}}})
        engine._verify = Mock(return_value=identity)
        engine._request = Mock()
        with self.assertRaises(DockerEngineError):
            engine.start_bound('a' * 32, identity)
        engine._request.assert_not_called()
