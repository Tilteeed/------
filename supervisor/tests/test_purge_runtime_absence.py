import unittest
from unittest.mock import Mock

from supervisor.docker_engine import DockerEngine, DockerEngineError


class PurgeRuntimeAbsenceTests(unittest.TestCase):
    def test_rejects_orphan_sidecar_even_when_gateway_absent(self):
        engine = object.__new__(DockerEngine)
        engine._find = Mock(return_value=None)
        engine._find_proxy_sidecar = Mock(return_value={'Id': 'a' * 64})
        with self.assertRaises(DockerEngineError):
            engine.assert_purge_runtime_absent('b' * 32)
        engine._find_proxy_sidecar.assert_called_once_with('b' * 32)

    def test_accepts_only_when_both_are_absent(self):
        engine = object.__new__(DockerEngine)
        engine._find = Mock(return_value=None)
        engine._find_proxy_sidecar = Mock(return_value=None)
        self.assertIsNone(engine.assert_purge_runtime_absent('b' * 32))

    def test_rejects_gateway_and_propagates_inconclusive_lookup(self):
        engine = object.__new__(DockerEngine)
        engine._find = Mock(return_value={'Id': 'a' * 64})
        engine._find_proxy_sidecar = Mock(return_value=None)
        with self.assertRaises(DockerEngineError):
            engine.assert_purge_runtime_absent('b' * 32)
        engine._find.return_value = None
        engine._find_proxy_sidecar.side_effect = DockerEngineError('unavailable')
        with self.assertRaises(DockerEngineError):
            engine.assert_purge_runtime_absent('b' * 32)
