import io
import json
import unittest
from unittest.mock import patch

from supervisor import service


class InitializationPolicyTests(unittest.TestCase):
    def test_ollama_uses_immutable_managed_config(self):
        config = {'gateway': 'managed'}
        blob = (service.canonical(config) + '\n').encode()
        instance = {'settings': json.dumps({'name': 'A', 'instructions': 'B'})}
        with patch.object(service.os, 'O_DIRECTORY', 0, create=True), \
             patch.object(service.os, 'O_NOFOLLOW', 0, create=True), \
             patch.object(service.os, 'open', side_effect=[10, 11]), \
             patch.object(service.os, 'close'), \
             patch.object(service.os, 'fdopen', return_value=io.BytesIO(blob)), \
             patch.object(service, '_private_dir_at', side_effect=[12, 13]), \
             patch.object(service, 'build_gateway_config', return_value=config), \
             patch.object(service, '_initial_file') as initial, \
             patch.object(service, '_initial_managed_config_at') as managed:
            service.initialize_files(instance, {'host_path': 'unused'}, {'enabled': True})
        managed.assert_called_once_with(12, blob, require_immutable=True)
        self.assertNotIn('openclaw.json', [call.args[1] for call in initial.call_args_list])

    def test_legacy_uses_managed_config_without_immutable_requirement(self):
        config = {'gateway': 'legacy'}
        blob = (service.canonical(config) + '\n').encode()
        instance = {'settings': json.dumps({'name': 'A', 'instructions': 'B'})}
        with patch.object(service.os, 'O_DIRECTORY', 0, create=True), \
             patch.object(service.os, 'O_NOFOLLOW', 0, create=True), \
             patch.object(service.os, 'open', side_effect=[10, 11]), \
             patch.object(service.os, 'close'), \
             patch.object(service.os, 'fdopen', return_value=io.BytesIO(blob)), \
             patch.object(service, '_private_dir_at', side_effect=[12, 13]), \
             patch.object(service, 'build_gateway_config', return_value=config), \
             patch.object(service, '_initial_file') as initial, \
             patch.object(service, '_initial_managed_config_at') as managed:
            service.initialize_files(instance, {'host_path': 'unused'})
        managed.assert_called_once_with(12, blob, require_immutable=False)
        self.assertNotIn('openclaw.json', [call.args[1] for call in initial.call_args_list])


if __name__ == '__main__':
    unittest.main()
