import json
import os
import threading
import unittest
from dataclasses import asdict
from unittest.mock import Mock, patch

from supervisor.ollama_config import validate_ollama_config
from supervisor.openclaw_config import build_gateway_config
from supervisor.runtime_store import canonical
from supervisor.service import RuntimeService, ServiceError

OLD = {'base_url': 'http://10.99.0.10:11434', 'default_model_id': 'qwen3.5:9b',
       'context_tokens': 8192, 'max_tokens': 512, 'think': False}
NEW = 'hf.co/DavidAU/Qwen3.5-9B-The-Defiant-Fable-Uncensored-Heretic-NEO-IMATRIX-MAX-MTP-GGUF:Q4_K_M'


class ModelChangeImmutableTests(unittest.TestCase):
    def setup_service(self, *, already_new=False):
        service = RuntimeService.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.ollama_config = OLD.copy()
        service.sidecar_migration = None
        service.store = Mock()
        service.store.ollama_model_id.return_value = OLD['default_model_id']
        instance = {'id': 'x', 'initialized': True, 'storage': True, 'state': 'stopped',
                    'active': False, 'desired_state': 'stopped'}
        service.store.all_instances.return_value = [instance]
        service._inspect = Mock(return_value={'state': 'absent'})
        service._absent = Mock(return_value=True)
        service._storage = Mock(return_value={})
        policy = asdict(validate_ollama_config({**OLD, 'default_model_id': NEW})) if already_new else OLD
        config = build_gateway_config({'id': 'x', 'actor': 'alice', 'network_profile': 'legacy_none',
                                       'gateway_token': 'T' * 43}, ollama=policy)
        state = {'blob': (canonical(config) + '\n').encode(), 'immutable': not already_new}
        def read(_evidence, *, require_immutable, with_bytes=False):
            if require_immutable and not state['immutable']:
                raise ServiceError('model_policy_unverified', 503)
            value = json.loads(state['blob'])
            return (value, state['blob']) if with_bytes else value
        service._read_managed_gateway_config = read
        service._open_gateway_state_fd = lambda _evidence: os.open(os.devnull, os.O_RDONLY)
        service.reconcile = Mock()
        return service, state

    def test_retry_unlocked_new_bytes_never_commits_or_restarts(self):
        service, state = self.setup_service(already_new=True)
        with self.assertRaises(ServiceError):
            service.change_ollama_model({'expected_model_id': OLD['default_model_id'], 'new_model_id': NEW})
        service.store.update_ollama_model_id.assert_not_called()
        service.reconcile.assert_not_called()

    def test_replacement_returning_unlocked_new_bytes_never_commits(self):
        service, state = self.setup_service()
        def replace(_fd, _expected, replacement):
            state['blob'] = replacement
            state['immutable'] = False
        with patch('supervisor.service.replace_locked_config_at', side_effect=replace):
            with self.assertRaises(ServiceError):
                service.change_ollama_model({'expected_model_id': OLD['default_model_id'], 'new_model_id': NEW})
        service.store.update_ollama_model_id.assert_not_called()
        service.reconcile.assert_not_called()

    def test_lock_lost_during_db_commit_does_not_restart_or_report_success(self):
        service, state = self.setup_service()
        def replace(_fd, _expected, replacement):
            state['blob'] = replacement
        def commit(*_args):
            state['immutable'] = False
            service.store.ollama_model_id.return_value = NEW
        service.store.update_ollama_model_id.side_effect = commit
        with patch('supervisor.service.replace_locked_config_at', side_effect=replace):
            with self.assertRaises(ServiceError):
                service.change_ollama_model({'expected_model_id': OLD['default_model_id'], 'new_model_id': NEW})
        service.reconcile.assert_not_called()

    def test_failed_replacement_with_unlocked_old_bytes_never_reconciles(self):
        service, state = self.setup_service()
        def fail(*args):
            state['immutable'] = False
            raise OSError('ambiguous replacement')
        with patch('supervisor.service.replace_locked_config_at', side_effect=fail):
            with self.assertRaises(ServiceError) as caught:
                service.change_ollama_model({'expected_model_id': OLD['default_model_id'], 'new_model_id': NEW})
        self.assertEqual(caught.exception.code, 'model_policy_unverified')
        service.store.update_ollama_model_id.assert_not_called()
        service.reconcile.assert_not_called()
