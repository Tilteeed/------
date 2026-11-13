import hashlib
import json
import os
import stat
import sys
import types
import unittest
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

from supervisor.firewall_acceptance import (
    build_firewall_acceptance_receipt,
    firewall_acceptance_receipt_matches,
    load_firewall_acceptance_receipt,
)


class FirewallAcceptanceReceiptTests(unittest.TestCase):
    HOST = 'a' * 64
    AGENT_POOL = '10.246.0.0/24'
    FRONTEND_POOL = '10.247.0.0/24'

    def receipt(self):
        return build_firewall_acceptance_receipt(
            self.HOST, self.AGENT_POOL, self.FRONTEND_POOL, accepted_at_unix=123)

    def test_receipt_matches_host_policy_version_and_exact_pools(self):
        self.assertTrue(firewall_acceptance_receipt_matches(
            self.receipt(), self.HOST, self.AGENT_POOL, self.FRONTEND_POOL))

    def test_receipt_does_not_transfer_to_another_host(self):
        self.assertFalse(firewall_acceptance_receipt_matches(
            self.receipt(), 'b' * 64, self.AGENT_POOL, self.FRONTEND_POOL))

    def test_receipt_rejects_policy_pool_or_acceptance_check_drift(self):
        for field, value in (
            ('policy_version', 2),
            ('agent_network_pool', '10.250.0.0/24'),
            ('frontend_network_pool', '10.251.0.0/24'),
            ('checks', ['linux_proxy_isolated_check']),
        ):
            with self.subTest(field=field):
                receipt = self.receipt()
                receipt[field] = value
                self.assertFalse(firewall_acceptance_receipt_matches(
                    receipt, self.HOST, self.AGENT_POOL, self.FRONTEND_POOL))

    def test_receipt_schema_is_strict(self):
        receipt = self.receipt()
        receipt['unexpected'] = True
        self.assertFalse(firewall_acceptance_receipt_matches(
            receipt, self.HOST, self.AGENT_POOL, self.FRONTEND_POOL))
        receipt = self.receipt()
        receipt['schema_version'] = True
        self.assertFalse(firewall_acceptance_receipt_matches(
            receipt, self.HOST, self.AGENT_POOL, self.FRONTEND_POOL))

    def test_receipt_builder_rejects_invalid_or_overlapping_pools(self):
        for agent, frontend in (
            ('10.246.0.1/24', '10.247.0.0/24'),
            ('10.246.0.0/24', '10.246.0.0/24'),
            ('192.0.2.0/24', '10.247.0.0/24'),
            ('10.246.0.0/23', '10.246.1.0/24'),
        ):
            with self.subTest(agent=agent, frontend=frontend):
                with self.assertRaises(ValueError):
                    build_firewall_acceptance_receipt(
                        self.HOST, agent, frontend, accepted_at_unix=123)

    def test_receipt_builder_requires_a_canonical_host_digest_and_time(self):
        with self.assertRaises(ValueError):
            build_firewall_acceptance_receipt('not-a-digest', self.AGENT_POOL,
                                              self.FRONTEND_POOL, accepted_at_unix=123)
        with self.assertRaises(ValueError):
            build_firewall_acceptance_receipt(self.HOST, self.AGENT_POOL,
                                              self.FRONTEND_POOL, accepted_at_unix=True)

    def test_machine_id_is_hashed_and_never_returned_raw(self):
        from supervisor import firewall_acceptance as acceptance
        machine_id = '0123456789abcdef0123456789abcdef'
        info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0,
            st_nlink=1, st_size=32)
        with patch.object(acceptance.os, 'O_NOFOLLOW', 0x20000, create=True), \
                patch.object(acceptance.os, 'open', return_value=9), \
                patch.object(acceptance.os, 'fstat', return_value=info), \
                patch.object(acceptance.os, 'read', return_value=machine_id.encode()), \
                patch.object(acceptance.os, 'close'):
            digest = acceptance.machine_id_sha256('/etc/machine-id')
        self.assertEqual(digest, hashlib.sha256(machine_id.encode()).hexdigest())
        self.assertNotEqual(digest, machine_id)

    def test_receipt_reader_rejects_untrusted_owner_permissions_and_links(self):
        from supervisor import firewall_acceptance as acceptance
        blob = json.dumps(self.receipt()).encode('utf-8')
        valid = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
            st_nlink=1, st_size=len(blob))
        with patch.object(acceptance.os, 'open', return_value=9), \
                patch.object(acceptance.os, 'fstat', return_value=valid), \
                patch.object(acceptance.os, 'read', return_value=blob), \
                patch.object(acceptance.os, 'close'):
            self.assertEqual(acceptance._read_receipt(7), self.receipt())
        for overrides in (
            {'st_uid': 1000}, {'st_gid': 1000}, {'st_mode': stat.S_IFREG | 0o640},
            {'st_nlink': 2}, {'st_size': 4097},
        ):
            with self.subTest(overrides=overrides):
                attrs = vars(valid).copy()
                attrs.update(overrides)
                invalid = SimpleNamespace(**attrs)
                with patch.object(acceptance.os, 'open', return_value=9), \
                        patch.object(acceptance.os, 'fstat', return_value=invalid), \
                        patch.object(acceptance.os, 'read', return_value=blob), \
                        patch.object(acceptance.os, 'close'):
                    with self.assertRaises(ValueError):
                        acceptance._read_receipt(7)

    def test_receipt_reader_rejects_duplicate_json_keys(self):
        from supervisor import firewall_acceptance as acceptance
        blob = b'{"schema_version":1,"schema_version":1}'
        info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
            st_nlink=1, st_size=len(blob))
        with patch.object(acceptance.os, 'open', return_value=9), \
                patch.object(acceptance.os, 'fstat', return_value=info), \
                patch.object(acceptance.os, 'read', return_value=blob), \
                patch.object(acceptance.os, 'close'):
            with self.assertRaises(ValueError):
                acceptance._read_receipt(7)

    def test_receipt_writer_uses_private_atomic_root_owned_file(self):
        from supervisor import firewall_acceptance as acceptance
        written = bytearray()
        opened = []
        replaced = []
        def fake_open(name, flags, mode=0o777, *, dir_fd=None):
            opened.append((name, flags, mode, dir_fd))
            return 11
        def fake_write(_fd, data):
            written.extend(data)
            return len(data)
        with patch.object(acceptance, 'machine_id_sha256', return_value=self.HOST), \
                patch.object(acceptance, '_open_state_directory', return_value=10), \
                patch.object(acceptance.os, 'open', side_effect=fake_open), \
                patch.object(acceptance.os, 'fchown', create=True) as fchown, \
                patch.object(acceptance.os, 'fchmod', create=True) as fchmod, \
                patch.object(acceptance.os, 'write', side_effect=fake_write), \
                patch.object(acceptance.os, 'fsync'), \
                patch.object(acceptance.os, 'close'), \
                patch.object(acceptance.os, 'replace', side_effect=lambda *a, **k: replaced.append((a, k))), \
                patch.object(acceptance.os, 'unlink'):
            result = acceptance.write_firewall_acceptance_receipt(
                '/var/lib/personal-agent-supervisor', self.AGENT_POOL, self.FRONTEND_POOL,
                expected_host_id_sha256=self.HOST)
        self.assertEqual(result, Path('/var/lib/personal-agent-supervisor') /
                         acceptance.RECEIPT_FILENAME)
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0][0].startswith('.firewall-acceptance-'), True)
        self.assertEqual(opened[0][2], 0o600)
        self.assertEqual(opened[0][3], 10)
        self.assertTrue(opened[0][1] & os.O_EXCL)
        fchown.assert_called_once_with(11, 0, 0)
        fchmod.assert_called_once_with(11, 0o600)
        self.assertEqual(len(replaced), 1)
        payload = json.loads(written.decode('utf-8'))
        self.assertTrue(firewall_acceptance_receipt_matches(
            payload, self.HOST, self.AGENT_POOL, self.FRONTEND_POOL))

    def test_receipt_loader_requires_current_host_and_runtime_pools(self):
        from supervisor import firewall_acceptance as acceptance
        receipt = self.receipt()
        with patch.object(acceptance, 'machine_id_sha256', return_value=self.HOST), \
                patch.object(acceptance, '_open_state_directory', return_value=123), \
                patch.object(acceptance, '_read_receipt', return_value=receipt), \
                patch.object(acceptance.os, 'close'):
            self.assertTrue(load_firewall_acceptance_receipt(
                '/var/lib/personal-agent-supervisor', self.AGENT_POOL, self.FRONTEND_POOL))
            self.assertFalse(load_firewall_acceptance_receipt(
                '/var/lib/personal-agent-supervisor', '10.250.0.0/24', self.FRONTEND_POOL))

    def test_receipt_loader_fails_closed_when_machine_identity_is_unavailable(self):
        from supervisor import firewall_acceptance as acceptance
        with patch.object(acceptance, 'machine_id_sha256', side_effect=OSError('synthetic')):
            self.assertFalse(load_firewall_acceptance_receipt(
                '/var/lib/personal-agent-supervisor', self.AGENT_POOL, self.FRONTEND_POOL))

    def test_linux_precheck_forwards_the_same_explicit_pools_into_netns(self):
        from scripts import linux_proxy_isolated_check as precheck
        argv = ['--agent-pool', self.AGENT_POOL, '--frontend-pool', self.FRONTEND_POOL,
                '--execute', '--confirm-disposable-host']
        # The public wrapper now delegates to the guarded private namespace
        # transport. No removed host-network helper is resurrected for a test.
        with patch.object(precheck, 'private_main', return_value=0) as private:
            self.assertEqual(precheck.main(argv), 0)
        forwarded = private.call_args.args[0]
        self.assertEqual(forwarded[forwarded.index('--agent-pool') + 1], self.AGENT_POOL)
        self.assertEqual(forwarded[forwarded.index('--frontend-pool') + 1], self.FRONTEND_POOL)
        self.assertEqual(private.call_args.kwargs, {'docker': False})

    def test_linux_precheck_passes_explicit_pools_to_namespace_runner(self):
        from scripts import linux_proxy_isolated_check as precheck
        argv = ['--agent-pool', self.AGENT_POOL, '--frontend-pool', self.FRONTEND_POOL,
                '--execute', '--confirm-disposable-host']
        with patch.object(precheck, 'private_main', return_value=1) as private:
            self.assertEqual(precheck.main(argv), 1)
        private.assert_called_once_with(argv, docker=False)

    def test_activation_script_records_receipt_only_after_both_checks_pass(self):
        from supervisor.tests.test_activate_agent_proxy import SyntheticActivationTests
        synthetic = SyntheticActivationTests(methodName='runTest')
        status, commands, writer, archive = synthetic.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(len(commands), 2)
        writer.assert_called_once()
        requested = synthetic.argv()
        for command in commands:
            for flag in ('--agent-pool', '--frontend-pool'):
                self.assertEqual(command[command.index(flag) + 1], requested[requested.index(flag) + 1])
            self.assertIn('--execute', command)
            self.assertIn('--confirm-disposable-host', command)
        self.assertEqual(commands[1][commands[1].index('--image-archive') + 1], archive)

    def test_activation_script_never_records_receipt_after_a_failed_check(self):
        from supervisor.tests.test_activate_agent_proxy import SyntheticActivationTests
        synthetic = SyntheticActivationTests(methodName='runTest')
        def failed_second_check(report, index):
            if index == 1:
                report['cleanup'] = False
        status, commands, writer, _ = synthetic.invoke(mutate=failed_second_check)
        self.assertEqual(status, 1)
        self.assertEqual(len(commands), 2)
        writer.assert_not_called()

    def test_configure_requires_receipt_before_selecting_agent_proxy_default(self):
        from scripts.configure_supervisor import validate_network_activation
        with patch('scripts.configure_supervisor.load_firewall_acceptance_receipt',
                   return_value=False) as load_receipt:
            with self.assertRaisesRegex(ValueError, 'acceptance receipt'):
                validate_network_activation(
                    'agent_proxy_v1', 'agents.example.test', self.AGENT_POOL,
                    self.FRONTEND_POOL, '/var/lib/personal-agent-supervisor')
        load_receipt.assert_called_once_with(
            '/var/lib/personal-agent-supervisor', self.AGENT_POOL, self.FRONTEND_POOL)

    def test_configure_accepts_agent_proxy_only_for_matching_host_receipt(self):
        from scripts.configure_supervisor import validate_network_activation
        with patch('scripts.configure_supervisor.load_firewall_acceptance_receipt',
                   return_value=True):
            validate_network_activation(
                'agent_proxy_v1', 'agents.example.test', self.AGENT_POOL,
                self.FRONTEND_POOL, '/var/lib/personal-agent-supervisor')

    def test_configure_requires_route_receipt_before_enabling_ollama(self):
        from scripts.configure_supervisor import validate_network_activation
        policy = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b',
            'context_tokens': 8192, 'max_tokens': 512, 'think': False,
        }
        with patch('scripts.configure_supervisor.load_firewall_acceptance_receipt',
                   return_value=True), \
             patch('scripts.configure_supervisor.load_ollama_route_receipt',
                   return_value=False) as load_route:
            with self.assertRaisesRegex(ValueError, 'Ollama route acceptance receipt'):
                validate_network_activation(
                    'agent_proxy_v1', 'agents.example.test', self.AGENT_POOL,
                    self.FRONTEND_POOL, '/var/lib/personal-agent-supervisor',
                    policy, '172.20.0.0/16', 'ens18')
        load_route.assert_called_once_with(
            '/var/lib/personal-agent-supervisor', self.AGENT_POOL, self.FRONTEND_POOL,
            '172.20.0.0/16', '10.99.0.10', 'ens18')

    def test_configure_accepts_ollama_only_with_matching_route_receipt(self):
        from scripts.configure_supervisor import validate_network_activation
        policy = {
            'base_url': 'http://10.99.0.10:11434',
            'default_model_id': 'qwen3.5:9b',
            'context_tokens': 8192, 'max_tokens': 512, 'think': False,
        }
        with patch('scripts.configure_supervisor.load_firewall_acceptance_receipt',
                   return_value=True), \
             patch('scripts.configure_supervisor.load_ollama_route_receipt',
                   return_value=True) as load_route:
            validate_network_activation(
                'agent_proxy_v1', 'agents.example.test', self.AGENT_POOL,
                self.FRONTEND_POOL, '/var/lib/personal-agent-supervisor',
                policy, '172.20.0.0/16', 'ens18')
        load_route.assert_called_once_with(
            '/var/lib/personal-agent-supervisor', self.AGENT_POOL, self.FRONTEND_POOL,
            '172.20.0.0/16', '10.99.0.10', 'ens18')

    def test_configure_keeps_legacy_default_independent_of_receipt(self):
        from scripts.configure_supervisor import validate_network_activation
        with patch('scripts.configure_supervisor.load_firewall_acceptance_receipt') as load_receipt:
            validate_network_activation(
                'legacy_none', None, None, None, '/var/lib/personal-agent-supervisor')
        load_receipt.assert_not_called()

    def test_configure_rejects_agent_proxy_without_explicit_pools(self):
        from scripts.configure_supervisor import validate_network_activation
        with self.assertRaisesRegex(ValueError, 'both explicit pools'):
            validate_network_activation(
                'agent_proxy_v1', 'agents.example.test', None, None,
                '/var/lib/personal-agent-supervisor')

    def test_runtime_manager_stays_closed_without_receipt(self):
        from supervisor.service import _runtime_firewall
        config = {
            'state_dir': '/var/lib/personal-agent-supervisor',
            'agent_network_pool': self.AGENT_POOL,
            'frontend_network_pool': self.FRONTEND_POOL,
        }
        with patch('supervisor.firewall_acceptance.load_firewall_acceptance_receipt',
                   return_value=False) as load_receipt:
            manager = _runtime_firewall(config)
        self.assertFalse(manager.can_apply)
        load_receipt.assert_called_once_with(
            config['state_dir'], self.AGENT_POOL, self.FRONTEND_POOL)

    def test_runtime_ollama_firewall_uses_separate_route_receipt_and_table(self):
        from supervisor.firewall import NftablesAdapter
        from supervisor.ollama_firewall import TABLE_NAME
        from supervisor.service import _runtime_ollama_firewall
        config = {
            'state_dir': '/var/lib/personal-agent-supervisor',
            'agent_network_pool': self.AGENT_POOL,
            'frontend_network_pool': self.FRONTEND_POOL,
            'ollama_network_pool': '172.20.0.0/16',
            'ollama_egress_interface': 'ens18',
            'ollama': {
                'base_url': 'http://10.99.0.10:11434',
                'default_model_id': 'qwen3.5:9b',
                'context_tokens': 8192, 'max_tokens': 512, 'think': False,
            },
        }
        with patch('supervisor.ollama_firewall.load_ollama_route_receipt',
                   return_value=False) as load_receipt:
            manager = _runtime_ollama_firewall(config)
        assert manager is not None
        self.assertFalse(manager.can_apply)
        self.assertIsInstance(manager.adapter, NftablesAdapter)
        self.assertEqual(manager.adapter.table_name, TABLE_NAME)
        load_receipt.assert_called_once_with(
            config['state_dir'], self.AGENT_POOL, self.FRONTEND_POOL,
            config['ollama_network_pool'], '10.99.0.10', 'ens18')

    def test_runtime_manager_enables_only_when_receipt_validation_succeeds(self):
        from supervisor.service import _runtime_firewall
        config = {
            'state_dir': '/var/lib/personal-agent-supervisor',
            'agent_network_pool': self.AGENT_POOL,
            'frontend_network_pool': self.FRONTEND_POOL,
        }
        with patch('supervisor.firewall_acceptance.load_firewall_acceptance_receipt',
                   return_value=True):
            manager = _runtime_firewall(config)
        self.assertTrue(manager.can_apply)

    def test_serve_injects_receipt_gated_firewall_manager_into_docker_engine(self):
        from supervisor import firewall_acceptance as acceptance
        from supervisor import service
        from supervisor.firewall import FirewallManager

        config = {
            'profile_path': '/etc/personal-agent/profile.json',
            'state_dir': '/var/lib/personal-agent-supervisor',
            'socket_path': '/run/personal-agent/control.sock',
            'token_file': '/var/lib/personal-agent-supervisor/service.token',
            'image': 'sha256:' + 'a' * 64,
            'agent_network_pool': self.AGENT_POOL,
            'frontend_network_pool': self.FRONTEND_POOL,
        }
        profile = SimpleNamespace(storage=SimpleNamespace(mountpoint='/srv/pool'))

        class FakePath:
            def __init__(self, value):
                self.value = str(value)

            @property
            def parent(self):
                return FakePath(PurePosixPath(self.value).parent)

            @property
            def name(self):
                return PurePosixPath(self.value).name

            def __truediv__(self, child):
                return FakePath(PurePosixPath(self.value) / str(child))

            def __eq__(self, other):
                return type(other) is FakePath and self.value == other.value

            def __str__(self):
                return self.value

            def is_relative_to(self, _other):
                return False

            def lstat(self):
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)

            def resolve(self, *, strict=False):
                return self

            def is_symlink(self):
                return False

        class StopBeforeHostCheck(Exception):
            pass

        for receipt_state, accepted in (('valid', True), ('missing', False), ('invalid', False)):
            with self.subTest(receipt_state=receipt_state):
                captured = {}
                receipt = self.receipt()
                if receipt_state == 'invalid':
                    receipt['agent_network_pool'] = '10.250.0.0/24'

                class ProbeDockerEngine:
                    def __init__(self, *args, **kwargs):
                        captured['args'] = args
                        captured['kwargs'] = kwargs

                    def check_host(self):
                        raise StopBeforeHostCheck

                with ExitStack() as stack:
                    stack.enter_context(patch.dict(
                        sys.modules, {'fcntl': types.ModuleType('fcntl')}))
                    stack.enter_context(patch.object(service, 'Path', FakePath))
                    stack.enter_context(patch.object(
                        service, 'load_profile', return_value=profile))
                    stack.enter_context(patch.object(service, '_trusted_directory'))
                    stack.enter_context(patch.object(service.os, 'umask'))
                    stack.enter_context(patch.object(
                        service.os.path, 'lexists', return_value=False))
                    stack.enter_context(patch(
                        'supervisor.docker_engine.DockerEngine', ProbeDockerEngine))
                    stack.enter_context(patch.object(
                        acceptance, 'machine_id_sha256', return_value=self.HOST))
                    stack.enter_context(patch.object(
                        acceptance, '_open_state_directory', return_value=123))
                    if receipt_state == 'missing':
                        read_receipt = stack.enter_context(patch.object(
                            acceptance, '_read_receipt', side_effect=FileNotFoundError))
                    else:
                        read_receipt = stack.enter_context(patch.object(
                            acceptance, '_read_receipt', return_value=receipt))
                    stack.enter_context(patch.object(acceptance.os, 'close'))
                    with self.assertRaises(StopBeforeHostCheck):
                        service.serve(config)

                manager = captured['kwargs'].get('firewall')
                self.assertIsInstance(manager, FirewallManager)
                self.assertIs(manager.can_apply, accepted)
                self.assertEqual(captured['args'], (config['image'],))
                self.assertEqual(captured['kwargs']['agent_network_pool'], self.AGENT_POOL)
                self.assertEqual(captured['kwargs']['frontend_network_pool'], self.FRONTEND_POOL)
                read_receipt.assert_called_once_with(123)


if __name__ == '__main__':
    unittest.main()
