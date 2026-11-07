import hashlib
import threading
import tempfile
import unittest
from pathlib import Path

from supervisor.runtime_store import RuntimeStore, canonical
from supervisor.control_ui_migration import ControlUiSidecarMigration, MigrationError


class FakeStore:
    def all_instances(self):
        return [
            {'id': 'a' * 32, 'actor': 'alice', 'active': 1,
             'network_profile': RuntimeStore.NETWORK_PROFILE_PROXY},
            {'id': 'b' * 32, 'actor': 'bob', 'active': 0,
             'network_profile': RuntimeStore.NETWORK_PROFILE_PROXY},
            {'id': 'c' * 32, 'actor': 'carol', 'active': 1,
             'network_profile': RuntimeStore.NETWORK_PROFILE_LEGACY},
        ]

    def instance(self, instance_id):
        return {
            'id': instance_id, 'actor': 'alice', 'active': 1,
            'network_profile': RuntimeStore.NETWORK_PROFILE_PROXY,
            'container_id': 'a' * 64,
            'storage': canonical({'host_path': '/srv/agents/' + instance_id}),
        }


class FakeEngine:
    def __init__(self):
        self.seen_instances = None
        self.plan_value = {
            'version': 1,
            'webui': {'container_id': 'd' * 64, 'image_id': 'sha256:' + 'e' * 64},
            'items': [], 'blockers': [],
            'summary': {'discovered': 0, 'needs_migration': 0, 'blocked': 0},
        }
        self.prepared = []
        self.migration_calls = 0
        self.rollback_calls = 0
        self.interrupt_once = False
        self.fail_once = False

    def plan_control_ui_sidecar_migration(self, instances, domain):
        self.seen_instances = instances
        self.seen_domain = domain
        return {'public': self.plan_value, 'prepared': self.prepared}

    def migrate_control_ui_sidecar(self, item, checkpoint):
        self.migration_calls += 1
        if self.interrupt_once:
            self.interrupt_once = False
            checkpoint('old_removed')
            raise SystemExit('synthetic process interruption')
        if self.fail_once:
            self.fail_once = False
            checkpoint('new_running', new_sidecar_id='f' * 64)
            raise RuntimeError('synthetic healthcheck failure')
        checkpoint('complete', new_sidecar_id='f' * 64, result='verified')
        return {'gateway_id': 'a' * 64, 'sidecar_id': 'f' * 64}

    def rollback_control_ui_sidecar(self, item, checkpoint):
        self.rollback_calls += 1
        checkpoint('rolled_back', result='old_sidecar_restored_control_ui_closed')
        return {'gateway_id': 'a' * 64, 'sidecar_id': 'b' * 64}


def configure_one_item_plan(engine):
    instance_id = 'a' * 32
    engine.plan_value['items'] = [{
        'instance_id': instance_id, 'action': 'replace',
        'old_image_id': 'sha256:' + 'b' * 64,
        'target_image_id': 'sha256:' + 'e' * 64,
    }]
    engine.plan_value['summary'] = {
        'discovered': 1, 'needs_migration': 1, 'blocked': 0}
    engine.prepared = [{
        'instance_id': instance_id, 'owner_id': 'alice',
        'gateway_id': 'a' * 64, 'gateway_image_id': 'sha256:' + '1' * 64,
        'old_sidecar_id': 'b' * 64, 'old_image_id': 'sha256:' + '2' * 64,
        'target_image_id': 'sha256:' + 'e' * 64,
        'agent_network_id': 'c' * 64, 'frontend_network_id': '7' * 64,
        'gateway_ip': '10.0.0.3', 'sidecar_agent_ip': '10.0.0.2',
        'sidecar_frontend_ip': '10.1.0.3', 'web_ip': '10.1.0.2',
        'action': 'replace', 'gateway_spec': {
            'version': 3, 'owner_id': 'alice',
            'host_path': '/srv/agents/' + instance_id,
            'control_ui_origin': f'https://{instance_id}.agents.example.test',
        },
        'gateway_spec_sha256': '1' * 64,
        'gateway_live_sha256': '4' * 64,
        'old_sidecar_spec': {'image_id': 'sha256:' + '2' * 64},
        'old_sidecar_config_sha256': '2' * 64,
        'target_sidecar_spec': {'image_id': 'sha256:' + 'e' * 64},
        'target_sidecar_config_sha256': '3' * 64,
        'network_plan': {'agent': {}, 'frontend': {}},
        'network_ids': {'agent': 'c' * 64, 'frontend': '7' * 64},
        'web_container_id': 'd' * 64, 'sidecar_was_running': True,
    }]


class ControlUiMigrationCoordinatorTests(unittest.TestCase):
    def test_plan_is_read_only_and_only_includes_active_proxy_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = FakeEngine()
            journal = Path(tmp) / 'sidecar-migration.json'
            coordinator = ControlUiSidecarMigration(
                engine, FakeStore(), 'agents.example.test', journal, threading.RLock(),
                require_root_owned=False)

            result = coordinator.handle({'action': 'plan'})

            self.assertEqual([item['id'] for item in engine.seen_instances], ['a' * 32])
            self.assertEqual(engine.seen_domain, 'agents.example.test')
            self.assertEqual(result['plan_sha256'], hashlib.sha256(
                canonical(engine.plan_value).encode('ascii')).hexdigest())
            self.assertFalse(journal.exists())

    def test_apply_is_plan_bound_durable_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = FakeEngine()
            configure_one_item_plan(engine)
            journal = Path(tmp) / 'sidecar-migration.json'
            coordinator = ControlUiSidecarMigration(
                engine, FakeStore(), 'agents.example.test', journal, threading.RLock(),
                require_root_owned=False)
            plan = coordinator.handle({'action': 'plan'})

            with self.assertRaises(MigrationError):
                coordinator.handle({'action': 'apply', 'plan_sha256': '0' * 64})
            self.assertEqual(engine.migration_calls, 0)

            result = coordinator.handle({'action': 'apply', 'plan_sha256': plan['plan_sha256']})

            self.assertEqual(result['status'], 'completed')
            self.assertTrue(journal.is_file())
            self.assertEqual(engine.migration_calls, 1)
            again = coordinator.handle({'action': 'apply', 'plan_sha256': plan['plan_sha256']})
            self.assertEqual(again['status'], 'completed')
            self.assertEqual(engine.migration_calls, 1)
            self.assertEqual(coordinator.handle({'action': 'status'})['status'], 'completed')

    def test_resume_continues_from_the_durable_last_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = FakeEngine()
            configure_one_item_plan(engine)
            engine.interrupt_once = True
            journal = Path(tmp) / 'sidecar-migration.json'
            coordinator = ControlUiSidecarMigration(
                engine, FakeStore(), 'agents.example.test', journal, threading.RLock(),
                require_root_owned=False)
            plan = coordinator.handle({'action': 'plan'})

            with self.assertRaises(SystemExit):
                coordinator.handle({'action': 'apply', 'plan_sha256': plan['plan_sha256']})

            interrupted = coordinator.handle({'action': 'status'})
            self.assertEqual(interrupted['status'], 'in_progress')
            self.assertEqual(interrupted['items'][0]['stage'], 'old_removed')
            self.assertEqual(coordinator.in_progress_instances(), {'a' * 32})

            resumed = coordinator.handle({'action': 'resume'})

            self.assertEqual(resumed['status'], 'completed')
            self.assertEqual(engine.migration_calls, 2)
            self.assertEqual(engine.rollback_calls, 0)

    def test_apply_failure_rolls_back_and_keeps_control_ui_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = FakeEngine()
            configure_one_item_plan(engine)
            engine.fail_once = True
            coordinator = ControlUiSidecarMigration(
                engine, FakeStore(), 'agents.example.test',
                Path(tmp) / 'sidecar-migration.json', threading.RLock(),
                require_root_owned=False)
            plan = coordinator.handle({'action': 'plan'})

            result = coordinator.handle({'action': 'apply', 'plan_sha256': plan['plan_sha256']})

            self.assertEqual(result['status'], 'rolled_back')
            self.assertEqual(result['mode'], 'rollback')
            self.assertEqual(result['last_error'], 'migration_step_failed')
            self.assertEqual(result['items'][0]['stage'], 'rolled_back')
            self.assertEqual(result['items'][0]['result'],
                             'old_sidecar_restored_control_ui_closed')
            self.assertEqual(engine.rollback_calls, 1)

    def test_needs_attention_only_gates_items_that_are_not_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = FakeEngine()
            configure_one_item_plan(engine)
            journal_path = Path(tmp) / 'sidecar-migration.json'
            coordinator = ControlUiSidecarMigration(
                engine, FakeStore(), 'agents.example.test', journal_path, threading.RLock(),
                require_root_owned=False)
            plan = coordinator.handle({'action': 'plan'})
            template = engine.prepared[0]
            items = []
            for instance_id, stage, result, suffix in (
                    ('a' * 32, 'complete', 'verified', '1'),
                    ('b' * 32, 'rolled_back', 'old_sidecar_restored_control_ui_closed', '2'),
                    ('c' * 32, 'planned', None, '3')):
                item = dict(template)
                item['instance_id'] = instance_id
                item['owner_id'] = 'owner-' + suffix
                item['gateway_id'] = suffix * 64
                item['old_sidecar_id'] = ('4' if suffix == '1' else '5' if suffix == '2' else '6') * 64
                item['agent_network_id'] = ('7' if suffix == '1' else '8' if suffix == '2' else '9') * 64
                item['frontend_network_id'] = ('a' if suffix == '1' else 'b' if suffix == '2' else 'c') * 64
                item['gateway_spec'] = dict(template['gateway_spec'], owner_id='owner-' + suffix)
                item['stage'] = stage
                item['result'] = result
                items.append(item)
            now = 1_700_000_000
            coordinator._write_journal({
                'version': coordinator.JOURNAL_VERSION,
                'operation_id': 'f' * 32,
                'status': 'needs_attention', 'mode': 'apply',
                'plan_sha256': plan['plan_sha256'],
                'target_web': {'container_id': 'd' * 64,
                               'image_id': 'sha256:' + 'e' * 64},
                'created_at': now, 'updated_at': now,
                'items': items, 'last_error': 'migration_step_failed',
            })

            self.assertEqual(coordinator.in_progress_instances(), {'c' * 32})

    def test_admin_payload_cannot_select_image_or_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = ControlUiSidecarMigration(
                FakeEngine(), FakeStore(), 'agents.example.test',
                Path(tmp) / 'sidecar-migration.json', threading.RLock(),
                require_root_owned=False)

            with self.assertRaises(MigrationError):
                coordinator.handle({'action': 'plan', 'image_id': 'sha256:' + 'f' * 64})

            with self.assertRaises(MigrationError):
                coordinator.handle({'action': 'apply', 'plan_sha256': '0' * 64,
                                    'instance_id': 'a' * 32})


if __name__ == '__main__':
    unittest.main()
