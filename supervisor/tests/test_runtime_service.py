"""One portable workflow smoke; no Docker, mounts, or host mutation."""
import tempfile
import unittest
import threading
from contextlib import ExitStack, closing
from pathlib import Path


class DurableIntentSmoke(unittest.TestCase):
    def test_failed_stop_intent_is_durable_before_runtime_mutation(self):
        from supervisor.runtime_store import RuntimeStore
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.sqlite3'
            store = RuntimeStore(path, 'v1', 'a' * 64)
            payload = {'actor_id': 'alice', 'action': 'create', 'idempotency_key': 'one',
                       'settings_revision': 1, 'settings': {}}
            create = store.intent(payload, (1, 1, 1), (10, 10, 10))
            store.complete(create['id'], 'running', 'container')
            stop = store.intent(dict(payload, action='stop', idempotency_key='stop'),
                                (1, 1, 1), (10, 10, 10))
            store.fail(stop['id'], 'runtime_unavailable')
            store.close()
            reopened = RuntimeStore(path, 'v1', 'a' * 64)
            self.assertEqual(reopened.current('alice')['desired_state'], 'stopped')
            reopened.close()

    def test_replaying_failed_stop_clears_later_running_intent(self):
        from supervisor.runtime_store import RuntimeStore
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(Path(tmp) / 'runtime.sqlite3', 'v1', 'a' * 64)
            p = {'actor_id': 'alice', 'action': 'create', 'idempotency_key': 'create',
                 'settings_revision': 1, 'settings': {}}
            args = ((1, 1, 1), (10, 10, 10))
            created = store.intent(p, *args)
            store.complete(created['id'], 'running', 'container')
            stop = dict(p, action='stop', idempotency_key='stop')
            operation = store.intent(stop, *args)
            store.fail(operation['id'], 'runtime_unavailable')
            start = store.intent(dict(p, action='start', idempotency_key='start'), *args)
            store.complete(start['id'], 'running', 'container')
            store.intent(stop, *args)
            current = store.current('alice')
            store.close()
            self.assertEqual(current['desired_state'], 'stopped')

    def test_retained_disk_and_exact_replay(self):
        from supervisor.runtime_store import RuntimeStore, StoreError
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(Path(tmp) / 'runtime.sqlite3', 'v1', 'a' * 64)
            payload = {'actor_id': 'alice', 'action': 'create', 'idempotency_key': 'one',
                       'settings_revision': 1, 'settings': {'name': 'Agent', 'instructions': 'Hello'}}
            limits = (10, 20, 30)
            first = store.intent(payload, limits, (100, 100, 50))
            self.assertEqual(first['status'], 'pending')
            self.assertEqual(first['instance_id'], store.intent(payload, limits, (100, 100, 50))['instance_id'])
            changed = dict(payload, settings_revision=2)
            with self.assertRaises(StoreError):
                store.intent(changed, limits, (100, 100, 50))
            store.complete(first['id'], 'running', 'container')
            running_instance = store.current('alice')
            assert running_instance is not None
            self.assertEqual(running_instance['desired_state'], 'running')
            stop = dict(payload, action='stop', idempotency_key='stop')
            stopped = store.intent(stop, limits, (100, 100, 50))
            store.complete(stopped['id'], 'stopped', 'container')
            stopped_instance = store.current('alice')
            assert stopped_instance is not None
            self.assertEqual(stopped_instance['desired_state'], 'stopped')
            remove = dict(payload, action='remove', idempotency_key='remove')
            operation = store.intent(remove, limits, (100, 100, 50))
            store.complete(operation['id'], 'removed')
            self.assertIsNone(store.current('alice'))
            with self.assertRaises(StoreError):
                store.intent(dict(payload, idempotency_key='two'), limits, (100, 100, 50))
            self.assertEqual(store.intent(payload, limits, (100, 100, 50))['instance_id'], first['instance_id'])
            store.close()
            reopened = RuntimeStore(Path(tmp) / 'runtime.sqlite3', 'v1', 'a' * 64)
            self.assertEqual(reopened.totals(), (0, 0, 30))
            reopened.close()


class ServiceWorkflowSmoke(unittest.TestCase):
    def test_quota_failure_retry_same_id_and_retain(self):
        from supervisor.service import RuntimeService, ServiceError
        from supervisor.config import validate_profile
        from supervisor.runtime_store import RuntimeStore
        from dataclasses import asdict
        from types import SimpleNamespace
        import hashlib
        import json
        profile = validate_profile(dict(schema_version=1, profile_version='smoke', mode='lab',
            storage=dict(backend='xfs_project_quota', mountpoint='/srv/agents', expected_uuid='12345678-1234-1234-1234-123456789abc'),
            agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
        fingerprint = hashlib.sha256(json.dumps(asdict(profile), sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()

        class Metrics:
            def snapshot(self):
                return dict(sampled_at=100, cpu_window_seconds=60, total_ram_bytes=10**14,
                            available_ram_bytes=10**14, cpu_percent=0, free_disk_bytes=10**14,
                            total_cpu_millicores=1000000, total_disk_bytes=10**14)

        class Volumes:
            valid = False
            prepare_calls = 0
            def prepare(self, instance_id, disk_bytes):
                self.prepare_calls += 1
                workspace = Path(tmp) / instance_id / 'state' / 'workspace'
                workspace.mkdir(parents=True, exist_ok=True)
                marker = workspace / 'retained-data.txt'
                if not marker.exists():
                    marker.write_text('SYNTHETIC_RETAINED_DATA', encoding='utf-8')
                return self.verify(instance_id, disk_bytes)
            def verify(self, instance_id, disk_bytes):
                return dict(host_path=str(Path(tmp) / instance_id), project_id=1, disk_quota_verified=self.valid)
            def purge(self, instance_id, disk_bytes, expected_project_id=None):
                self.purge_calls += 1
                if self.purge_calls == 1:
                    raise OSError('synthetic incomplete purge')
                self.purged = True
                return dict(purged=True, project_id=expected_project_id or 1)
            purge_calls = 0
            purged = False

        class Engine:
            calls = []
            host_paths = []
            network_profiles = []
            state = 'absent'
            def inspect(self, instance_id):
                return dict(state=self.state, gateway='unknown',
                            container_id='c' if self.state != 'absent' else None,
                            **({'network_profile': self.network_profiles[-1] if self.network_profiles else 'legacy_none',
                                'config_policy_version': 1}
                               if self.state != 'absent' else {}))
            def create(self, instance_id, host_path, limits, token, *, network_profile='legacy_none'):
                self.calls.append(('create', instance_id))
                self.host_paths.append(host_path)
                self.network_profiles.append(network_profile)
                self.state = 'stopped'
                return 'c'
            def start(self, instance_id):
                self.calls.append(('start', instance_id))
                self.state = 'running'
            def stop(self, instance_id):
                self.state = 'stopped'
            def remove(self, instance_id):
                self.state = 'absent'

        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            store = stack.enter_context(closing(RuntimeStore(Path(tmp) / 'runtime.sqlite3', profile.profile_version, fingerprint)))
            volumes, engine = Volumes(), Engine()
            initialized = []
            service = RuntimeService(profile, store, volumes, engine, Metrics(),
                                     capacities=(10**14, 1000000, 10**14), disk_floor_bytes=0,
                                     clock=lambda: 100, initialize=lambda *args: initialized.append(args))
            payload = dict(actor_id='alice', action='create', idempotency_key='key',
                           settings_revision=0, settings=dict(name='Agent', instructions='Hello'))
            with self.assertRaises(ServiceError):
                service.action(payload)
            instance_id = store.current('alice')['id']
            self.assertEqual(engine.calls, [])
            volumes.valid = True
            result = service.action(payload)
            self.assertEqual(result['runtime']['state'], 'running')
            self.assertEqual(result['runtime']['instance_id'], instance_id)
            self.assertEqual(result['runtime']['network_profile'], 'legacy_none')
            self.assertEqual(engine.network_profiles[-1], 'legacy_none')
            self.assertIsNone(initialized[0][2])
            engine.network_profiles[-1] = 'agent_internal_v1'
            with self.assertRaises(ServiceError):
                service.me({'actor_id': 'alice'})
            engine.network_profiles[-1] = 'legacy_none'
            calls_before_replay = len(engine.calls)
            replayed = service.replay({'actor_id': 'alice', 'action': 'create',
                                       'idempotency_key': 'key', 'settings_revision': 0})
            self.assertEqual(replayed['runtime']['state'], 'running')
            self.assertEqual(len(engine.calls), calls_before_replay)
            action_payloads: list[dict] = [payload]
            for action, key, instructions in (
                    ('start', 'start-1', 'START_PRIVATE_INSTRUCTIONS'),
                    ('stop', 'stop-1', 'STOP_PRIVATE_INSTRUCTIONS')):
                request = dict(payload, action=action, idempotency_key=key,
                               settings={'name': 'Agent', 'instructions': instructions})
                service.action(request)
                action_payloads.append(request)
            remove_request = dict(payload, action='remove', idempotency_key='remove',
                                  settings={'name': 'Agent', 'instructions': 'REMOVE_PRIVATE_INSTRUCTIONS'})
            service.action(remove_request)
            action_payloads.append(remove_request)
            self.assertEqual(store.totals(), (0, 0, profile.agent_limits.disk_bytes))
            self.assertEqual([item['instance_id'] for item in store.retained('alice')], [instance_id])
            self.assertEqual(store.retained('bob'), [])
            store.db.execute('UPDATE instances SET network_profile=? WHERE id=?',
                             ('legacy_none', instance_id))
            replay = service.action(payload)
            self.assertEqual(replay['runtime']['state'], 'removed')
            self.assertEqual(len(engine.calls), 2)
            prepares_before_restore = volumes.prepare_calls
            restore_request = {key: value for key, value in payload.items() if key != 'settings'}
            restore_request.update(action='restore', idempotency_key='restore-1', instance_id=instance_id)
            calls_before_foreign_restore = list(engine.calls)
            foreign_restore = dict(restore_request, actor_id='bob', idempotency_key='restore-foreign')
            with self.assertRaises(ServiceError) as foreign_restore_error:
                service.action(foreign_restore)
            self.assertEqual(foreign_restore_error.exception.code, 'instance_not_found')
            self.assertEqual(volumes.prepare_calls, prepares_before_restore)
            self.assertEqual(engine.calls, calls_before_foreign_restore)
            volumes.valid = False
            with self.assertRaises(ServiceError) as restore_error:
                service.action(restore_request)
            self.assertEqual(restore_error.exception.code, 'quota_unverified')
            self.assertEqual(store.restore_retry(instance_id), {'key': 'restore-1', 'revision': 0})
            self.assertEqual(service.me({'actor_id': 'alice'})['runtime']['pending_restore_key'], 'restore-1')
            volumes.valid = True
            restored = service.replay({key: value for key, value in restore_request.items() if key != 'settings'})
            self.assertEqual(restored['runtime']['state'], 'running')
            self.assertEqual(restored['runtime']['instance_id'], instance_id)
            self.assertEqual(engine.network_profiles[-1], 'legacy_none')
            restore_operation = store.operation('alice', 'restore-1')
            assert restore_operation is not None
            self.assertNotIn('RESTORE_PRIVATE_INSTRUCTIONS', restore_operation['payload'])
            self.assertEqual(json.loads(restore_operation['payload']), {'redacted': True, 'replay': {
                'action': 'restore', 'settings_revision': 0, 'instance_id': instance_id}})
            self.assertEqual(volumes.prepare_calls, prepares_before_restore,
                             'Restoring a retained dataset must not allocate another volume')
            self.assertEqual(engine.host_paths[-1], engine.host_paths[0])
            marker = Path(engine.host_paths[-1]) / 'state' / 'workspace' / 'retained-data.txt'
            self.assertEqual(marker.read_text(encoding='utf-8'), 'SYNTHETIC_RETAINED_DATA')
            self.assertEqual(store.totals(), (profile.agent_limits.ram_bytes,
                                              profile.agent_limits.cpu_millicores,
                                              profile.agent_limits.disk_bytes))
            action_payloads.append(restore_request)
            remove_again = dict(payload, action='remove', idempotency_key='remove-2',
                                settings={'name': 'Agent', 'instructions': 'REMOVE_AGAIN_PRIVATE_INSTRUCTIONS'})
            service.action(remove_again)
            action_payloads.append(remove_again)
            self.assertEqual(store.totals(), (0, 0, profile.agent_limits.disk_bytes))
            purge = dict(payload, action='purge', idempotency_key='purge-1', instance_id=instance_id,
                         settings={'name': 'Agent', 'instructions': 'PURGE_PRIVATE_INSTRUCTIONS'})
            action_payloads.append(purge)
            foreign_purge = dict(purge, actor_id='bob', idempotency_key='foreign-purge')
            with self.assertRaises(ServiceError) as foreign_error:
                service.action(foreign_purge)
            self.assertEqual(foreign_error.exception.code, 'instance_not_found')
            self.assertEqual(volumes.purge_calls, 0, 'A foreign owner must not reach storage deletion')
            with self.assertRaises(ServiceError):
                service.action(purge)
            self.assertEqual(store.totals(), (0, 0, profile.agent_limits.disk_bytes),
                             'A failed volume purge must keep the retained disk reservation')
            self.assertFalse(volumes.purged)

            class BusyCheckpoint:
                def __init__(self, database):
                    self.database = database
                def execute(self, sql, *args):
                    if sql == 'PRAGMA wal_checkpoint(TRUNCATE)':
                        return SimpleNamespace(fetchone=lambda: (1, 1, 0))
                    return self.database.execute(sql, *args)
                def __getattr__(self, name):
                    return getattr(self.database, name)

            database = store.db
            setattr(store, 'db', BusyCheckpoint(database))
            try:
                with self.assertRaises(ServiceError) as checkpoint_error:
                    service.action(purge)
            finally:
                setattr(store, 'db', database)
            self.assertEqual(checkpoint_error.exception.code, 'purge_scrub_unverified')
            self.assertEqual(checkpoint_error.exception.status, 503)
            self.assertEqual(store.totals(), (0, 0, profile.agent_limits.disk_bytes),
                             'Do not release reservation before SQLite scrub is checkpointed')
            self.assertTrue(volumes.purged)
            self.assertEqual(store.purge_retry(instance_id), {'key': 'purge-1', 'revision': 0})
            self.assertEqual(store.retained('alice')[0]['pending_purge_key'], 'purge-1')

            result = service.replay({key: value for key, value in purge.items() if key != 'settings'})
            self.assertEqual(result['runtime']['state'], 'purged')
            self.assertEqual(store.totals(), (0, 0, 0), 'Release disk only after storage purge succeeds')
            self.assertTrue(volumes.purged)
            purged_instance = store.instance(instance_id)
            self.assertEqual(purged_instance['settings'], '{}')
            self.assertEqual(purged_instance['gateway_token'], '')
            self.assertIsNone(store.saved_request('alice', 'key'))
            operation_rows = list(store.db.execute(
                "SELECT action,payload FROM operations WHERE instance_id=? ORDER BY rowid", (instance_id,)))
            self.assertEqual([row['action'] for row in operation_rows],
                             ['create', 'start', 'stop', 'remove', 'restore', 'remove', 'purge'])
            self.assertEqual(len(action_payloads), len(operation_rows))
            for row, request in zip(operation_rows, action_payloads):
                instructions = request.get('settings', {}).get('instructions')
                if instructions:
                    self.assertNotIn(instructions, row['payload'], row['action'] + ' payload retained instructions')
                self.assertEqual(json.loads(row['payload']), {'redacted': True, 'replay': {
                    'action': request['action'], 'settings_revision': 0,
                    'instance_id': request.get('instance_id')}})
            redacted_record = json.loads(operation_rows[0]['payload'])
            self.assertEqual(redacted_record, {'redacted': True,
                'replay': {'action': 'create', 'settings_revision': 0, 'instance_id': None}})
            replayed_create = service.replay({key: value for key, value in payload.items()
                                              if key != 'settings'})
            self.assertEqual(replayed_create['runtime']['state'], 'purged')
            with self.assertRaises(ServiceError) as redacted_create:
                service.action(payload)
            self.assertEqual(redacted_create.exception.code, 'idempotency_conflict')
            calls_after_success = volumes.purge_calls
            replay = service.replay({key: value for key, value in purge.items()
                                     if key != 'settings'})
            self.assertEqual(replay['runtime']['state'], 'purged')
            self.assertEqual(volumes.purge_calls, calls_after_success, 'Exact replay must not repeat purge effects')


class SupervisorRestartRecoveryTests(unittest.TestCase):
    def test_reconcile_after_store_reopen_preserves_running_instance_and_reservations(self):
        import hashlib
        from dataclasses import asdict
        from supervisor.config import validate_profile
        from supervisor.runtime_store import RuntimeStore, canonical
        from supervisor.service import RuntimeService

        gib = 1024 ** 3
        profile = validate_profile(dict(schema_version=1, profile_version='restart-recovery-test', mode='lab',
            storage=dict(backend='xfs_project_quota', mountpoint='/mnt/recovery-test',
                         expected_uuid='11111111-2222-4333-8444-555555555555'),
            agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
        fingerprint = hashlib.sha256(canonical(asdict(profile)).encode('ascii')).hexdigest()
        capacities = (4*gib, 4000, 40*gib)

        class Metrics:
            def snapshot(self):
                return dict(sampled_at=100, cpu_window_seconds=60, total_ram_bytes=8*gib,
                            available_ram_bytes=7*gib, cpu_percent=5, free_disk_bytes=50*gib,
                            total_cpu_millicores=8000, total_disk_bytes=60*gib)

        class Volumes:
            def __init__(self, root):
                self.root = root
                self.prepare_calls = 0
                self.verify_calls = 0
            def prepare(self, instance_id, _disk_bytes):
                self.prepare_calls += 1
                workspace = self.root / instance_id / 'state' / 'workspace'
                workspace.mkdir(parents=True, exist_ok=True)
                (workspace / 'recovery-marker.txt').write_text('SYNTHETIC_RECOVERY_DATA', encoding='utf-8')
            def verify(self, instance_id, _disk_bytes):
                self.verify_calls += 1
                path = self.root / instance_id
                marker = path / 'state' / 'workspace' / 'recovery-marker.txt'
                return dict(host_path=str(path), project_id=17,
                            disk_quota_verified=marker.is_file())

        class Engine:
            def __init__(self, host_state, *, require_firewall=False):
                self.host_state = host_state
                self.network_profiles = {}
                self.calls = []
                self.require_firewall = require_firewall
                self.firewall_ready = False
            def inspect(self, instance_id):
                state = self.host_state.get(instance_id, 'absent')
                return dict(state=state, gateway='unknown',
                            container_id=('container-' + instance_id[:8]) if state != 'absent' else None,
                            **({'network_profile': self.network_profiles.get(instance_id, 'legacy_none')}
                               if state != 'absent' else {}))
            def create(self, instance_id, _host_path, _limits, _token, *, network_profile='legacy_none'):
                self.calls.append(('create', instance_id))
                self.network_profiles[instance_id] = network_profile
                self.host_state[instance_id] = 'stopped'
                return 'container-' + instance_id[:8]
            def restore_firewall(self):
                self.calls.append(('firewall_restore', None))
                self.firewall_ready = True
                return {'policy_count': 0, 'instance_ids': [], 'ready': True}
            def start(self, instance_id):
                if self.require_firewall and not self.firewall_ready:
                    raise AssertionError('network start preceded firewall read-back')
                self.calls.append(('start', instance_id))
                self.host_state[instance_id] = 'running'
            def stop(self, instance_id):
                self.calls.append(('stop', instance_id))
                self.host_state[instance_id] = 'stopped'
            def remove(self, instance_id):
                self.calls.append(('remove', instance_id))
                self.host_state[instance_id] = 'absent'

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'volumes'
            root.mkdir()
            db_path = Path(tmp) / 'runtime.sqlite3'
            host_state = {}
            volumes_before = Volumes(root)
            engine_before = Engine(host_state)
            store_before = RuntimeStore(db_path, profile.profile_version, fingerprint)
            try:
                service_before = RuntimeService(profile, store_before, volumes_before, engine_before, Metrics(),
                    capacities=capacities, disk_floor_bytes=0, clock=lambda: 100,
                    initialize=lambda *_args: None)
                request = {'actor_id': 'alice', 'action': 'create', 'idempotency_key': 'restart-create',
                           'settings_revision': 1,
                           'settings': {'name': 'Agent', 'instructions': 'keep this workspace'}}
                created = service_before.action(request)
                instance_id = created['runtime']['instance_id']
                self.assertEqual(created['runtime']['state'], 'running')
                original_instance = store_before.instance(instance_id)
                self.assertEqual(original_instance['desired_state'], 'running')
                original_totals = store_before.totals()
                original_container_id = original_instance['container_id']
            finally:
                store_before.close()

            # Docker RestartPolicy is `no`; after a host reboot the instance is
            # observed stopped although the last successful intent was running.
            host_state[instance_id] = 'stopped'
            store_after = RuntimeStore(db_path, profile.profile_version, fingerprint)
            try:
                volumes_after = Volumes(root)
                engine_after = Engine(host_state, require_firewall=True)
                service_after = RuntimeService(profile, store_after, volumes_after, engine_after, Metrics(),
                    capacities=capacities, disk_floor_bytes=0, clock=lambda: 100,
                    initialize=lambda *_args: None)
                service_after.reconcile()
                view = service_after.me({'actor_id': 'alice'})
                recovered = store_after.current('alice')
                assert recovered is not None
                self.assertEqual(view['runtime']['state'], 'running')
                self.assertEqual(view['runtime']['desired_state'], 'running')
                self.assertEqual(view['runtime']['instance_id'], instance_id)
                self.assertEqual(recovered['container_id'], original_container_id)
                self.assertEqual(recovered['desired_state'], 'running')
                self.assertEqual(store_after.totals(), original_totals)
                self.assertEqual(engine_after.calls, [
                    ('firewall_restore', None), ('start', instance_id),
                ], 'Recovery must verify firewall before starting, without recreating')
                self.assertEqual(volumes_after.prepare_calls, 0, 'Reconciliation must not re-prepare existing storage')
                self.assertGreater(volumes_after.verify_calls, 0)
                self.assertEqual((root / instance_id / 'state' / 'workspace' / 'recovery-marker.txt')
                                 .read_text(encoding='utf-8'), 'SYNTHETIC_RECOVERY_DATA')
                self.assertEqual(store_after.db.execute(
                    "SELECT count(*) FROM operations WHERE instance_id=? AND action='create'",
                    (instance_id,)).fetchone()[0], 1)
            finally:
                store_after.close()
    def test_reconcile_does_not_start_networked_instance_when_firewall_restore_fails(self):
        from supervisor.service import RuntimeService

        instance = {
            'id': 'd' * 32, 'active': 1, 'state': 'stopped',
            'desired_state': 'running', 'network_profile': 'agent_proxy_v1',
        }

        class Store:
            def all_instances(self):
                return [instance]
            def observe(self, _instance_id, state, _container_id):
                instance['state'] = state

        class Engine:
            def __init__(self):
                self.calls = []
            def restore_firewall(self):
                self.calls.append('restore_firewall')
                raise RuntimeError('synthetic firewall read-back failure')
            def start(self, _instance_id):
                self.calls.append('start')
                raise AssertionError('network start must be gated')
            def inspect(self, _instance_id):
                return {'state': 'stopped', 'gateway': 'unknown',
                        'container_id': 'container', 'network_profile': 'agent_proxy_v1'}

        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.store = Store()
        service.engine = Engine()
        service.sidecar_migration = None
        service._inspect = lambda instance_id: service.engine.inspect(instance_id)

        service.reconcile()

        self.assertEqual(service.engine.calls, ['restore_firewall'])
        self.assertEqual(instance['desired_state'], 'running')
        self.assertEqual(instance['state'], 'stopped')

    def test_reconcile_keeps_ollama_instance_stopped_when_route_receipt_is_unavailable(self):
        from supervisor.service import RuntimeService

        instance = {
            'id': 'f' * 32, 'active': 1, 'state': 'stopped',
            'desired_state': 'running', 'network_profile': 'agent_proxy_v1',
        }

        class Store:
            def __init__(self):
                self.observed = []
            def all_instances(self):
                return [instance]
            def observe(self, instance_id, state, container_id):
                self.observed.append((instance_id, state, container_id))
                instance['state'] = state

        class Engine:
            def __init__(self):
                self.calls = []
            def restore_firewall(self):
                self.calls.append('restore_firewall')
                return {'policy_count': 0, 'instance_ids': [instance['id']], 'ready': True}
            def inspect(self, instance_id):
                return {'state': 'stopped', 'gateway': 'not_ready',
                        'container_id': 'container', 'network_profile': 'agent_proxy_v1',
                        'config_policy_version': 1}
            def ensure_ollama_route(self, instance_id):
                self.calls.append(('ensure_ollama_route', instance_id))
                return {'ready': False}
            def start(self, instance_id):
                self.calls.append(('start', instance_id))
                raise AssertionError('Gateway must not start without accepted route')

        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.store = Store()
        service.engine = Engine()
        service.sidecar_migration = None
        service.ollama_config = {'default_model_id': 'qwen3.5:9b'}
        service._inspect = lambda instance_id: service.engine.inspect(instance_id)
        service.__dict__['_storage'] = lambda instance, *, prepare=False: {'disk_quota_verified': True}
        service.__dict__['_admit'] = lambda *, quota, preparing=False, requested_disk_bytes=None, network_profile=None: None
        service._ollama_policy_file_matches = lambda evidence: True

        service.reconcile()

        self.assertEqual(service.engine.calls, [
            'restore_firewall', ('ensure_ollama_route', instance['id']),
        ])
        self.assertEqual(instance['desired_state'], 'running')
        self.assertEqual(instance['state'], 'stopped')

    def test_reconcile_stops_legacy_container_when_ollama_config_policy_is_unverified(self):
        from supervisor.service import RuntimeService

        instance = {
            'id': 'e' * 32, 'active': 1, 'state': 'running',
            'desired_state': 'running', 'network_profile': 'legacy_none',
        }
        observed = {'state': 'running', 'gateway': 'ready', 'container_id': 'container',
                    'network_profile': 'legacy_none', 'config_policy_version': 0}

        class Store:
            def all_instances(self):
                return [instance]
            def observe(self, _instance_id, state, _container_id):
                instance['state'] = state

        class Engine:
            def __init__(self):
                self.calls = []
            def restore_firewall(self):
                self.calls.append('restore_firewall')
                return {'policy_count': 0, 'instance_ids': [], 'ready': True}
            def stop(self, _instance_id):
                self.calls.append('stop')
                observed['state'] = 'stopped'
            def inspect(self, _instance_id):
                return dict(observed)

        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.store = Store()
        service.engine = Engine()
        service.sidecar_migration = None
        service.ollama_config = {
            'base_url': 'http://10.99.0.10:11434', 'default_model_id': 'qwen3.5:9b',
            'context_tokens': 8192, 'max_tokens': 512, 'think': False,
        }
        service._inspect = lambda instance_id: service.engine.inspect(instance_id)

        service.reconcile()

        self.assertEqual(service.engine.calls, ['restore_firewall', 'stop'])
        self.assertEqual(instance['desired_state'], 'running')
        self.assertEqual(instance['state'], 'stopped')

    def test_fd_cleanup_recurses_only_through_open_directory_descriptors(self):
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch
        from supervisor.volumes import XfsVolumes

        directory = SimpleNamespace(st_dev=123, st_ino=456, st_mode=stat.S_IFDIR | 0o700)
        file_info = SimpleNamespace(st_dev=123, st_ino=789, st_mode=stat.S_IFREG | 0o600)

        class Entries:
            def __init__(self, names):
                self.names = names
            def __enter__(self):
                return [SimpleNamespace(name=name) for name in self.names]
            def __exit__(self, *_args):
                return False

        def scandir(fd):
            return Entries(['state'] if fd == 10 else ['private.txt'])

        def stat_at(name, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            return directory if dir_fd == 10 and name == 'state' else file_info

        with patch('supervisor.volumes.os.scandir', side_effect=scandir), \
             patch('supervisor.volumes.os.stat', side_effect=stat_at), \
             patch('supervisor.volumes.os.open', return_value=11) as open_child, \
             patch('supervisor.volumes.os.fstat', return_value=directory), \
             patch.object(XfsVolumes, '_mount_id', return_value=7), \
             patch('supervisor.volumes.os.unlink') as unlink, \
             patch('supervisor.volumes.os.rmdir') as rmdir, \
             patch('supervisor.volumes.os.fsync'), patch('supervisor.volumes.os.close'):
            XfsVolumes._clear_contents_fd(10, device=123, mount_id=7)

        self.assertEqual(open_child.call_args.kwargs['dir_fd'], 10)
        unlink.assert_called_once_with('private.txt', dir_fd=11)
        rmdir.assert_called_once_with('state', dir_fd=10)

    def test_fd_cleanup_refuses_directory_swapped_before_open(self):
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch
        from supervisor.volumes import XfsVolumes

        directory = SimpleNamespace(st_dev=123, st_ino=456, st_mode=stat.S_IFDIR | 0o700)

        class Entries:
            def __enter__(self):
                return [SimpleNamespace(name='victim')]
            def __exit__(self, *_args):
                return False

        nofollow = 0x20000
        directory_flag = 0x10000
        with patch('supervisor.volumes.os.O_NOFOLLOW', nofollow, create=True), \
             patch('supervisor.volumes.os.O_DIRECTORY', directory_flag, create=True), \
             patch('supervisor.volumes.os.scandir', return_value=Entries()), \
             patch('supervisor.volumes.os.stat', return_value=directory), \
             patch('supervisor.volumes.os.open', side_effect=OSError('O_NOFOLLOW rejected swapped symlink')) as open_child, \
             patch('supervisor.volumes.os.unlink') as unlink, patch('supervisor.volumes.os.rmdir') as rmdir:
            with self.assertRaises(OSError):
                XfsVolumes._clear_contents_fd(10, device=123, mount_id=7)
        self.assertEqual(open_child.call_args.kwargs['dir_fd'], 10)
        flags = open_child.call_args.args[1]
        self.assertTrue(flags & nofollow)
        self.assertTrue(flags & directory_flag)
        unlink.assert_not_called()
        rmdir.assert_not_called()

    def test_database_can_write_existing_file_without_create_and_readonly_verify_stays_readonly(self):
        import os
        import sqlite3
        import stat
        import sys
        from contextlib import closing
        from types import SimpleNamespace
        from unittest.mock import patch
        from supervisor.config import validate_profile
        from supervisor.volumes import XfsVolumes

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mount = base / 'mount'
            mount.mkdir()
            state_dir = base / 'service-state'
            state_dir.mkdir(mode=0o700)
            profile = validate_profile(dict(schema_version=1, profile_version='database-mode-test', mode='lab',
                storage=dict(backend='xfs_project_quota', mountpoint='/mnt/purge-test',
                             expected_uuid='11111111-2222-4333-8444-555555555555'),
                agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
            volumes = XfsVolumes(profile, state_dir)
            volumes.mountpoint = mount
            with closing(sqlite3.connect(volumes.db_path)) as db:
                with db:
                    db.execute("CREATE TABLE volume_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    binding = volumes.profile.storage.expected_uuid.lower() + ':' + str(mount)
                    db.execute("INSERT INTO volume_meta VALUES ('binding', ?)", (binding,))
                    db.execute('CREATE TABLE probe (value TEXT NOT NULL)')
                    db.execute("INSERT INTO probe VALUES ('before')")
            (state_dir / 'storage.lock').touch()
            fake_info = SimpleNamespace(st_dev=mount.stat().st_dev + 1,
                                        st_mode=stat.S_IFDIR | 0o700, st_uid=0)

            def open_private(path, _create):
                return os.open(path, os.O_RDONLY)

            fake_fcntl = SimpleNamespace(LOCK_EX=1, flock=lambda _fd, _operation: None)
            with patch.dict(sys.modules, {'fcntl': fake_fcntl}), \
                 patch.object(volumes, '_canonical', return_value=fake_info), \
                 patch.object(volumes, '_trusted_ancestors'), \
                 patch.object(volumes, '_private_file', side_effect=open_private):
                with volumes._database(create=False) as readonly:
                    with self.assertRaises(sqlite3.OperationalError):
                        readonly.execute("UPDATE probe SET value='must-not-write'")
                with volumes._database(create=False, writable=True) as writable:
                    writable.execute("UPDATE probe SET value='after'")
                missing = state_dir / 'must-not-be-created.sqlite3'
                volumes.db_path = missing
                with self.assertRaises(FileNotFoundError):
                    with volumes._database(create=False, writable=True):
                        pass
                self.assertFalse(missing.exists())

            with closing(sqlite3.connect(base / 'service-state' / 'storage.sqlite3')) as db:
                self.assertEqual(db.execute('SELECT value FROM probe').fetchone()[0], 'after')

    def test_purge_retries_partial_tree_cleanup_and_releases_only_recorded_project(self):
        import sqlite3
        import stat
        from types import SimpleNamespace
        from contextlib import closing, contextmanager
        from unittest.mock import patch
        from supervisor.config import validate_profile
        from supervisor.volumes import XfsVolumes

        instance_id = 'a' * 32
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mount = base / 'mount'
            root = mount / 'instances' / instance_id
            (root / 'state').mkdir(parents=True)
            marker = root / 'state' / 'private.txt'
            marker.write_text('owned data', encoding='utf-8')
            other = mount / 'instances' / ('b' * 32)
            other.mkdir()
            other_marker = other / 'keep.txt'
            other_marker.write_text('not this owner', encoding='utf-8')
            profile = validate_profile(dict(schema_version=1, profile_version='purge-test', mode='lab',
                storage=dict(backend='xfs_project_quota', mountpoint='/mnt/purge-test',
                             expected_uuid='11111111-2222-4333-8444-555555555555'),
                agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
            volumes = XfsVolumes(profile, base / 'service-state')
            volumes.mountpoint = mount
            volumes.instances = mount / 'instances'
            volumes.db_path.parent.mkdir()
            with closing(sqlite3.connect(volumes.db_path, isolation_level=None)) as db:
                db.row_factory = sqlite3.Row
                db.executescript('''
                    CREATE TABLE volume_projects (project_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        instance_id TEXT NOT NULL UNIQUE, disk_bytes INTEGER NOT NULL, stage TEXT NOT NULL);
                    CREATE TABLE volume_directories (path TEXT PRIMARY KEY, device INTEGER NOT NULL,
                        inode INTEGER NOT NULL, stage TEXT NOT NULL);
                ''')
                root_info = SimpleNamespace(st_dev=123, st_ino=456)
                db.execute('INSERT INTO volume_projects VALUES (?,?,?,?)', (42, instance_id, 4096, 'ready'))
                db.execute('INSERT INTO volume_directories VALUES (?,?,?,?)',
                           (root.relative_to(mount).as_posix(), root_info.st_dev, root_info.st_ino, 'ready'))

            @contextmanager
            def fake_database(create, *, writable=False):
                self.assertFalse(create)
                self.assertTrue(writable)
                connection = sqlite3.connect(volumes.db_path, isolation_level=None)
                connection.row_factory = sqlite3.Row
                try:
                    yield connection
                finally:
                    connection.close()

            quota_calls = []
            limits = iter([((0, 0, 4), (0, 0, 1024)),
                           ((0, 0, 4), (0, 0, 1024)),
                           ((0, 0, 4), (0, 0, 1024)), (None, None)])
            fsxattr = iter([(42, True), (42, True), (0, False)])
            fake_info = SimpleNamespace(st_dev=123, st_ino=456, st_uid=0,
                                        st_mode=stat.S_IFDIR | 0o700)
            clear_calls = 0
            def fake_clear(path, _device, _inode):
                nonlocal clear_calls
                clear_calls += 1
                if clear_calls == 1:
                    marker.unlink()
                    raise OSError('synthetic failure after one file was removed')
                actual = path.lstat()
                XfsVolumes._clear_contents_path(path, actual.st_dev, actual.st_ino)

            with patch.object(volumes, '_preflight'), patch.object(volumes, '_database', fake_database), \
                 patch.object(volumes, '_clear_contents', side_effect=fake_clear), \
                 patch.object(volumes, '_canonical', return_value=fake_info), patch.object(XfsVolumes, '_sync_dir'), \
                 patch('supervisor.volumes.os.path.ismount', return_value=False), \
                 patch.object(volumes, '_fsxattr', side_effect=lambda _path: next(fsxattr)), \
                 patch.object(volumes, '_limits', side_effect=lambda _project_id: next(limits)), \
                 patch.object(volumes, '_quota', side_effect=lambda command: quota_calls.append(command)):
                with self.assertRaisesRegex(OSError, 'after one file was removed'):
                    volumes.purge(instance_id, 4096, expected_project_id=42)
                self.assertFalse(marker.exists())
                self.assertTrue(other_marker.exists())
                self.assertEqual(quota_calls, [])
                with closing(sqlite3.connect(volumes.db_path.as_uri() + '?mode=ro', uri=True)) as read_db:
                    stage = read_db.execute('SELECT stage FROM volume_projects WHERE instance_id=?',
                                             (instance_id,)).fetchone()[0]
                    self.assertEqual(stage, 'purging')
                result = volumes.purge(instance_id, 4096, expected_project_id=42)

            self.assertEqual(result, {'purged': True, 'project_id': 42})
            self.assertFalse(root.exists())
            self.assertTrue(other_marker.exists())
            with closing(sqlite3.connect(volumes.db_path.as_uri() + '?mode=ro', uri=True)) as read_db:
                self.assertEqual(read_db.execute('SELECT count(*) FROM volume_projects').fetchone()[0], 0)
                self.assertEqual(read_db.execute('SELECT count(*) FROM volume_directories').fetchone()[0], 0)
            self.assertTrue(any(command.startswith('project -C -p ') for command in quota_calls))
            self.assertTrue(any(command.startswith('limit -p bsoft=0 bhard=0') for command in quota_calls))
class OllamaRouteGateTests(unittest.TestCase):
    def test_model_policy_gate_requires_route_receipt_before_authorizing_start(self):
        from types import SimpleNamespace
        from supervisor.service import RuntimeService, ServiceError

        service = object.__new__(RuntimeService)
        service.ollama_config = {'default_model_id': 'qwen3.5:9b'}
        calls = []
        service.engine = SimpleNamespace(ensure_ollama_route=lambda instance_id: (
            calls.append(instance_id) or {'ready': False}))
        service._ollama_policy_file_matches = lambda _evidence: True
        with self.assertRaises(ServiceError) as failure:
            service._require_ollama_policy(
                {'id': 'a' * 32}, {}, {'config_policy_version': 1, 'state': 'stopped'})
        self.assertEqual(getattr(failure.exception, 'code', None), 'model_policy_unverified')
        self.assertEqual(calls, ['a' * 32])


class OllamaModelChangeTests(unittest.TestCase):
    def test_admin_switch_updates_existing_config_and_preserves_instance_state(self):
        import hashlib
        import json
        import os
        from dataclasses import asdict
        from contextlib import closing
        from unittest.mock import patch
        from supervisor.config import validate_profile
        from supervisor.openclaw_config import build_gateway_config
        from supervisor.ollama_config import ollama_policy_matches_config
        from supervisor.runtime_store import RuntimeStore, canonical
        from supervisor.service import RuntimeService, ServiceError

        profile = validate_profile(dict(schema_version=1, profile_version='model-change', mode='lab',
            storage=dict(backend='xfs_project_quota', mountpoint='/srv/agents',
                         expected_uuid='12345678-1234-1234-1234-123456789abc'),
            agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
        fingerprint = hashlib.sha256(
            json.dumps(asdict(profile), sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True).encode('ascii')).hexdigest()
        old_policy = {'base_url': 'http://10.99.0.10:11434', 'default_model_id': 'qwen3.5:9b',
                      'context_tokens': 8192, 'max_tokens': 512, 'think': False}
        new_model = 'hf.co/DavidAU/Qwen3.5-9B-The-Defiant-Fable-Uncensored-Heretic-NEO-IMATRIX-MAX-MTP-GGUF:Q4_K_M'

        class Metrics:
            def snapshot(self):
                return dict(sampled_at=100, cpu_window_seconds=60, total_ram_bytes=10**14,
                            available_ram_bytes=10**14, cpu_percent=0, free_disk_bytes=10**14,
                            total_cpu_millicores=1000000, total_disk_bytes=10**14)

        class Volumes:
            def __init__(self, host_path):
                self.host_path = host_path
            def verify(self, instance_id, disk_bytes):
                return {'host_path': self.host_path, 'project_id': 7,
                        'disk_quota_verified': True}

        class Engine:
            def __init__(self):
                self.state = 'running'
                self.calls = []
            def inspect(self, _instance_id):
                return {'state': self.state, 'gateway': 'ready', 'container_id': 'c' * 64,
                        'network_profile': 'legacy_none', 'config_policy_version': 1}
            def stop(self, _instance_id):
                self.calls.append('stop')
                self.state = 'stopped'
            def restore_firewall(self):
                self.calls.append('restore_firewall')
                return {'policy_count': 0, 'instance_ids': [], 'ready': True}
            def ensure_ollama_route(self, instance_id):
                self.calls.append('ensure_ollama_route')
                return {'ready': True}
            def start(self, _instance_id):
                self.calls.append('start')
                self.state = 'running'

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / 'runtime.sqlite3'
            with closing(RuntimeStore(db_path, profile.profile_version, fingerprint)) as store:
                limits = profile.agent_limits
                request = {'actor_id': 'alice', 'action': 'create', 'idempotency_key': 'create',
                           'settings_revision': 1, 'settings': {'name': 'Agent', 'instructions': 'Hi'}}
                operation = store.intent(request,
                    (limits.ram_bytes, limits.cpu_millicores, limits.disk_bytes),
                    (10**14, 1000000, 10**14))
                instance_id = operation['instance_id']
                host_path = Path(tmp) / instance_id
                workspace = host_path / 'state' / 'workspace'
                workspace.mkdir(parents=True)
                marker = workspace / 'user-state.txt'
                marker.write_text('PRESERVE_SYNTHETIC_STATE', encoding='utf-8')
                evidence = {'host_path': str(host_path), 'project_id': 7,
                            'disk_quota_verified': True}
                store.complete(operation['id'], 'running', 'c' * 64)
                store.storage_ready(instance_id, evidence)
                store.initialized(instance_id)
                self.assertEqual(store.instance(instance_id)['initialized'], 1)
                self.assertIsNotNone(store.instance(instance_id)['storage'])
                current_instance = {'id': instance_id, 'actor': 'alice',
                                    'network_profile': 'legacy_none', 'gateway_token': 'T' * 43}
                persisted_config = build_gateway_config(current_instance, ollama=old_policy)
                state = {'config': persisted_config,
                         'blob': (canonical(persisted_config) + '\n').encode('utf-8')}
                engine = Engine()
                service = RuntimeService(profile, store, Volumes(str(host_path)), engine, Metrics(),
                    capacities=(10**14, 1000000, 10**14), disk_floor_bytes=0, clock=lambda: 100,
                    ollama_config=old_policy)
                self.assertEqual(store.ollama_model_id(), old_policy['default_model_id'])
                self.assertEqual(service.ollama_config['default_model_id'], old_policy['default_model_id'])

                def read_config(evidence, *, require_immutable, with_bytes=False):
                    return (state['config'], state['blob']) if with_bytes else state['config']

                def replace_config(_state_fd, expected, replacement, **_kwargs):
                    self.assertEqual(state['blob'], expected)
                    state['blob'] = replacement
                    state['config'] = json.loads(replacement.decode('utf-8'))

                service._read_managed_gateway_config = read_config
                service._open_gateway_state_fd = lambda evidence: os.open(os.devnull, os.O_RDONLY)
                with patch('supervisor.service.replace_locked_config_at', side_effect=replace_config):
                    result = service.change_ollama_model({
                        'expected_model_id': old_policy['default_model_id'],
                        'new_model_id': new_model,
                    })

                self.assertEqual(result['updated_instances'], 1)
                self.assertEqual(service.ollama_config['default_model_id'], new_model)
                self.assertEqual(state['config']['models']['providers']['ollama']['models'][0]['id'], new_model)
                self.assertTrue(ollama_policy_matches_config(state['config'], service.ollama_config))
                self.assertEqual(result['model_id'], new_model)
                self.assertEqual(store.ollama_model_id(), new_model)
                current = store.current('alice')
                assert current is not None
                self.assertEqual(current['desired_state'], 'running')
                self.assertEqual(current['container_id'], 'c' * 64)
                self.assertEqual(engine.calls, [
                    'stop', 'restore_firewall', 'ensure_ollama_route', 'start'])
                self.assertEqual(marker.read_text(encoding='utf-8'), 'PRESERVE_SYNTHETIC_STATE')
                self.assertEqual(state['config']['gateway'], persisted_config['gateway'])
                self.assertEqual(state['config']['models']['providers']['ollama']['models'][0]['id'], new_model)
                with closing(RuntimeStore(db_path, profile.profile_version, fingerprint)) as reopened:
                    restarted = RuntimeService(profile, reopened, Volumes(str(host_path)),
                        engine, Metrics(), capacities=(10**14, 1000000, 10**14),
                        disk_floor_bytes=0, clock=lambda: 100, ollama_config=old_policy)
                    assert restarted.ollama_config is not None
                    self.assertEqual(restarted.ollama_config['default_model_id'], new_model)

                with self.assertRaises(ServiceError) as stale:
                    service.change_ollama_model({
                        'expected_model_id': old_policy['default_model_id'],
                        'new_model_id': old_policy['default_model_id'],
                    })
                self.assertEqual(getattr(stale.exception, 'code', None), 'admin_config_conflict')
                unchanged = service.change_ollama_model({
                    'expected_model_id': old_policy['default_model_id'],
                    'new_model_id': new_model,
                })
                self.assertEqual(unchanged['status'], 'unchanged')
                with self.assertRaises(ServiceError) as invalid:
                    service.change_ollama_model({
                        'expected_model_id': new_model, 'new_model_id': 'unsupported:model',
                    })
                self.assertEqual(getattr(invalid.exception, 'code', None), 'invalid_request')


if __name__ == '__main__':
    unittest.main()


class ProductionWiringTests(unittest.TestCase):
    def test_serve_passes_ollama_configuration_to_engine(self):
        import stat
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch
        from supervisor.service import serve

        config = dict(profile_path='/trusted/profile', state_dir='/state',
                      socket_path='/run/control.sock', token_file='/state/service.token',
                      image='image', agent_network_pool='agent', frontend_network_pool='front',
                      ollama_network_pool='ollama-pool', ollama_egress_interface='eth0',
                      ollama={'base_url': 'http://10.0.0.1:11434'})
        profile = SimpleNamespace(storage=SimpleNamespace(mountpoint='/pool'))
        marker = object()
        with (patch.dict(sys.modules, {'fcntl': SimpleNamespace()}),
             patch('supervisor.service.load_profile', return_value=profile),
             patch('supervisor.service._trusted_directory'),
             patch('supervisor.service._runtime_firewall', return_value='firewall'),
             patch('supervisor.service._runtime_ollama_firewall', return_value=marker),
             patch('pathlib.Path.lstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)),
             patch('pathlib.Path.resolve', lambda self, **kwargs: self),
             patch('supervisor.service.os.path.lexists', return_value=False),
             patch('supervisor.docker_engine.DockerEngine') as constructor):
            constructor.return_value.check_host.side_effect = RuntimeError('stop')
            with self.assertRaisesRegex(RuntimeError, 'stop'):
                serve(config)
        self.assertEqual(constructor.call_args.kwargs['ollama_config'], config['ollama'])
        self.assertEqual(constructor.call_args.kwargs['ollama_network_pool'], 'ollama-pool')
        self.assertEqual(constructor.call_args.kwargs['ollama_egress_interface'], 'eth0')
        self.assertIs(constructor.call_args.kwargs['ollama_firewall'], marker)


class RecoveryRetryTests(unittest.TestCase):
    def test_background_retry_is_disabled_for_safe_containment(self):
        from supervisor.service import _retry_recovery
        class Controller:
            calls = 0
            def reconcile(self): self.calls += 1
        class Stop:
            def wait(self, seconds): return False
        controller = Controller()
        _retry_recovery(controller, Stop())
        self.assertEqual(controller.calls, 0)

    def test_repeated_recovery_does_not_readmit_running_instance(self):
        from supervisor.service import RuntimeService, ServiceError
        instance = dict(id='a' * 32, active=1, state='running',
                        desired_state='running', network_profile='legacy_none')
        class Store:
            def all_instances(self): return [instance]
            def observe(self, instance_id, state, container_id): instance['state'] = state
        class Engine:
            def __init__(self): self.calls = []
            def stop(self, instance_id): self.calls.append('stop')
            def inspect(self, instance_id):
                return dict(state='running', container_id='c', network_profile='legacy_none')
        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.store, service.engine = Store(), Engine()
        service.sidecar_migration = None
        service._inspect = service.engine.inspect
        service._storage = lambda instance: {'disk_quota_verified': True}
        def deny(**kwargs): raise ServiceError('admission_denied', 503)
        service._admit = deny
        service.reconcile()
        self.assertEqual(service.engine.calls, [])
        self.assertEqual(instance['desired_state'], 'running')

    def test_recovery_worker_retries_after_warmup_and_stops(self):
        from supervisor.service import _retry_recovery
        class Stop:
            def __init__(self): self.waits = []
            def wait(self, seconds):
                self.waits.append(seconds)
                return len(self.waits) == 4
        class Controller:
            def __init__(self): self.calls = 0
            def reconcile(self):
                self.calls += 1
                if self.calls == 1: raise RuntimeError('transient')
        stop, controller = Stop(), Controller()
        _retry_recovery(controller, stop)
        self.assertEqual(controller.calls, 0)
        self.assertEqual(stop.waits, [])

    def test_warmup_retry_restores_only_desired_running_after_firewall(self):
        from supervisor.service import RuntimeService, ServiceError, _retry_recovery
        running = dict(id='a' * 32, active=1, state='stopped', desired_state='running',
                       network_profile='agent_proxy_v1')
        stopped = dict(id='b' * 32, active=1, state='stopped', desired_state='stopped',
                       network_profile='agent_proxy_v1')
        class Store:
            def all_instances(self): return [running, stopped]
            def observe(self, instance_id, state, container_id):
                next(i for i in (running, stopped) if i['id'] == instance_id)['state'] = state
        class Engine:
            def __init__(self): self.calls = []; self.states = {}
            def restore_firewall(self):
                self.calls.append('firewall')
                return dict(ready=True, instance_ids=[running['id']])
            def inspect(self, instance_id):
                return dict(state=self.states.get(instance_id, 'stopped'), container_id='c',
                            network_profile='agent_proxy_v1')
            def start(self, instance_id):
                self.calls.append(('start', instance_id)); self.states[instance_id] = 'running'
        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.store, service.engine = Store(), Engine()
        service.sidecar_migration = None
        service._inspect = service.engine.inspect
        service._storage = lambda instance: {'disk_quota_verified': True}
        warm = [False]
        def admit(**kwargs):
            if not warm[0]: raise ServiceError('admission_denied', 503)
        service._admit = admit
        service.reconcile()
        self.assertEqual(service.engine.calls, ['firewall'])
        class Stop:
            calls = 0
            def wait(self, seconds):
                self.calls += 1
                warm[0] = True
                return self.calls > 1
        _retry_recovery(service, Stop())
        self.assertEqual(service.engine.calls, ['firewall'])
        self.assertEqual((running['desired_state'], running['state']), ('running', 'stopped'))
        self.assertEqual((stopped['desired_state'], stopped['state']), ('stopped', 'stopped'))

    def test_recovery_worker_is_bounded_and_shutdown_interrupts_wait(self):
        from supervisor.service import _retry_recovery
        class Controller:
            calls = 0
            def reconcile(self): self.calls += 1
        class NeverStop:
            def wait(self, seconds): return False
        controller = Controller()
        _retry_recovery(controller, NeverStop())
        self.assertEqual(controller.calls, 0)
        stop = threading.Event()
        worker = threading.Thread(target=_retry_recovery, args=(controller, stop))
        worker.start()
        stop.set()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(controller.calls, 0)
