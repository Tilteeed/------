"""Coordinator/transaction tests use real temporary SQLite and synthetic budgets."""
import sqlite3
from contextlib import closing
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from typing import Any, cast
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from supervisor.registry import Registry


class RegistryFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'registry.sqlite3'
        self.registry = Registry(self.path)
        self.request = dict(idempotency_key='unit-create', settings_revision=0,
                            profile_version='unit-v1', ram_bytes=1024,
                            cpu_units=1000, disk_bytes=4096)


class AdmissionTransactionTests(RegistryFixture):
    def test_fresh_admission_and_capacity_are_evaluated_under_sqlite_lock(self):
        from supervisor.registry import ReservationCapacity
        calls = []

        def admit():
            # A second writer must be locked out before the provider is invoked.
            with closing(sqlite3.connect(self.path, timeout=0)) as other:
                with self.assertRaises(sqlite3.OperationalError):
                    other.execute('BEGIN IMMEDIATE')
            calls.append('admitted')
            return ReservationCapacity(ram_bytes=2048, cpu_units=2000, disk_bytes=8192)

        operation = self.registry.reserve_create('owner-a', **self.request, admit=admit)
        self.assertEqual(calls, ['admitted'])
        self.assertEqual(operation['status'], 'queued')
        self.assertEqual(self.registry.get_instance('owner-a', operation['instance_id'])['status'], 'reserved')
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM instances').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM operations').fetchone()[0], 1)

    def test_admission_source_is_exclusive_and_typed(self):
        from supervisor.registry import ReservationCapacity
        calls = []

        def admit():
            calls.append(True)
            return ReservationCapacity(2048, 2000, 8192)

        with self.assertRaises(ValueError):
            self.registry.reserve_create('owner-a', **self.request, admit=admit,
                                         capacity_ram_bytes=2048, capacity_cpu_units=2000,
                                         capacity_disk_bytes=8192)
        self.assertEqual(calls, [])
        for provider in (True, 1, 'not-a-provider'):
            with self.subTest(provider=provider), self.assertRaises(ValueError):
                self.registry.reserve_create('owner-a', **self.request, admit=provider)
        for capacity in (None, {}, (2048, 2000, 8192), ReservationCapacity(True, 2000, 8192),
                         ReservationCapacity(-1, 2000, 8192), ReservationCapacity(2048, cast(Any, 1.5), 8192),
                         ReservationCapacity(2048, 2000, 2**63)):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                self.registry.reserve_create('owner-a', **self.request,
                                             admit=lambda: capacity)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM instances').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM operations').fetchone()[0], 0)

    def test_profile_version_is_pinned_persistently_not_silently_rebound(self):
        from supervisor.registry import ProfileVersionConflict
        capacities = dict(capacity_ram_bytes=2048, capacity_cpu_units=2000,
                          capacity_disk_bytes=8192)
        first = self.registry.reserve_create('owner-a', **self.request,
                                             profile_fingerprint='a' * 64, **capacities)
        reopened = Registry(self.path)
        reopened.reserve_create('owner-b', **self.request,
                                profile_fingerprint='a' * 64, **capacities)
        for actor, fingerprint in (('owner-a', 'b' * 64), ('owner-c', 'b' * 64), ('owner-c', None)):
            with self.subTest(actor=actor, fingerprint=fingerprint), self.assertRaises(ProfileVersionConflict):
                reopened.reserve_create(actor, **self.request,
                                        profile_fingerprint=fingerprint, **capacities)
        self.assertEqual(reopened.reserve_create('owner-a', **self.request,
                                                profile_fingerprint='a' * 64, **capacities), first)

    def test_profile_fingerprint_requires_exact_sha256_token(self):
        for fingerprint in (True, 1, '', 'a' * 63, 'g' * 64, 'A' * 64,
                            'a' * 65, 'a' * 64 + '\n'):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(ValueError):
                self.registry.reserve_create('owner-a', **self.request,
                                             profile_fingerprint=fingerprint,
                                             capacity_ram_bytes=2048, capacity_cpu_units=2000,
                                             capacity_disk_bytes=8192)

    def test_legacy_reservations_are_not_relabelled_as_verified_profiles(self):
        from supervisor.registry import ProfileVersionConflict
        capacities = dict(capacity_ram_bytes=2048, capacity_cpu_units=2000,
                          capacity_disk_bytes=8192)
        original = self.registry.reserve_create('owner-a', **self.request, **capacities)
        for actor in ('owner-a', 'owner-b'):
            with self.subTest(actor=actor), self.assertRaises(ProfileVersionConflict):
                self.registry.reserve_create(actor, **self.request,
                                             profile_fingerprint='a' * 64, **capacities)
        self.assertEqual(self.registry.get_operation('owner-a', original['id']), original)
        request = self.request | {'profile_version': 'unit-v2'}
        self.assertEqual(self.registry.reserve_create('owner-b', **request,
                                                     profile_fingerprint='b' * 64, **capacities)['status'], 'queued')


def site_profile(**changes):
    from supervisor.config import validate_profile
    return validate_profile({
        'schema_version': 1, 'profile_version': 'unit-v1', 'mode': 'final',
        'storage': {'backend': 'xfs_project_quota', 'mountpoint': '/mnt/unit-agents',
                    'expected_uuid': '11111111-2222-4333-8444-555555555555'},
        'agent_limits': {'ram_bytes': 1024, 'cpu_millicores': 1000,
                         'pids_limit': 256, 'disk_bytes': 4096},
    } | changes)


def observation(**changes):
    from supervisor.coordinator import ResourceObservation
    # Quota evidence and all metrics here are synthetic, not inferred from a real FS.
    values: dict[str, Any] = dict(
        sampled_at=95, cpu_window_seconds=60,
        total_ram_bytes=8192, available_ram_bytes=6144, cpu_percent=10,
        free_disk_bytes=32768, disk_floor_bytes=1024, disk_quota_verified=True,
        capacity_ram_bytes=2048, capacity_cpu_millicores=2000, capacity_disk_bytes=8192,
        total_cpu_millicores=4000, total_disk_bytes=65536,
    )
    values.update(changes)
    return ResourceObservation(**values)


class CoordinatorTests(RegistryFixture):
    def test_create_connects_profile_admission_and_actual_sqlite_reservation(self):
        from supervisor.coordinator import CreateCoordinator
        calls = []

        def observe():
            calls.append('observed')
            return observation()

        coordinator = CreateCoordinator(self.registry, site_profile(), observe, lambda: 100)
        result = coordinator.create('owner-a', {'action': 'create',
                                              'idempotency_key': 'unit-create',
                                              'settings_revision': 0}, current_settings_revision=0)
        self.assertEqual(result.status, 'queued')
        self.assertFalse(result.replayed)
        assert result.admission is not None
        self.assertTrue(result.admission.allowed)
        self.assertEqual(calls, ['observed'])
        instance = self.registry.get_instance('owner-a', result.instance_id)
        self.assertEqual(instance['status'], 'reserved')
        self.assertEqual(instance['ram_bytes'], 1024)
        self.assertEqual(instance['cpu_units'], 1000)
        self.assertEqual(instance['disk_bytes'], 4096)
        self.assertEqual(self.registry.get_operation('owner-a', result.operation_id)['status'], 'queued')
        fingerprint = hashlib.sha256(json.dumps(asdict(site_profile()), sort_keys=True,
                                              separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT fingerprint FROM deployment_profiles').fetchone()[0], fingerprint)

    def test_denied_observations_leave_no_reservations_or_profile_binding(self):
        from supervisor.coordinator import CreateCoordinator, AdmissionDenied
        cases = (({'sampled_at': 89}, 'stale_metrics'),
                 ({'sampled_at': 101}, 'future_metrics'),
                 ({'cpu_percent': 50}, 'cpu_threshold'),
                 ({'available_ram_bytes': 4096}, 'memory_threshold'),
                 ({'cpu_window_seconds': 59}, 'cpu_window_incomplete'),
                 ({'free_disk_bytes': 1}, 'insufficient_disk'),
                 ({'available_ram_bytes': 1}, 'insufficient_ram'),
                 ({'disk_quota_verified': False}, 'disk_quota_unverified'))
        for changes, reason in cases:
            coordinator = CreateCoordinator(self.registry, site_profile(),
                                            lambda: observation(**changes), lambda: 100)
            with self.subTest(reason=reason), self.assertRaises(AdmissionDenied) as caught:
                coordinator.create('owner-a', {'action': 'create', 'idempotency_key': 'unit-create',
                                              'settings_revision': 0}, current_settings_revision=0)
            self.assertIn(reason, caught.exception.decision.reasons)
        with closing(sqlite3.connect(self.path)) as db:
            for table in ('instances', 'operations', 'deployment_profiles'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)

    def test_new_request_requires_matching_trusted_settings_revision(self):
        from supervisor.coordinator import CreateCoordinator, SettingsRevisionConflict

        def forbidden_observe():
            self.fail('Settings revision must be checked before metrics are requested')

        coordinator = CreateCoordinator(self.registry, site_profile(), forbidden_observe, lambda: 100)
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}
        with self.assertRaises(SettingsRevisionConflict):
            coordinator.create('owner-a', payload, current_settings_revision=1)
        for revision in (None, True, -1, 0.0, '0', 2**63):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                coordinator.create('owner-a', payload, current_settings_revision=revision)
        with closing(sqlite3.connect(self.path)) as db:
            for table in ('instances', 'operations', 'deployment_profiles'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)


    def test_constructor_revalidates_profile_and_trusted_provider_contracts(self):
        from supervisor.coordinator import CreateCoordinator
        profile = site_profile()
        invalid_profile = replace(profile, storage=replace(profile.storage, mountpoint='/'))
        cases = ((None, profile, observation, lambda: 100),
                 (self.registry, None, observation, lambda: 100),
                 (self.registry, invalid_profile, observation, lambda: 100),
                 (self.registry, profile, None, lambda: 100),
                 (self.registry, profile, observation, None))
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                CreateCoordinator(*cast(Any, arguments))

    def test_observation_provider_cannot_return_untyped_or_malformed_evidence(self):
        from supervisor.coordinator import CreateCoordinator
        invalid = (None, {}, observation(cpu_percent=float('nan')),
                   observation(disk_quota_verified=1), observation(capacity_ram_bytes=True),
                   observation(capacity_cpu_millicores=2**63), observation(capacity_disk_bytes=-1))
        for sample in invalid:
            coordinator = CreateCoordinator(self.registry, site_profile(),
                                            cast(Any, lambda: sample), lambda: 100)
            with self.subTest(sample=sample), self.assertRaises(ValueError):
                coordinator.create('owner-a', {'action': 'create', 'idempotency_key': 'unit-create',
                                              'settings_revision': 0}, current_settings_revision=0)
        with closing(sqlite3.connect(self.path)) as db:
            for table in ('instances', 'operations', 'deployment_profiles'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)


    def test_exact_retry_returns_original_without_new_observations_or_revision_check(self):
        from supervisor.coordinator import CreateCoordinator
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}
        coordinator = CreateCoordinator(self.registry, site_profile(), observation, lambda: 100)
        first = coordinator.create('owner-a', payload, current_settings_revision=0)

        def unavailable():
            self.fail('Replay must not require new metrics or a new clock sample')

        retry = replace(coordinator, registry=Registry(self.path), observe=unavailable, clock=unavailable)
        result = retry.create('owner-a', payload, current_settings_revision=1)
        self.assertTrue(result.replayed)
        self.assertIsNone(result.admission)
        self.assertEqual(result.operation_id, first.operation_id)
        self.assertEqual(result.instance_id, first.instance_id)
        with closing(sqlite3.connect(self.path)) as db:
            for table in ('instances', 'operations', 'deployment_profiles'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 1)

    def test_changed_request_conflicts_and_operation_access_stays_owner_scoped(self):
        from supervisor.coordinator import CreateCoordinator
        from supervisor.registry import IdempotencyConflict, OneInstanceLimit
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}
        coordinator = CreateCoordinator(self.registry, site_profile(), observation, lambda: 100)
        first = coordinator.create('owner-a', payload, current_settings_revision=0)
        with self.assertRaises(IdempotencyConflict):
            coordinator.create('owner-a', payload | {'settings_revision': 1}, current_settings_revision=1)
        with self.assertRaises(OneInstanceLimit):
            coordinator.create('owner-a', payload | {'idempotency_key': 'different'}, current_settings_revision=0)
        second = coordinator.create('owner-b', payload, current_settings_revision=0)
        self.assertNotEqual(first.operation_id, second.operation_id)
        with self.assertRaises(PermissionError):
            self.registry.get_operation('owner-b', first.operation_id)
        with self.assertRaises(PermissionError):
            self.registry.get_instance('owner-a', second.instance_id)

    def test_client_payload_cannot_supply_identity_limits_or_quota_evidence(self):
        from supervisor.coordinator import CreateCoordinator
        coordinator = CreateCoordinator(self.registry, site_profile(), observation, lambda: 100)
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}
        for key in ('owner_id', 'image', 'mounts', 'mode', 'ram_bytes', 'capacity_ram_bytes',
                    'disk_quota_verified', 'current_settings_revision', 'threshold_percent'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                coordinator.create('owner-a', payload | {key: True}, current_settings_revision=0)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM instances').fetchone()[0], 0)

    def test_lab_reports_half_threshold_without_bypassing_quota_requirement(self):
        from supervisor.coordinator import CreateCoordinator, AdmissionDenied
        profile = site_profile(mode='lab')
        coordinator = CreateCoordinator(self.registry, profile,
                                        lambda: observation(cpu_percent=50, available_ram_bytes=4096),
                                        lambda: 100)
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}
        result = coordinator.create('owner-a', payload, current_settings_revision=0)
        assert result.admission is not None
        self.assertEqual(set(result.admission.would_deny), {'memory_threshold', 'cpu_threshold'})
        denied = replace(coordinator, observe=lambda: observation(disk_quota_verified=False))
        with self.assertRaises(AdmissionDenied):
            denied.create('owner-b', payload, current_settings_revision=0)

    def test_profile_drift_is_rejected_before_replay_and_before_new_admission(self):
        from supervisor.coordinator import CreateCoordinator
        from supervisor.registry import ProfileVersionConflict
        profile = site_profile()
        coordinator = CreateCoordinator(self.registry, profile, observation, lambda: 100)
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}
        coordinator.create('owner-a', payload, current_settings_revision=0)
        changed = (replace(profile, agent_limits=replace(profile.agent_limits, pids_limit=128)),
                   replace(profile, storage=replace(profile.storage, mountpoint='/mnt/other')),
                   replace(profile, storage=replace(profile.storage,
                           expected_uuid='AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE')),
                   replace(profile, mode='lab'))

        def forbidden():
            self.fail('Changed profile must fail before admission')

        for other in changed:
            altered = replace(coordinator, profile=other, observe=forbidden)
            for actor in ('owner-a', 'owner-b'):
                with self.subTest(profile=other, actor=actor), self.assertRaises(ProfileVersionConflict):
                    altered.create(actor, payload, current_settings_revision=0)

    def test_operation_insert_failure_rolls_back_new_profile_binding(self):
        from supervisor.coordinator import CreateCoordinator
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TRIGGER unit_reject_operation BEFORE INSERT ON operations
                          BEGIN SELECT RAISE(ABORT, 'unit failure'); END""")
        coordinator = CreateCoordinator(self.registry, site_profile(), observation, lambda: 100)
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}
        with self.assertRaises(sqlite3.IntegrityError):
            coordinator.create('owner-a', payload, current_settings_revision=0)
        with closing(sqlite3.connect(self.path)) as db, db:
            for table in ('instances', 'operations', 'deployment_profiles'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)
            db.execute('DROP TRIGGER unit_reject_operation')
        changed = replace(coordinator.profile,
                          agent_limits=replace(coordinator.profile.agent_limits, pids_limit=128))
        self.assertEqual(replace(coordinator, profile=changed).create(
            'owner-a', payload, current_settings_revision=0).status, 'queued')

    def test_concurrent_distinct_owners_cannot_oversubscribe_a_single_slot_budget(self):
        from supervisor.coordinator import CreateCoordinator
        from supervisor.registry import CapacityExceeded
        coordinator = CreateCoordinator(self.registry, site_profile(),
                                        lambda: observation(capacity_ram_bytes=1024), lambda: 100)
        barrier = Barrier(4)
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}

        def submit(index):
            barrier.wait(timeout=10)
            try:
                return coordinator.create(f'owner-{index}', payload, current_settings_revision=0)
            except CapacityExceeded:
                return None

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(submit, range(4)))
        self.assertEqual(sum(result is not None for result in results), 1)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*), sum(ram_bytes) FROM instances').fetchone(), (1, 1024))
            self.assertEqual(db.execute('SELECT count(*) FROM operations').fetchone()[0], 1)

    def test_concurrent_exact_retries_share_one_operation_and_one_admission(self):
        from supervisor.coordinator import CreateCoordinator
        calls = []

        def observe():
            calls.append(True)
            return observation()

        coordinator = CreateCoordinator(self.registry, site_profile(), observe, lambda: 100)
        barrier = Barrier(4)
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}

        def submit(_index):
            barrier.wait(timeout=10)
            return coordinator.create('owner-a', payload, current_settings_revision=0)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(submit, range(4)))
        self.assertEqual(len({result.operation_id for result in results}), 1)
        self.assertEqual(sum(result.replayed for result in results), 3)
        self.assertEqual(len(calls), 1)

    def test_ten_second_freshness_boundary_is_inclusive(self):
        from supervisor.coordinator import CreateCoordinator, AdmissionDenied
        coordinator = CreateCoordinator(self.registry, site_profile(),
                                        lambda: observation(sampled_at=90), lambda: 100)
        payload = {'action': 'create', 'idempotency_key': 'unit-create', 'settings_revision': 0}
        self.assertEqual(coordinator.create('owner-a', payload, current_settings_revision=0).status, 'queued')
        older = replace(coordinator, observe=lambda: observation(sampled_at=89.999))
        with self.assertRaises(AdmissionDenied) as caught:
            older.create('owner-b', payload, current_settings_revision=0)
        self.assertIn('stale_metrics', caught.exception.decision.reasons)

    def test_reservation_ceiling_cannot_exceed_observed_physical_total(self):
        from supervisor.coordinator import CreateCoordinator
        changes = ({'capacity_ram_bytes': 8193},
                   {'capacity_cpu_millicores': 4001},
                   {'capacity_disk_bytes': 65537},
                   {'free_disk_bytes': 65537},
                   {'total_cpu_millicores': True}, {'total_disk_bytes': 0})
        for change in changes:
            coordinator = CreateCoordinator(self.registry, site_profile(),
                                            lambda: observation(**change), lambda: 100)
            with self.subTest(change=change), self.assertRaises(ValueError):
                coordinator.create('owner-a', {'action': 'create', 'idempotency_key': 'unit-create',
                                              'settings_revision': 0}, current_settings_revision=0)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM instances').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
