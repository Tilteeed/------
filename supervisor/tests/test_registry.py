import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

from supervisor import registry


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get(
            'TMPDIR', 'C:/Users/SystemX/AppData/Local/hermes/cache/scratch'))
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, 'registry.sqlite3')
        self.registry = registry.Registry(self.path)
        self.request = dict(idempotency_key='create-1', settings_revision=0,
                            profile_version='basic-v1', ram_bytes=2,
                            cpu_units=1, disk_bytes=3, capacity_ram_bytes=4,
                            capacity_cpu_units=2, capacity_disk_bytes=6)

    def reserve(self, actor='alice', **changes):
        return self.registry.reserve_create(actor, **(self.request | changes))

    def race(self, actors, **changes):
        barrier = threading.Barrier(len(actors))

        def reserve(actor):
            local = registry.Registry(self.path)
            barrier.wait(timeout=10)
            try:
                return local.reserve_create(actor, **(self.request | changes))
            except Exception as error:
                return error

        with ThreadPoolExecutor(max_workers=len(actors)) as pool:
            return list(pool.map(reserve, actors))

    def counts(self):
        with closing(sqlite3.connect(self.path)) as db:
            return tuple(db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                         for table in ('instances', 'operations'))

    def test_two_owners_have_distinct_slots(self):
        first, second = self.reserve(), self.reserve('bob')
        self.assertNotEqual(first['instance_id'], second['instance_id'])
        self.assertEqual(self.counts(), (2, 2))

    def test_one_owner_race_has_exactly_one_winner(self):
        # Distinct keys: this is a slot race, not an idempotent retry.
        barrier = threading.Barrier(2)

        def create(key):
            local = registry.Registry(self.path)
            barrier.wait(timeout=10)
            try:
                return local.reserve_create('alice', **(self.request |
                                                        {'idempotency_key': key}))
            except Exception as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(create, ('one', 'two')))
        self.assertEqual(sum(isinstance(x, dict) for x in results), 1)
        self.assertEqual(sum(isinstance(x, registry.OneInstanceLimit)
                             for x in results), 1)
        self.assertEqual(self.counts(), (1, 1))

    def test_total_budget_race_has_exactly_one_winner(self):
        for capacity in ('capacity_ram_bytes', 'capacity_cpu_units',
                         'capacity_disk_bytes'):
            with self.subTest(capacity=capacity):
                self.path = os.path.join(self.temp.name, capacity + '.sqlite3')
                results = self.race(('alice', 'bob'), **{
                    capacity: self.request[capacity.removeprefix('capacity_')]})
                self.assertEqual(sum(isinstance(x, dict) for x in results), 1)
                self.assertEqual(sum(isinstance(x, registry.CapacityExceeded)
                                     for x in results), 1)
                self.assertEqual(self.counts(), (1, 1))

    def test_capacity_failure_leaves_no_partial_reservation(self):
        for field in ('ram_bytes', 'cpu_units', 'disk_bytes'):
            with self.subTest(field=field):
                with self.assertRaises(registry.CapacityExceeded):
                    self.reserve(**{field: self.request['capacity_' + field] + 1})
                self.assertEqual(self.counts(), (0, 0))
        self.reserve()
        self.assertEqual(self.counts(), (1, 1))

    def test_idempotent_retry_survives_reopen_and_capacity_change(self):
        first = self.reserve()
        self.registry = registry.Registry(self.path)
        self.assertEqual(self.reserve(capacity_ram_bytes=1,
                                      capacity_cpu_units=1,
                                      capacity_disk_bytes=1), first)
        self.assertEqual(self.counts(), (1, 1))

    def test_changed_semantic_request_conflicts(self):
        self.reserve()
        for change in ({'settings_revision': 1}, {'profile_version': 'v2'},
                       {'ram_bytes': 3}, {'cpu_units': 2}, {'disk_bytes': 4}):
            with self.subTest(change=change):
                with self.assertRaises(registry.IdempotencyConflict):
                    self.reserve(**change)
        self.assertEqual(self.counts(), (1, 1))

    def test_same_key_is_scoped_to_actor(self):
        first = self.reserve()
        other = self.reserve('bob', settings_revision=7)
        self.assertNotEqual(first['id'], other['id'])
        self.assertEqual(self.reserve('bob', settings_revision=7), other)

    def test_idempotent_race_returns_same_operation(self):
        results = self.race(('alice', 'alice'))
        self.assertTrue(all(isinstance(x, dict) for x in results), results)
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.counts(), (1, 1))

    def test_different_key_cannot_bypass_owner_slot(self):
        self.reserve()
        with self.assertRaises(registry.OneInstanceLimit):
            self.reserve(idempotency_key='second')
        self.assertEqual(self.counts(), (1, 1))

    def test_resource_and_capacity_validation_is_strict(self):
        fields = ('ram_bytes', 'cpu_units', 'disk_bytes', 'capacity_ram_bytes',
                  'capacity_cpu_units', 'capacity_disk_bytes')
        for field in fields:
            for invalid in (0, -1, True, False, 1.0, '1', None, 2**63):
                with self.subTest(field=field, invalid=invalid):
                    with self.assertRaises(ValueError):
                        self.reserve(**{field: invalid})
        self.assertEqual(self.counts(), (0, 0))

    def test_revision_validation_is_strict(self):
        for invalid in (-1, True, False, 0.0, '0', None, 2**63):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.reserve(settings_revision=invalid)
        self.assertEqual(self.counts(), (0, 0))
        self.reserve(settings_revision=2**63 - 1)

    def test_string_validation(self):
        for field in ('actor', 'idempotency_key', 'profile_version'):
            for invalid in ('', ' ', None, 1, True, 'x' * 129,
                            'a\n', 'a\x00b', 'a\x7fb', 'a\x85b', 'a\u202eb'):
                with self.subTest(field=field, invalid=invalid):
                    with self.assertRaises(ValueError):
                        self.reserve(**{field: invalid})
        self.assertEqual(self.counts(), (0, 0))
        self.reserve('я' * 128, idempotency_key='k' * 128,
                     profile_version='п' * 128)

    def test_maximum_sqlite_integer_resources_are_supported(self):
        large = 2**63 - 1
        changes = {field: large for field in (
            'ram_bytes', 'cpu_units', 'disk_bytes', 'capacity_ram_bytes',
            'capacity_cpu_units', 'capacity_disk_bytes')}
        op = self.reserve(**changes)
        self.assertEqual(self.registry.get_instance('alice', op['instance_id'])[
            'ram_bytes'], large)
        with self.assertRaises(registry.CapacityExceeded):
            self.reserve('bob', **changes)

    def test_extra_payload_is_not_accepted(self):
        with self.assertRaises(TypeError):
            self.reserve(payload={'sql': 'DROP TABLE instances'})
        self.assertEqual(self.counts(), (0, 0))

    def test_getters_reject_other_owner_without_disclosing_fields(self):
        op = self.reserve()
        for getter, identifier in (
                (self.registry.get_instance, op['instance_id']),
                (self.registry.get_operation, op['id'])):
            with self.subTest(getter=getter.__name__):
                with self.assertRaises(PermissionError) as caught:
                    getter('bob', identifier)
                for secret in ('alice', identifier, 'reserved', 'queued', 'basic-v1'):
                    self.assertNotIn(secret, str(caught.exception))
                self.assertEqual(getter('alice', identifier)['id'], identifier)

    def test_getters_missing_ids_raise_key_error(self):
        for getter in (self.registry.get_instance, self.registry.get_operation):
            with self.subTest(getter=getter.__name__):
                with self.assertRaises(KeyError):
                    getter('alice', 'nonexistent')
                with self.assertRaises(KeyError):
                    getter('alice', "x' OR 1=1 --")

    def test_getters_validate_identity_and_identifier(self):
        op = self.reserve()
        for getter, identifier in (
                (self.registry.get_instance, op['instance_id']),
                (self.registry.get_operation, op['id'])):
            for invalid in (None, '', True, 'x\n', 'x' * 129):
                with self.subTest(getter=getter.__name__, invalid=invalid):
                    with self.assertRaises(ValueError):
                        getter(invalid, identifier)
                    with self.assertRaises(ValueError):
                        getter('alice', invalid)

    def test_operation_insert_failure_rolls_back_instance_and_key(self):
        # A real SQLite failure after instance insertion, not a mocked connection.
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('''CREATE TRIGGER reject_operation BEFORE INSERT ON operations
                          BEGIN SELECT RAISE(ABORT, 'test failure'); END''')
        with self.assertRaises(sqlite3.IntegrityError):
            self.reserve()
        self.assertEqual(self.counts(), (0, 0))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('DROP TRIGGER reject_operation')
        self.reserve()
        self.assertEqual(self.counts(), (1, 1))

    def test_sql_looking_strings_are_literal_values(self):
        actor = "owner'; DROP TABLE instances; --"
        op = self.reserve(actor, idempotency_key="key' OR 1=1 --",
                          profile_version="v'; SELECT 1; --")
        self.assertEqual(self.registry.get_instance(actor, op['instance_id'])[
            'owner_id'], actor)
        self.assertEqual(self.counts(), (1, 1))

    def test_persistent_reserved_instance_and_queued_operation(self):
        op = self.reserve()
        reopened = registry.Registry(self.path)
        self.assertEqual(reopened.get_operation('alice', op['id']), op)
        instance = reopened.get_instance('alice', op['instance_id'])
        self.assertEqual(op['status'], 'queued')
        self.assertEqual(op['kind'], 'create')
        self.assertEqual(instance['status'], 'reserved')
        self.assertEqual(instance['owner_id'], 'alice')
        for field in ('settings_revision', 'profile_version', 'ram_bytes',
                      'cpu_units', 'disk_bytes'):
            self.assertEqual(instance[field], self.request[field])
        self.assertNotIn('container_id', instance)
        self.assertNotIn('container_id', op)


if __name__ == '__main__':
    unittest.main()
