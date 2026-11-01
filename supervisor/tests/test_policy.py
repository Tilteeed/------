"""Pure server policy tests; not evidence of running Docker or authenticating users."""
import unittest
from supervisor.policy import validate_create


class CreateRequestTests(unittest.TestCase):
    def test_create_accepts_only_user_request_fields(self):
        request = validate_create({'action': 'create', 'idempotency_key': 'request-01', 'settings_revision': 0})
        self.assertEqual(request.idempotency_key, 'request-01')
        self.assertEqual(request.settings_revision, 0)
        for field, value in (('owner_id', 'other-user'), ('image', 'other:latest'),
                             ('mounts', ['/']), ('privileged', True), ('gateway_url', 'http://internal')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_create({'action': 'create', 'idempotency_key': 'request-01',
                                 'settings_revision': 0, field: value})

    def test_invalid_requests_and_out_of_range_revisions_are_rejected(self):
        base = {'action': 'create', 'idempotency_key': 'request-01', 'settings_revision': 0}
        for field, values in {'action': ['stop', None, True],
                              'idempotency_key': ['', 'a b', 'a\n', 'x'*129, 42],
                              'settings_revision': [True, -1, 1.0, None, 2**63]}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_create(base | {field: value})
        for payload in (None, [], {}, base | {'action_extra': 'create'}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validate_create(payload)


class AdmissionTests(unittest.TestCase):
    def test_final_enforces_half_threshold_while_lab_reports_it(self):
        from supervisor.policy import evaluate_admission
        gib = 1024 ** 3
        inputs = dict(mode='final', now=100.0, sampled_at=95.0, cpu_window_seconds=60,
                      total_ram_bytes=8*gib, available_ram_bytes=6*gib, cpu_percent=10.0,
                      requested_ram_bytes=2*gib, free_disk_bytes=30*gib,
                      requested_disk_bytes=10*gib, disk_floor_bytes=2*gib,
                      disk_quota_verified=True)
        self.assertTrue(evaluate_admission(**inputs).allowed)
        inputs.update(available_ram_bytes=4*gib, cpu_percent=50.0)
        decision = evaluate_admission(**inputs)
        self.assertFalse(decision.allowed)
        self.assertEqual(set(decision.reasons), {'memory_threshold', 'cpu_threshold'})
        inputs['mode'] = 'lab'
        decision = evaluate_admission(**inputs)
        self.assertTrue(decision.allowed)
        self.assertEqual(set(decision.would_deny), {'memory_threshold', 'cpu_threshold'})
    def test_unready_metrics_never_authorize_admission(self):
        from supervisor.policy import evaluate_admission
        gib = 1024 ** 3
        base = dict(mode='lab', now=100.0, sampled_at=95.0, cpu_window_seconds=60,
                    total_ram_bytes=8*gib, available_ram_bytes=6*gib, cpu_percent=10.0,
                    requested_ram_bytes=2*gib, free_disk_bytes=30*gib,
                    requested_disk_bytes=10*gib, disk_floor_bytes=2*gib,
                    disk_quota_verified=True)
        for change, reason in (({'sampled_at': 89.0}, 'stale_metrics'),
                               ({'sampled_at': 101.0}, 'future_metrics'),
                               ({'cpu_window_seconds': 59}, 'cpu_window_incomplete')):
            with self.subTest(change=change):
                decision = evaluate_admission(**(base | change))
                self.assertFalse(decision.allowed)
                self.assertIn(reason, decision.reasons)
    def test_lab_does_not_bypass_physical_capacity_or_unverified_disk_quota(self):
        from supervisor.policy import evaluate_admission
        gib = 1024 ** 3
        base = dict(mode='lab', now=100.0, sampled_at=95.0, cpu_window_seconds=60,
                    total_ram_bytes=8*gib, available_ram_bytes=6*gib, cpu_percent=10.0,
                    requested_ram_bytes=2*gib, free_disk_bytes=30*gib,
                    requested_disk_bytes=10*gib, disk_floor_bytes=2*gib,
                    disk_quota_verified=True)
        for change, reason in (({'available_ram_bytes': gib}, 'insufficient_ram'),
                               ({'free_disk_bytes': 11*gib}, 'insufficient_disk'),
                               ({'disk_quota_verified': False}, 'disk_quota_unverified')):
            with self.subTest(change=change):
                decision = evaluate_admission(**(base | change))
                self.assertFalse(decision.allowed)
                self.assertIn(reason, decision.reasons)
        boundary = base | {'free_disk_bytes': 12*gib, 'available_ram_bytes': 2*gib}
        self.assertTrue(evaluate_admission(**boundary).allowed)
    def test_zero_new_disk_request_is_valid_when_reusing_a_retained_quota(self):
        from supervisor.policy import evaluate_admission
        gib = 1024 ** 3
        inputs = dict(mode='final', now=100.0, sampled_at=95.0, cpu_window_seconds=60,
                      total_ram_bytes=8*gib, available_ram_bytes=6*gib, cpu_percent=10.0,
                      requested_ram_bytes=2*gib, free_disk_bytes=2*gib,
                      requested_disk_bytes=0, disk_floor_bytes=2*gib,
                      disk_quota_verified=True)
        self.assertTrue(evaluate_admission(**inputs).allowed)

    def test_invalid_observations_and_profiles_are_rejected(self):
        from supervisor.policy import evaluate_admission
        gib = 1024 ** 3
        base = dict(mode='lab', now=100.0, sampled_at=95.0, cpu_window_seconds=60,
                    total_ram_bytes=8*gib, available_ram_bytes=6*gib, cpu_percent=10.0,
                    requested_ram_bytes=2*gib, free_disk_bytes=30*gib,
                    requested_disk_bytes=10*gib, disk_floor_bytes=2*gib,
                    disk_quota_verified=True)
        invalid = {'mode': ['unknown', None, []], 'now': [float('nan'), float('inf'), True],
                   'sampled_at': [float('nan'), None], 'cpu_window_seconds': [-1, True],
                   'total_ram_bytes': [0, True, 1.0, 2**64],
                   'available_ram_bytes': [-1, 9*gib], 'cpu_percent': [float('nan'), 101, -1, True],
                   'requested_ram_bytes': [0, True, 1.5], 'free_disk_bytes': [-1, None],
                   'requested_disk_bytes': [True, -1], 'disk_floor_bytes': [-1, False],
                   'disk_quota_verified': [1, 'true', None]}
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    evaluate_admission(**(base | {field: value}))


if __name__ == '__main__':
    unittest.main()
