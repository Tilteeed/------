"""Boot lifecycle tests with synthetic Docker/storage and trusted metric samples."""
import copy
import json
import threading
import unittest
from types import SimpleNamespace as NS
from supervisor.service import RuntimeService, ServiceError, _retry_recovery


class BootRecoveryTests(unittest.TestCase):
    def make_service(self, profile='agent_proxy_v1'):
        service = object.__new__(RuntimeService)
        service.lock = threading.RLock()
        service.sidecar_migration = None
        service.ollama_config = None
        service.network_profile_default = profile
        service.profile = NS(mode='lab', agent_limits=NS(ram_bytes=1024, disk_bytes=4096))
        service.capacities = (10**9, 1000, 10**9)
        service.disk_floor_bytes = 0
        now = [100.0]
        service.clock = lambda: now[0]
        sample = dict(total_ram_bytes=10**9, total_cpu_millicores=1000, total_disk_bytes=10**9,
                      available_ram_bytes=8*10**8, free_disk_bytes=10**9,
                      cpu_percent=0, cpu_window_seconds=0, sampled_at=now[0])
        service.metrics = NS(snapshot=lambda: dict(sample))
        events = []
        instance_id, gateway_id, sidecar_id = 'a'*32, 'b'*64, 'c'*64
        evidence = dict(host_path='/synthetic/instance', project_id=42, disk_quota_verified=True)
        item = dict(id=instance_id, actor='owner', active=1, initialized=1, state='running',
                    desired_state='running', container_id=gateway_id, network_profile=profile,
                    storage=json.dumps(evidence, sort_keys=True, separators=(',',':')), settings='{}')
        class Store:
            def instance(self, instance): return copy.deepcopy(item) if instance == instance_id else None
            def all_instances(self): return [copy.deepcopy(item)]
            def observe(self, instance, state, container_id):
                item.update(state=state, container_id=container_id)
            def storage_ready(self, instance, observed):
                item['storage'] = json.dumps(observed, sort_keys=True, separators=(',',':'))
        class Engine:
            def __init__(self):
                self.gateway_id, self.sidecar_id = gateway_id, sidecar_id if profile == 'agent_proxy_v1' else None
                self.state, self.firewall, self.failed_start = 'stopped', True, False
            def inspect(self, instance, *, read_only=False,
                        expected_container_id=None, expected_sidecar_id=None):
                if (expected_container_id is not None and expected_container_id != self.gateway_id
                        or expected_sidecar_id is not None and expected_sidecar_id != self.sidecar_id):
                    raise RuntimeError('identity changed during observation')
                return dict(state=self.state, container_id=self.gateway_id,
                            network_profile=profile, config_policy_version=1, gateway='unknown')
            def restore_firewall(self):
                events.append('firewall')
                return dict(ready=self.firewall, instance_ids=[instance_id])
            def recovery_identity(self, instance):
                events.append('identity')
                if not self.firewall or self.state not in {'stopped','created','exited'}:
                    raise RuntimeError('not eligible')
                return dict(gateway_id=self.gateway_id, sidecar_id=self.sidecar_id)
            def start_bound(self, instance, expected_container_id, expected_sidecar_id=None):
                events.append('bound_start')
                if (expected_container_id, expected_sidecar_id) != (self.gateway_id, self.sidecar_id):
                    raise RuntimeError('identity drift')
                self.state = 'running'
                if self.failed_start: raise RuntimeError('ambiguous start')
                return self.inspect(instance)
            def stop_bound(self, expected_container_id, expected_sidecar_id=None):
                events.append('bound_stop')
                self.state = 'stopped'
                return True
            def start(self, instance):
                events.append('ordinary_start')
                self.state = 'running'
            def stop(self, instance):
                events.append('ordinary_stop')
                self.state = 'stopped'
        service.store, service.engine = Store(), Engine()
        def storage(instance, *, prepare=False):
            events.append('storage')
            if evidence['disk_quota_verified'] is not True:
                raise ServiceError('quota_unverified',503)
            service.store.storage_ready(instance['id'],evidence)
            return dict(evidence)
        service._storage = storage
        return NS(service=service, item=item, evidence=evidence, events=events,
                  now=now, sample=sample, stop=threading.Event())

    def warm(self, f):
        f.now[0] += 60
        f.sample.update(cpu_window_seconds=60, sampled_at=f.now[0])

    def test_one_deferred_attempt_after_warmup_with_all_gates(self):
        f = self.make_service()
        f.service.reconcile(boot=True)
        self.assertNotIn('bound_start', f.events)
        self.assertEqual(f.item['desired_state'],'running')
        _retry_recovery(f.service, f.stop)
        self.assertNotIn('bound_start', f.events)
        self.warm(f)
        f.events.clear()
        _retry_recovery(f.service, f.stop)
        self.assertEqual(f.events.count('bound_start'),1)
        self.assertLess(f.events.index('firewall'),f.events.index('bound_start'))
        self.assertLess(f.events.index('identity'),f.events.index('bound_start'))
        self.assertLess(f.events.index('storage'),f.events.index('bound_start'))
        self.assertEqual(f.item['state'],'running')
        f.service.engine.state = 'failed'
        _retry_recovery(f.service, f.stop)
        self.assertEqual(f.events.count('bound_start'),1,'Never restart a post-recovery crash')

    def test_stop_remove_or_replacement_cancels_automatic_start(self):
        for change in ('stopped','removed','gateway','sidecar'):
            with self.subTest(change=change):
                f = self.make_service()
                f.service.reconcile(boot=True)
                if change=='stopped': f.item['desired_state']='stopped'
                elif change=='removed': f.item['active']=0
                elif change=='gateway': f.service.engine.gateway_id='d'*64
                elif change=='sidecar': f.service.engine.sidecar_id='e'*64
                self.warm(f)
                _retry_recovery(f.service,f.stop)
                self.assertNotIn('bound_start',f.events)

    def test_failures_consume_single_attempt_without_reservation_or_intent_loss(self):
        for failure in ('firewall','storage','admission','ambiguous_start'):
            with self.subTest(failure=failure):
                f = self.make_service()
                f.service.reconcile(boot=True)
                self.warm(f)
                if failure=='firewall': f.service.engine.firewall=False
                elif failure=='storage': f.evidence['disk_quota_verified']=False
                elif failure=='admission': f.sample['available_ram_bytes']=0
                elif failure=='ambiguous_start': f.service.engine.failed_start=True
                _retry_recovery(f.service,f.stop)
                attempts=f.events.count('bound_start')
                f.service.engine.firewall=True
                f.evidence['disk_quota_verified']=True
                f.sample['available_ram_bytes']=8*10**8
                f.service.engine.failed_start=False
                _retry_recovery(f.service,f.stop)
                self.assertEqual(f.events.count('bound_start'),attempts)
                self.assertEqual(f.item['desired_state'],'running')
                self.assertEqual(f.service.engine.state,'stopped')
                if failure=='ambiguous_start': self.assertIn('bound_stop',f.events)

    def test_no_candidate_for_running_or_unpersisted_container_or_non_boot_reconcile(self):
        for case in ('running','unpersisted','ordinary'):
            with self.subTest(case=case):
                f=self.make_service()
                if case=='running': f.service.engine.state='running'
                if case=='unpersisted': f.item['container_id']=None
                f.service.reconcile(boot=case!='ordinary')
                self.warm(f)
                _retry_recovery(f.service,f.stop)
                self.assertNotIn('bound_start',f.events)

    def test_stale_metrics_wait_and_timeout_or_shutdown_never_start(self):
        for cancel in ('timeout','shutdown'):
            with self.subTest(cancel=cancel):
                f=self.make_service()
                f.service.reconcile(boot=True)
                f.sample['cpu_window_seconds']=60
                f.now[0]+=30
                _retry_recovery(f.service,f.stop)
                self.assertNotIn('bound_start',f.events)
                if cancel=='timeout': f.now[0]+=300
                else: f.stop.set()
                _retry_recovery(f.service,f.stop)
                self.warm(f)
                _retry_recovery(f.service,f.stop)
                self.assertNotIn('bound_start',f.events)

    def test_no_reenrollment_after_first_boot_pass(self):
        f=self.make_service()
        self.warm(f)
        f.service.reconcile(boot=True)
        self.assertEqual(f.events.count('bound_start'),1)
        self.assertNotIn('ordinary_start', f.events)
        f.service.engine.state='stopped'
        f.sample['cpu_window_seconds']=0
        f.service.reconcile(boot=True)
        self.warm(f)
        _retry_recovery(f.service,f.stop)
        self.assertEqual(f.events.count('bound_start'),1)

    def test_failed_policy_never_enrolls(self):
        f=self.make_service()
        f.service.ollama_config={'default_model_id':'synthetic'}
        f.service._ollama_policy_file_matches=lambda evidence:False
        f.service.reconcile(boot=True)
        self.warm(f)
        _retry_recovery(f.service,f.stop)
        self.assertNotIn('bound_start',f.events)

    def test_boot_inspection_never_repairs_missing_web_attachment(self):
        from types import MethodType
        from unittest.mock import Mock
        from supervisor.docker_engine import DockerEngine
        from supervisor.tests.test_identity_bound_start import ProxyFixture
        class Pair(ProxyFixture):
            instance = 'a' * 32
        pair = Pair()
        f = self.make_service()
        f.item['container_id'] = pair.gateway_id
        f.service.engine = pair.engine
        pair.engine.inspect = MethodType(DockerEngine.inspect, pair.engine)
        pair.engine.control_ui_target = MethodType(DockerEngine.control_ui_target, pair.engine)
        pair.engine._verify_control_plane_forwarded_trust = Mock()
        pair.web['NetworkSettings']['Networks'].clear()
        f.service.reconcile(boot=True)
        self.assertTrue(all(method == 'GET' for method, _ in pair.calls), pair.calls)
        self.assertFalse(f.service._boot_candidates)

    def test_boot_post_inspection_never_stops_name_replacement(self):
        from types import MethodType
        from supervisor.docker_engine import DockerEngine
        from supervisor.tests.test_identity_bound_start import ProxyFixture
        class Pair(ProxyFixture):
            instance = 'a' * 32
        pair = Pair()
        f = self.make_service()
        f.item['container_id'] = pair.gateway_id
        f.service.engine = pair.engine
        pair.engine.inspect = MethodType(DockerEngine.inspect, pair.engine)
        start = pair.engine.start_bound
        def replaced(*args):
            result = start(*args)
            pair.sidecar = copy.deepcopy(pair.sidecar)
            pair.sidecar['Id'] = 'd' * 64
            pair.sidecar['HostConfig']['Privileged'] = True
            return result
        pair.engine.start_bound = replaced
        self.warm(f)
        f.service.reconcile(boot=True)
        pair.engine._stop_proxy_containers.assert_not_called()
        self.assertFalse(any('/containers/' + 'd'*64 + '/' in path
                             for method, path in pair.calls if method == 'POST'))
        self.assertEqual(pair.sidecar['State']['Status'], 'running')

    def test_service_drives_real_engine_pair_checks_over_synthetic_transport(self):
        from types import MethodType
        from supervisor.docker_engine import DockerEngine
        from supervisor.tests.test_identity_bound_start import ProxyFixture
        class Pair(ProxyFixture):
            instance = 'a' * 32
        pair = Pair()
        f = self.make_service()
        f.service.engine = pair.engine
        pair.engine.inspect = MethodType(DockerEngine.inspect, pair.engine)
        f.item['container_id'] = pair.gateway_id
        f.evidence['host_path'] = pair.spec['host_path']
        f.item['storage'] = json.dumps(f.evidence, sort_keys=True, separators=(',', ':'))
        f.service.reconcile(boot=True)
        self.assertEqual(set(f.service._boot_candidates), {f.item['id']})
        self.assertTrue(all(method == 'GET' for method, _ in pair.calls))
        self.warm(f)
        _retry_recovery(f.service, f.stop)
        starts = [path for method, path in pair.calls if method == 'POST' and path.endswith('/start')]
        self.assertEqual(starts, ['/containers/' + pair.gateway_id + '/start',
                                  '/containers/' + pair.sidecar_id + '/start'])
        self.assertEqual(f.item['state'], 'running')
        self.assertEqual(pair.gateway['State']['Status'], 'running')
        self.assertEqual(pair.sidecar['State']['Status'], 'running')
        pair.gateway['State']['Status'] = 'exited'
        _retry_recovery(f.service, f.stop)
        self.assertEqual(starts, [path for method, path in pair.calls
                                 if method == 'POST' and path.endswith('/start')])

    def test_unverified_boolean_containment_is_reported(self):
        import io
        from contextlib import redirect_stderr
        f = self.make_service()
        f.service.reconcile(boot=True)
        self.warm(f)
        f.service.engine.failed_start = True
        f.service.engine.stop_bound = lambda *args: False
        output = io.StringIO()
        with redirect_stderr(output):
            _retry_recovery(f.service, f.stop)
        self.assertIn('containment unverified', output.getvalue())
        self.assertEqual(f.service.engine.state, 'running')

    def test_initial_start_never_adopts_replacement_gateway(self):
        f = self.make_service()
        self.warm(f)
        start = f.service.engine.start_bound
        def replaced(*args):
            result = start(*args)
            f.service.engine.gateway_id = 'd' * 64
            return result
        f.service.engine.start_bound = replaced
        f.service.reconcile(boot=True)
        self.assertIn('bound_stop', f.events)
        self.assertEqual(f.item['container_id'], 'b' * 64)

    def test_manual_model_reconcile_does_not_restart_unrelated_crash(self):
        f=self.make_service()
        self.warm(f)
        f.service.engine.state='failed'
        f.service.reconcile(recover_ids=set())
        self.assertNotIn('ordinary_start',f.events)

if __name__=='__main__': unittest.main()
