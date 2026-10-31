#!/usr/bin/env python3
"""One portable integration scenario: real HTTP/SQLite, FAKE Docker/XFS/metrics.

Never connects to Docker, mounts filesystems, assigns quotas or uses real users.
This is NOT VM acceptance. Requires only the project's already available web deps.
"""
from dataclasses import asdict
import hashlib
import http.client
from http.server import HTTPServer
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from control_plane.api import create_router
from control_plane.store import DraftStore
from control_plane.runtime import SupervisorClient
from supervisor.config import validate_profile
from supervisor.runtime_store import RuntimeStore, canonical
from supervisor.service import RuntimeApplication, create_handler


class FakeMetrics:
    def snapshot(self):
        return dict(sampled_at=100.0, cpu_window_seconds=60.0, cpu_percent=5.0,
                    total_ram_bytes=8 * 1024**3, available_ram_bytes=6 * 1024**3,
                    total_cpu_millicores=8000, total_disk_bytes=50 * 1024**3,
                    free_disk_bytes=40 * 1024**3)


class FakeVolumes:
    def __init__(self):
        self.verified = True
        self.purge_calls = 0
        self.purged = set()

    def prepare(self, instance_id, disk_bytes):
        return self.verify(instance_id, disk_bytes)
    def verify(self, instance_id, disk_bytes):
        return dict(host_path='/mnt/integration-fixture/instances/' + instance_id,
                    project_id=123, disk_quota_verified=self.verified)
    def purge(self, instance_id, disk_bytes, expected_project_id=None):
        self.purge_calls += 1
        if self.purge_calls == 1:
            raise OSError('synthetic interrupted purge')
        assert expected_project_id == 123 and disk_bytes == 10 * 1024**3
        self.purged.add(instance_id)
        return dict(purged=True, project_id=expected_project_id)


class FakeEngine:
    def __init__(self):
        self.containers, self.creates = {}, 0
    def inspect(self, instance_id):
        return dict(self.containers.get(instance_id, dict(state='absent', gateway='unknown', container_id=None)))
    def create(self, instance_id, host_path, limits, token):
        if instance_id not in self.containers:
            self.creates += 1
            self.containers[instance_id] = dict(state='created', gateway='unknown', container_id=instance_id * 2)
        return self.containers[instance_id]['container_id']
    def start(self, instance_id):
        self.containers[instance_id].update(state='running', gateway='ready')
    def stop(self, instance_id):
        self.containers[instance_id].update(state='stopped', gateway='not_ready')
    def restart(self, instance_id):
        self.start(instance_id)
    def remove(self, instance_id):
        self.containers.pop(instance_id, None)


async def smoke_identity(request: Request):
    # Test-only identity provider, never imported by the production bootstrap.
    owner = {'Bearer smoke-alice': 'alice', 'Bearer smoke-bob': 'bob'}.get(request.headers.get('authorization', ''))
    if owner is None:
        raise HTTPException(401, 'Synthetic smoke identity required')
    request.state.auth_type = 'jwt'
    request.state.claims = {'typ': 'session'}
    return SimpleNamespace(id=owner, name=owner, role='user')


def main():
    with TemporaryDirectory() as temporary:
        folder = Path(temporary)
        profile = validate_profile(dict(schema_version=1, profile_version='integration-fixture-v1', mode='lab',
            storage=dict(backend='xfs_project_quota', mountpoint='/mnt/integration-fixture',
                         expected_uuid='11111111-2222-4333-8444-555555555555'),
            agent_limits=dict(ram_bytes=2 * 1024**3, cpu_millicores=1000, pids_limit=256, disk_bytes=10 * 1024**3)))
        config = dict(state_dir=str(folder), image='sha256:' + 'a' * 64,
                      capacity_ram_bytes=8 * 1024**3, capacity_cpu_millicores=4000,
                      capacity_disk_bytes=40 * 1024**3, disk_floor_bytes=1024**3)
        fingerprint = hashlib.sha256(canonical(asdict(profile)).encode('ascii')).hexdigest()
        store = RuntimeStore(folder / 'runtime.sqlite3', profile.profile_version, fingerprint)
        engine, volumes = FakeEngine(), FakeVolumes()
        initialization_attempts = []
        def initialize(instance, _evidence):
            import json
            settings = json.loads(instance['settings'])
            initialization_attempts.append(settings)
            if len(initialization_attempts) == 1:
                raise RuntimeError('synthetic interrupted initialization')
        controller = RuntimeApplication(config, profile, store, volumes, engine, FakeMetrics(),
                                        clock=lambda: 100.0, initialize=initialize)
        token = 'synthetic_smoke_credential_' + 'x' * 40
        (folder / 'token').write_text(token, encoding='ascii')
        server = HTTPServer(('127.0.0.1', 0), create_handler(controller, token))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        class TestTransport(http.client.HTTPConnection):
            def __init__(self, _socket_path, timeout=120):
                super().__init__('127.0.0.1', server.server_port, timeout=timeout)
        try:
            runtime = SupervisorClient('/synthetic-not-a-real-socket', folder / 'token')
            app = FastAPI()
            app.include_router(create_router(smoke_identity, DraftStore(folder / 'drafts.sqlite3'), runtime=runtime))
            base = '/api/v1/agent-platform/me'
            alice, bob = {'Authorization': 'Bearer smoke-alice'}, {'Authorization': 'Bearer smoke-bob'}
            with patch('control_plane.runtime.UnixConnection', TestTransport), TestClient(app) as web:
                assert web.get(base).status_code == 401
                saved = web.put(base + '/settings', headers=alice, json=dict(
                    settings=dict(name='Original snapshot', instructions='Original instructions'), revision=0))
                assert saved.status_code == 200, saved.text
                bob_saved = web.put(base + '/settings', headers=bob, json=dict(
                    settings=dict(name='Bob agent', instructions='Bob instructions'), revision=0))
                assert bob_saved.status_code == 200, bob_saved.text
                def action(name, key, headers=alice, settings_revision=1, instance_id=None):
                    payload: dict[str, object] = dict(action=name, idempotency_key=key,
                                   settings_revision=settings_revision)
                    if name == 'purge':
                        payload['instance_id'] = instance_id
                    return web.post(base + '/actions', headers=headers, json=payload)
                failed = action('create', 'create-1')
                assert failed.status_code == 503, failed.text
                pending = web.get(base, headers=alice).json()['runtime']
                assert pending['state'] == 'failed'
                assert pending['pending_create_key'] == 'create-1'
                assert pending['pending_create_revision'] == 1
                changed = web.put(base + '/settings', headers=alice, json=dict(
                    settings=dict(name='Newer draft', instructions='Changed after pending create'), revision=1))
                assert changed.status_code == 200 and changed.json()['draft']['revision'] == 2
                stale = web.post(base + '/actions', headers=alice, json=dict(
                    action='create', idempotency_key='stale-new-key', settings_revision=1))
                assert stale.status_code == 409 and stale.json()['detail']['code'] == 'revision_conflict'
                resumed = web.post(base + '/actions', headers=alice, json=dict(
                    action='create', idempotency_key=pending['pending_create_key'], settings_revision=pending['pending_create_revision']))
                created = resumed
                assert created.status_code == 200, created.text
                data = created.json()
                identifier = data['runtime']['instance_id']
                assert data['runtime']['state'] == 'running'
                assert data['capabilities']['provisioning'], 'An existing instance must not reserve a second slot to start'
                assert initialization_attempts == [
                    {'name': 'Original snapshot', 'instructions': 'Original instructions'},
                    {'name': 'Original snapshot', 'instructions': 'Original instructions'},
                ], 'Recovery must resume using the immutable original settings snapshot'
                foreign = web.get(base, headers=bob).json()
                assert foreign['runtime']['instance_id'] is None and identifier not in str(foreign)
                injected = web.post(base + '/actions', headers=bob, json=dict(
                    action='stop', idempotency_key='spoof-1', settings_revision=1, actor_id='alice'))
                assert injected.status_code == 400
                assert action('stop', 'stop-1', settings_revision=2).json()['runtime']['state'] == 'stopped'
                replay = action('create', 'create-1')
                assert replay.status_code == 200, replay.text
                assert replay.json()['runtime']['state'] == 'stopped', 'Replay must inspect actual state, not stale running'
                assert engine.creates == 1
                assert action('start', 'start-1', settings_revision=2).json()['runtime']['state'] == 'running'
                assert action('restart', 'restart-1', settings_revision=2).json()['runtime']['state'] == 'running'
                engine.containers[identifier]['state'] = 'paused'
                assert web.get(base, headers=alice).json()['runtime']['state'] == 'paused'
                engine.containers[identifier]['state'] = 'restarting'
                assert web.get(base, headers=alice).json()['runtime']['state'] == 'restarting'
                engine.containers[identifier]['state'] = 'running'
                bob_create = web.post(base + '/actions', headers=bob, json=dict(
                    action='create', idempotency_key='bob-create-1', settings_revision=1))
                assert bob_create.status_code == 200, bob_create.text
                bob_id = bob_create.json()['runtime']['instance_id']
                assert bob_id != identifier and engine.creates == 2
                volumes.verified = False
                controller.reconcile()
                assert engine.inspect(identifier)['state'] == 'stopped', 'Unverified storage must not leave an adopted runtime running'
                volumes.verified = True
                assert action('remove', 'remove-1', settings_revision=2).json()['runtime']['state'] == 'removed'
                retained = web.get(base, headers=alice).json()['retained']
                assert [item['instance_id'] for item in retained] == [identifier]
                assert web.get(base, headers=bob).json()['retained'] == []
                assert store.totals() == (profile.agent_limits.ram_bytes, profile.agent_limits.cpu_millicores,
                                          2 * profile.agent_limits.disk_bytes), 'Retained disk must remain reserved'
                recreated = web.post(base + '/actions', headers=alice, json=dict(
                    action='create', idempotency_key='create-after-remove', settings_revision=2))
                assert recreated.status_code == 200, recreated.text
                new_identifier = recreated.json()['runtime']['instance_id']
                assert new_identifier not in {identifier, bob_id}
                assert 'pending_create_key' not in recreated.json()['runtime'], 'Removed create keys must not attach to a new instance'
                assert engine.creates == 3
                assert web.get(base, headers=bob).json()['retained'] == []

                foreign_purge = action('purge', 'foreign-purge', headers=bob,
                                       settings_revision=1, instance_id=identifier)
                assert foreign_purge.status_code == 404, foreign_purge.text
                assert volumes.purge_calls == 0, 'A foreign owner must not reach storage deletion'
                purge_payload = dict(action='purge', idempotency_key='purge-retained-1',
                                     settings_revision=2, instance_id=identifier)
                before_purge = store.totals()
                failed_purge = web.post(base + '/actions', headers=alice, json=purge_payload)
                assert failed_purge.status_code == 503, failed_purge.text
                assert store.totals() == before_purge, 'Failed purge must retain its disk reservation'
                pending_purge = web.get(base, headers=alice).json()
                assert pending_purge['runtime']['instance_id'] == new_identifier
                saved_item = pending_purge['retained'][0]
                assert saved_item['instance_id'] == identifier
                assert saved_item['pending_purge_key'] == 'purge-retained-1'
                assert saved_item['pending_purge_revision'] == 2
                purged = web.post(base + '/actions', headers=alice, json=purge_payload)
                assert purged.status_code == 200, purged.text
                assert purged.json()['runtime']['instance_id'] == new_identifier, 'Purging retained data must not hide the current instance'
                assert store.instance(identifier)['state'] == 'purged'
                assert identifier in volumes.purged
                calls_after_purge = volumes.purge_calls
                replay_purge = web.post(base + '/actions', headers=alice, json=purge_payload)
                assert replay_purge.status_code == 200, replay_purge.text
                assert replay_purge.json()['runtime']['instance_id'] == new_identifier
                assert volumes.purge_calls == calls_after_purge, 'Exact purge replay must not repeat deletion'
                assert web.get(base, headers=alice).json()['retained'] == []
                assert new_identifier not in str(web.get(base, headers=bob).json())
                assert token not in str(data) and 'gateway_token' not in str(data)
            unauth = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            try:
                unauth.request('POST', '/v1/me', body=b'{}', headers={'Content-Type': 'application/json'})
                response = unauth.getresponse()
                assert response.status == 401
                response.read()
            finally:
                unauth.close()
            print('PASS: lifecycle, replay after draft revision, stale-key rejection, pending-create recovery, owner isolation, paused/restarting state, remove-retain, fresh create, and owner-scoped purge retry/replay.')
            print('Scope: FAKE Docker/XFS/metrics, real HTTP and SQLite. Linux AF_UNIX, Docker image and XFS enforcement NOT verified.')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            controller.close()
    print('Temporary integration state removed; no server left running.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
