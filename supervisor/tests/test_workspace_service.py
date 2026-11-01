"""Owner-scoped retained-workspace service tests with synthetic storage only."""
import hashlib
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from supervisor.config import validate_profile
from supervisor.runtime_store import RuntimeStore, canonical
from supervisor.service import RuntimeService, ServiceError


class RetainedWorkspaceServiceTests(unittest.TestCase):
    def test_removed_owner_can_browse_preview_and_download_only_workspace(self):
        profile = validate_profile(dict(schema_version=1, profile_version="workspace-test", mode="lab",
            storage=dict(backend="xfs_project_quota", mountpoint="/mnt/workspace-test",
                         expected_uuid="11111111-2222-4333-8444-555555555555"),
            agent_limits=dict(ram_bytes=1024, cpu_millicores=100, pids_limit=32, disk_bytes=4096)))
        fingerprint = hashlib.sha256(canonical(asdict(profile)).encode("ascii")).hexdigest()
        gib = 1024 ** 3

        class Metrics:
            def snapshot(self):
                return dict(sampled_at=100, cpu_window_seconds=60, total_ram_bytes=8*gib,
                            available_ram_bytes=7*gib, cpu_percent=5, free_disk_bytes=50*gib,
                            total_cpu_millicores=8000, total_disk_bytes=60*gib)

        class Volumes:
            def __init__(self, base):
                self.base = base
            def prepare(self, instance_id, _disk):
                workspace = self.base / instance_id / "state" / "workspace"
                workspace.mkdir(parents=True)
                (workspace / "readme.md").write_bytes("Сохранённый текст\n".encode("utf-8"))
                (workspace / "report.bin").write_bytes(b"\x00report")
                (self.base / instance_id / "state" / "credentials").mkdir()
                (self.base / instance_id / "state" / "credentials" / "token").write_text("PRIVATE_TOKEN")
                (self.base / instance_id / "secrets").mkdir()
                (self.base / instance_id / "secrets" / "credential").write_text("PRIVATE_SECRET")
            def verify(self, instance_id, _disk):
                return dict(host_path=str(self.base / instance_id), project_id=7,
                            disk_quota_verified=True)

        class Engine:
            def __init__(self):
                self.states = {}
            def inspect(self, instance_id):
                state = self.states.get(instance_id, "absent")
                return dict(state=state, gateway="unknown",
                            container_id="container-1" if state != "absent" else None)
            def create(self, instance_id, *_args):
                self.states[instance_id] = "stopped"
                return "container-1"
            def start(self, instance_id):
                self.states[instance_id] = "running"
            def remove(self, instance_id):
                self.states[instance_id] = "absent"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RuntimeStore(root / "runtime.sqlite3", profile.profile_version, fingerprint)
            try:
                service = RuntimeService(profile, store, Volumes(root / "instances"), Engine(), Metrics(),
                    capacities=(4*gib, 4000, 40*gib), disk_floor_bytes=0, clock=lambda: 100,
                    initialize=lambda *_args: None)
                created = service.action({'actor_id': 'alice', 'action': 'create',
                    'idempotency_key': 'create-workspace', 'settings_revision': 1,
                    'settings': {'name': 'Agent', 'instructions': 'test'}})
                instance_id = created['runtime']['instance_id']
                service.action({'actor_id': 'alice', 'action': 'remove',
                    'idempotency_key': 'remove-workspace', 'settings_revision': 1,
                    'settings': {'name': 'Agent', 'instructions': 'test'}})

                listing = service.retained_workspace({'actor_id': 'alice', 'instance_id': instance_id,
                    'action': 'list', 'directory': '', 'offset': 0})
                self.assertEqual([item['name'] for item in listing['entries']], ['readme.md', 'report.bin'])
                self.assertNotIn('PRIVATE_TOKEN', str(listing))
                self.assertNotIn('PRIVATE_SECRET', str(listing))
                preview = service.retained_workspace({'actor_id': 'alice', 'instance_id': instance_id,
                    'action': 'preview', 'path': 'readme.md'})
                self.assertEqual(preview['text'], 'Сохранённый текст\n')
                download = service.retained_workspace({'actor_id': 'alice', 'instance_id': instance_id,
                    'action': 'download', 'path': 'report.bin'})
                self.assertEqual(download.name, 'report.bin')
                self.assertEqual(download.content, b'\x00report')

                with self.assertRaises(ServiceError) as foreign:
                    service.retained_workspace({'actor_id': 'bob', 'instance_id': instance_id,
                        'action': 'list', 'directory': '', 'offset': 0})
                self.assertEqual(foreign.exception.status, 404)
                with self.assertRaises(ServiceError) as traversal:
                    service.retained_workspace({'actor_id': 'alice', 'instance_id': instance_id,
                        'action': 'download', 'path': '../secrets/credential'})
                self.assertEqual(traversal.exception.status, 400)
                service.action({'actor_id': 'alice', 'action': 'restore',
                    'idempotency_key': 'restore-workspace', 'settings_revision': 1,
                    'instance_id': instance_id})
                with self.assertRaises(ServiceError) as active:
                    service.retained_workspace({'actor_id': 'alice', 'instance_id': instance_id,
                        'action': 'list', 'directory': '', 'offset': 0})
                self.assertEqual(active.exception.status, 404)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
