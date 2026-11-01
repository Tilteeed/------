"""HTTP contract tests. Test identities are injected ONLY inside this test file.

These tests do not claim to verify real Open WebUI sessions or passwords.
"""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from control_plane import api
from control_plane.policy import validate_agent_input
from control_plane.runtime import RuntimeRejected, SupervisorClient
from control_plane.store import DraftStore


async def verified_test_user(request: Request):
    identities = {
        "Bearer alice-session": ("alice", "user", "jwt", "session"),
        "Bearer bob-session": ("bob", "user", "jwt", "session"),
        "Bearer admin-session": ("admin", "admin", "jwt", "session"),
        "Bearer pending-session": ("pending", "pending", "jwt", "session"),
        "Bearer automation-session": ("alice", "user", "jwt", "automation"),
        "Bearer sk-api-key": ("alice", "user", "api_key", None),
    }
    # Mirror upstream cookie fallback to prove our explicit-Bearer gate blocks it.
    credential = request.headers.get("authorization")
    if credential is None and request.cookies.get("token"):
        credential = "Bearer " + request.cookies["token"]
    identity = identities.get(credential)
    if identity is None:
        raise HTTPException(401, "Unauthenticated test request")
    identifier, role, auth_type, typ = identity
    request.state.auth_type = auth_type
    request.state.claims = {"typ": typ}
    return SimpleNamespace(id=identifier, name=identifier.title(), role=role)


class PlatformApiTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(api, "create_router"), "Platform router is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DraftStore(Path(self.temp.name) / "platform.sqlite3")
        app = FastAPI()
        app.include_router(api.create_router(verified_test_user, self.store))
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.base = "/api/v1/agent-platform/me"
        self.alice = {"Authorization": "Bearer alice-session"}
        self.bob = {"Authorization": "Bearer bob-session"}

    def test_restore_does_not_forward_current_draft_to_supervisor(self):
        client = SupervisorClient('unused.sock', 'unused.token')
        sent = {}
        client._request = lambda path, payload, *, response_kind='runtime', response_limit=65536: sent.update(path=path, payload=payload) or {}
        request = {'action': 'restore', 'idempotency_key': 'restore-key',
                   'settings_revision': 2, 'instance_id': 'b' * 32}
        client.action('alice', request, {'name': 'Draft', 'instructions': 'PRIVATE_DRAFT_TEXT'})
        self.assertEqual(sent, {'path': '/v1/actions', 'payload': {
            **request, 'actor_id': 'alice'}})

    def test_unauthenticated_requests_are_denied(self):
        self.assertEqual(self.client.get(self.base).status_code, 401)
        self.assertEqual(self.client.get(self.base, headers={"X-OpenWebUI-User-Id": "alice"}).status_code, 401)

    def test_nonhuman_pending_and_cookie_only_access_is_denied(self):
        for token in ("pending-session", "automation-session", "sk-api-key"):
            with self.subTest(token=token):
                response = self.client.get(self.base, headers={"Authorization": "Bearer " + token})
                self.assertIn(response.status_code, (401, 403))
        self.client.cookies.set("token", "alice-session")
        self.assertEqual(self.client.get(self.base).status_code, 401)

    def test_status_is_honest_and_scoped_to_current_user(self):
        response = self.client.get(self.base, headers=self.alice)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["user"]["id"], "alice")
        self.assertIn("draft", data)
        self.assertIsNone(data["draft"])
        self.assertTrue(all(value is False for value in data["capabilities"].values()))
        self.assertEqual(data["runtime"]["state"], "not_connected")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertNotIn("token", data)

    def test_settings_save_uses_server_identity_and_remains_private(self):
        payload = {"settings": {"name": "Личный агент", "instructions": "Только мои данные"}, "revision": 0}
        saved = self.client.put(self.base + "/settings", headers=self.alice, json=payload)
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual(saved.json()["draft"]["revision"], 1)
        self.assertEqual(self.client.get(self.base, headers=self.alice).json()["draft"]["name"], "Личный агент")
        self.assertIsNone(self.client.get(self.base, headers=self.bob).json()["draft"])
        self.assertIsNone(self.client.get(self.base, headers={"Authorization": "Bearer admin-session"}).json()["draft"])
        stale = self.client.put(self.base + "/settings", headers=self.alice, json=payload)
        self.assertEqual(stale.status_code, 409)

    def test_mutation_rejects_cross_origin_wrong_content_type_and_oversize(self):
        path = self.base + "/settings"
        body = '{"settings":{"name":"Agent"},"revision":0}'
        for origin in ("https://attacker.invalid", "null"):
            result = self.client.put(path, headers={**self.alice, "Origin": origin, "Content-Type": "application/json"}, content=body)
            self.assertEqual(result.status_code, 403, result.text)
        result = self.client.put(path, headers={**self.alice, "Content-Type": "text/plain"}, content=body)
        self.assertEqual(result.status_code, 415)
        result = self.client.put(path, headers={**self.alice, "Content-Type": "application/json"}, content=" " * 65537)
        self.assertEqual(result.status_code, 413)
        duplicate = '{"settings":{"name":"A"},"settings":{"name":"B"},"revision":0}'
        result = self.client.put(path, headers={**self.alice, "Content-Type": "application/json"}, content=duplicate)
        self.assertEqual(result.status_code, 400)
        self.assertIsNone(self.store.get("alice"))

    def test_events_are_private_and_settings_do_not_mark_runtime_ready(self):
        payload = {"settings": {"name": "Agent", "instructions": "private text"}, "revision": 0}
        self.assertEqual(self.client.put(self.base + "/settings", headers=self.alice, json=payload).status_code, 200)
        events = self.client.get(self.base + "/events", headers=self.alice)
        self.assertEqual(events.status_code, 200, events.text)
        self.assertEqual(events.json()["events"][0]["kind"], "settings.saved")
        self.assertNotIn("private text", events.text)
        self.assertEqual(self.client.get(self.base + "/events", headers=self.bob).json(), {"events": []})
        self.assertEqual(self.client.get(self.base, headers=self.alice).json()["runtime"]["state"], "not_connected")

    def test_purge_route_replays_old_revision_but_rejects_new_stale_request(self):
        self.store.save('alice', validate_agent_input({'name': 'Agent', 'instructions': 'initial'}), expected_revision=0)

        class Runtime:
            def __init__(self):
                self.calls = []

            def replay(self, _actor, payload):
                if any(call['idempotency_key'] == payload['idempotency_key'] for call in self.calls):
                    return {'runtime': {'state': 'purged', 'instance_id': payload['instance_id']},
                            'capabilities': {}, 'retained': [],
                            'operation': {'id': 'op', 'status': 'completed'}}
                raise RuntimeRejected(404, 'operation_not_found', 'not found')

            def action(self, _actor, payload, _draft):
                self.calls.append(payload.copy())
                return {'runtime': {'state': 'purged', 'instance_id': payload['instance_id']},
                        'capabilities': {}, 'retained': [],
                        'operation': {'id': 'op', 'status': 'completed'}}

        runtime = Runtime()
        app = FastAPI()
        app.include_router(api.create_router(verified_test_user, self.store, runtime=runtime))
        client = TestClient(app)
        self.addCleanup(client.close)
        path = self.base + '/actions'
        payload = {'action': 'purge', 'idempotency_key': 'purge-key-1',
                   'settings_revision': 1, 'instance_id': 'a' * 32}
        first = client.post(path, headers=self.alice, json=payload)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(len(runtime.calls), 1)
        self.store.save('alice', validate_agent_input({'name': 'Agent v2', 'instructions': 'new draft'}), expected_revision=1)
        replay = client.post(path, headers=self.alice, json=payload)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(len(runtime.calls), 1)
        stale = {**payload, 'idempotency_key': 'purge-key-2'}
        result = client.post(path, headers=self.alice, json=stale)
        self.assertEqual(result.status_code, 409)
        self.assertEqual(len(runtime.calls), 1)
        malformed = {**payload, 'instance_id': '../other'}
        self.assertEqual(client.post(path, headers=self.alice, json=malformed).status_code, 400)
        restore = {'action': 'restore', 'idempotency_key': 'restore-key-1',
                   'settings_revision': 2, 'instance_id': 'b' * 32}
        restored = client.post(path, headers=self.alice, json=restore)
        self.assertEqual(restored.status_code, 200, restored.text)
        self.assertEqual(runtime.calls[-1]['action'], 'restore')
        self.assertEqual(runtime.calls[-1]['instance_id'], 'b' * 32)
        missing_target = dict(restore)
        missing_target.pop('instance_id')
        self.assertEqual(client.post(path, headers=self.alice, json=missing_target).status_code, 400)
        bad_target = {**restore, 'idempotency_key': 'restore-key-2', 'instance_id': '../other'}
        self.assertEqual(client.post(path, headers=self.alice, json=bad_target).status_code, 400)

    def test_retained_workspace_routes_require_owner_session_and_set_download_headers(self):
        class Runtime:
            def __init__(self):
                self.calls = []
            def workspace_list(self, actor_id, instance_id, directory, offset):
                self.calls.append(("list", actor_id, instance_id, directory, offset))
                return {"directory": directory, "entries": [{"name": "note.md", "kind": "file", "size": 5}],
                        "next_offset": None}
            def workspace_preview(self, actor_id, instance_id, path):
                self.calls.append(("preview", actor_id, instance_id, path))
                return {"text": "hello"}
            def workspace_download(self, actor_id, instance_id, path):
                self.calls.append(("download", actor_id, instance_id, path))
                return b"\\x00file"

        runtime = Runtime()
        app = FastAPI()
        app.include_router(api.create_router(verified_test_user, self.store, runtime=runtime))
        client = TestClient(app)
        self.addCleanup(client.close)
        base = self.base + "/retained/" + "a" * 32 + "/files"
        listing = client.get(base, params={"directory": "notes"}, headers=self.alice)
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertEqual(listing.json()["entries"][0]["name"], "note.md")
        preview = client.get(base + "/preview", params={"path": "notes/note.md"}, headers=self.alice)
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(preview.json(), {"text": "hello"})
        self.assertEqual(preview.headers["cache-control"], "no-store")
        download = client.get(base + "/download", params={"path": "notes/note.md"}, headers=self.alice)
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.content, b"\\x00file")
        self.assertEqual(download.headers["cache-control"], "no-store")
        self.assertEqual(download.headers["x-content-type-options"], "nosniff")
        self.assertIn("filename*=UTF-8''note.md", download.headers["content-disposition"])
        self.assertEqual(runtime.calls, [
            ("list", "alice", "a" * 32, "notes", 0),
            ("preview", "alice", "a" * 32, "notes/note.md"),
            ("download", "alice", "a" * 32, "notes/note.md"),
        ])
        before_bad_path = len(runtime.calls)
        self.assertEqual(client.get(base + "/download", params={"path": "../secrets/token"},
                                   headers=self.alice).status_code, 400)
        self.assertEqual(len(runtime.calls), before_bad_path)
        self.assertEqual(client.get(base, params={"directory": ""}).status_code, 401)
        self.assertEqual(client.get(self.base + "/retained/../files", headers=self.alice).status_code, 404)

    def test_lifecycle_refuses_unconnected_runtime_without_faking_success(self):
        for action in ("create", "start", "stop", "restart", "remove", "purge", "restore"):
            with self.subTest(action=action):
                result = self.client.post(self.base + "/actions", headers=self.alice, json={"action": action})
                self.assertEqual(result.status_code, 503, result.text)
                self.assertEqual(result.json()["detail"]["code"], "runtime_not_connected")
        self.assertIsNone(self.store.get("alice"))
        injected = self.client.post(self.base + "/actions", headers=self.alice, json={"action": "create", "image": "other"})
        self.assertEqual(injected.status_code, 400)
        self.assertEqual(self.client.get(self.base + "/actions", headers=self.alice).status_code, 405)


if __name__ == "__main__":
    unittest.main()
