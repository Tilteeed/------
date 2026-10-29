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

    def test_lifecycle_refuses_unconnected_runtime_without_faking_success(self):
        for action in ("create", "start", "stop", "restart", "remove"):
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
