import hashlib
import re
import tempfile
import unittest
from pathlib import Path

from control_plane import store
from control_plane.policy import AgentSettings


class DraftStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "platform.sqlite3"

    def test_saved_settings_are_private_and_persistent(self):
        self.assertTrue(hasattr(store, "DraftStore"), "Draft store is not implemented")
        db = store.DraftStore(self.path)
        saved = db.save("alice", AgentSettings("Агент", "По-русски"), expected_revision=0)
        self.assertEqual(saved["revision"], 1)
        self.assertEqual(saved["name"], "Агент")
        self.assertIsNone(db.get("bob"))
        reopened = store.DraftStore(self.path)
        self.assertEqual(reopened.get("alice"), saved)
        self.assertIsNone(reopened.get("bob"))

    def test_updates_require_current_revision_and_conflicts_preserve_data(self):
        db = store.DraftStore(self.path)
        first = db.save("alice", AgentSettings("Первый"), expected_revision=0)
        self.assertTrue(hasattr(store, "RevisionConflict"), "Revision checks are missing")
        for stale in (0, 2):
            with self.subTest(stale=stale):
                with self.assertRaises(store.RevisionConflict):
                    db.save("alice", AgentSettings("Подмена"), expected_revision=stale)
                self.assertEqual(db.get("alice"), first)
        updated = db.save("alice", AgentSettings("Обновлённый"), expected_revision=1)
        self.assertEqual(updated["revision"], 2)
        self.assertEqual(updated["id"], first["id"])
        with self.assertRaises(store.RevisionConflict):
            db.save("bob", AgentSettings("Нет такого"), expected_revision=1)
        self.assertIsNone(db.get("bob"))

    def test_events_are_owner_scoped_and_do_not_contain_settings(self):
        db = store.DraftStore(self.path)
        db.save("alice", AgentSettings("Agent", "sensitive instructions"), expected_revision=0)
        self.assertTrue(hasattr(db, "events"), "Event journal is missing")
        events = db.events("alice")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "settings.saved")
        self.assertEqual(set(events[0]), {"kind", "created_at"})
        self.assertNotIn("sensitive", str(events))
        self.assertEqual(db.events("bob"), [])

    def test_control_ui_launch_ticket_is_hashed_one_time_and_audience_bound(self):
        import sqlite3
        db = store.DraftStore(self.path)
        issued = db.issue_control_ui_ticket(
            "alice", "a" * 32, "https://" + "a" * 32 + ".agents.example.test", now=1000)
        ticket = issued["ticket"]
        self.assertRegex(ticket, r"^[A-Za-z0-9_-]{40,64}$")
        connection = sqlite3.connect(self.path)
        try:
            stored_hash = connection.execute(
                "SELECT ticket_hash FROM control_ui_tickets").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(stored_hash, hashlib.sha256(ticket.encode("ascii")).hexdigest())
        self.assertNotEqual(stored_hash, ticket)
        audience = "https://" + "a" * 32 + ".agents.example.test"
        with self.assertRaises(store.InvalidControlUiTicket):
            db.consume_control_ui_ticket(ticket, audience="https://other.agents.example.test", now=1001)
        redeemed = db.consume_control_ui_ticket(ticket, audience=audience, now=1001)
        self.assertEqual(redeemed, {"owner_id": "alice", "instance_id": "a" * 32,
                                    "audience": audience})
        with self.assertRaises(store.InvalidControlUiTicket):
            db.consume_control_ui_ticket(ticket, audience=audience, now=1002)

    def test_control_ui_launch_ticket_expires_at_boundary(self):
        db = store.DraftStore(self.path)
        audience = "https://" + "b" * 32 + ".agents.example.test"
        issued = db.issue_control_ui_ticket("alice", "b" * 32, audience, now=2000)
        with self.assertRaises(store.InvalidControlUiTicket):
            db.consume_control_ui_ticket(issued["ticket"], audience=audience, now=2060)

    def test_control_ui_launch_rate_limit_is_per_owner(self):
        db = store.DraftStore(self.path)
        for index in range(10):
            instance_id = f"{index:032x}"
            db.issue_control_ui_ticket(
                "alice", instance_id, f"https://{instance_id}.agents.example.test", now=3000)
        with self.assertRaises(store.LaunchRateLimited):
            db.issue_control_ui_ticket(
                "alice", "f" * 32, "https://" + "f" * 32 + ".agents.example.test", now=3001)
        other = db.issue_control_ui_ticket(
            "bob", "f" * 32, "https://" + "f" * 32 + ".agents.example.test", now=3001)
        self.assertTrue(other["ticket"])

    def test_redeem_launch_ticket_creates_hashed_origin_bound_session(self):
        import sqlite3
        db = store.DraftStore(self.path)
        audience = "https://" + "c" * 32 + ".agents.example.test"
        issued = db.issue_control_ui_ticket("alice", "c" * 32, audience, now=4000)
        redeemed = db.redeem_control_ui_ticket(
            issued["ticket"], audience=audience, now=4001)
        session_id = redeemed["session_id"]
        self.assertRegex(session_id, r"^[A-Za-z0-9_-]{40,64}$")
        self.assertEqual(redeemed["owner_id"], "alice")
        self.assertEqual(redeemed["instance_id"], "c" * 32)
        self.assertEqual(redeemed["audience"], audience)
        connection = sqlite3.connect(self.path)
        try:
            stored_hash = connection.execute(
                "SELECT session_hash FROM control_ui_sessions").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(stored_hash, hashlib.sha256(session_id.encode("ascii")).hexdigest())
        self.assertNotEqual(stored_hash, session_id)
        self.assertEqual(db.validate_control_ui_session(session_id, audience=audience, now=4002), {
            "owner_id": "alice", "instance_id": "c" * 32, "audience": audience,
        })
        self.assertIsNone(db.validate_control_ui_session(
            session_id, audience="https://other.agents.example.test", now=4002))
        with self.assertRaises(store.InvalidControlUiTicket):
            db.redeem_control_ui_ticket(issued["ticket"], audience=audience, now=4002)

    def test_control_ui_sessions_expire_and_revoke_per_owner(self):
        db = store.DraftStore(self.path)
        def make_session(owner, instance_id):
            audience = f"https://{instance_id}.agents.example.test"
            ticket = db.issue_control_ui_ticket(owner, instance_id, audience, now=5000)["ticket"]
            return audience, db.redeem_control_ui_ticket(ticket, audience=audience, now=5001)["session_id"]
        audience_a, session_a = make_session("alice", "d" * 32)
        audience_b, session_b = make_session("bob", "e" * 32)
        pending_ticket = db.issue_control_ui_ticket(
            "alice", "d" * 32, audience_a)['ticket']
        self.assertEqual(db.revoke_control_ui_sessions("alice", now=5002), 1)
        with self.assertRaises(store.InvalidControlUiTicket):
            db.redeem_control_ui_ticket(pending_ticket, audience=audience_a, now=5003)
        self.assertIsNone(db.validate_control_ui_session(session_a, audience=audience_a, now=5003))
        self.assertIsNotNone(db.validate_control_ui_session(session_b, audience=audience_b, now=5003))
        self.assertIsNone(db.validate_control_ui_session(session_b, audience=audience_b, now=8602))

    def test_invalid_internal_inputs_cannot_bypass_validation(self):
        db = store.DraftStore(self.path)
        initial = db.save("alice", AgentSettings("Original"), expected_revision=0)
        for revision in (True, False, -1, 1.0, "1", None):
            with self.subTest(revision=revision):
                with self.assertRaises(ValueError):
                    db.save("alice", AgentSettings("Changed"), expected_revision=revision)
                self.assertEqual(db.get("alice"), initial)
        with self.assertRaises(ValueError):
            db.save("alice", AgentSettings(""), expected_revision=1)
        self.assertEqual(db.get("alice"), initial)


if __name__ == "__main__":
    unittest.main()
