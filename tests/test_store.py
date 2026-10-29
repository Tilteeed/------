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
