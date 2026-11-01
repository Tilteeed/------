"""Portable tests for owner-workspace file access; Linux dirfd path is VM-only."""
import os
import tempfile
import unittest
from pathlib import Path

from supervisor.workspace_files import RetainedWorkspace, WorkspaceFileError


class RetainedWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "instance"
        self.workspace = self.root / "state" / "workspace"
        self.workspace.mkdir(parents=True)
        (self.workspace / "notes").mkdir()
        (self.workspace / "notes" / "hello.md").write_bytes("Привет\n".encode("utf-8"))
        (self.workspace / "image.bin").write_bytes(b"\x00\xffbinary")
        (self.workspace / ".hidden").write_text("not exposed", encoding="utf-8")
        (self.root / "secrets").mkdir()
        (self.root / "secrets" / "token").write_text("PRIVATE_SECRET", encoding="utf-8")
        (self.root / "state" / "credentials").mkdir()
        (self.root / "state" / "credentials" / "credential.json").write_text(
            "PRIVATE_CREDENTIAL", encoding="utf-8")
        self.reader = RetainedWorkspace(self.root)

    def test_lists_only_workspace_entries_without_following_symlinks(self):
        try:
            (self.workspace / "leak").symlink_to(self.root / "secrets" / "token")
        except (OSError, NotImplementedError):
            pass
        entries = self.reader.list_directory("")
        self.assertEqual([entry["name"] for entry in entries["entries"]],
                         ["image.bin", "notes"])
        self.assertEqual(entries["directory"], "")
        self.assertNotIn("PRIVATE_SECRET", str(entries))
        nested = self.reader.list_directory("notes")
        self.assertEqual(nested["entries"], [{"name": "hello.md", "kind": "file", "size": 13}])

    def test_previews_utf8_as_text_and_downloads_bounded_bytes(self):
        preview = self.reader.preview("notes/hello.md")
        self.assertEqual(preview, "Привет\n")
        name, content = self.reader.download("image.bin")
        self.assertEqual(name, "image.bin")
        self.assertEqual(content, b"\x00\xffbinary")
        with self.assertRaises(WorkspaceFileError):
            self.reader.preview("image.bin")

    def test_directory_listing_is_bounded_and_paginated(self):
        for index in range(57):
            (self.workspace / f"file-{index:03d}.txt").write_text("x", encoding="utf-8")
        first = self.reader.list_directory("", 0)
        self.assertEqual(len(first["entries"]), 50)
        self.assertEqual(first["next_offset"], 50)
        second = self.reader.list_directory("", first["next_offset"])
        self.assertEqual(len(second["entries"]), 9)
        self.assertIsNone(second["next_offset"])

    def test_hardlinked_workspace_files_are_not_exposed(self):
        source = self.workspace / "notes" / "hello.md"
        alias = self.workspace / "alias.md"
        try:
            os.link(source, alias)
        except OSError:
            self.skipTest("Hard links are unavailable on this test filesystem")
        self.assertNotIn("alias.md", [entry["name"] for entry in self.reader.list_directory("")["entries"]])
        with self.assertRaises(WorkspaceFileError):
            self.reader.preview("notes/hello.md")

    def test_rejects_traversal_hidden_paths_and_symlinks(self):
        for path in ("../secrets/token", "/etc/passwd", "notes/../../secrets/token", ".hidden"):
            with self.subTest(path=path), self.assertRaises(WorkspaceFileError):
                self.reader.download(path)
        link = self.workspace / "outside-link"
        try:
            link.symlink_to(self.root / "secrets" / "token")
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable on this test host")
        with self.assertRaises(WorkspaceFileError):
            self.reader.download("outside-link")


if __name__ == "__main__":
    unittest.main()
