"""Portable fallback tests plus Linux descriptor-path unit tests for retained workspaces."""
import os
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from supervisor import workspace_files
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
        with patch("supervisor.workspace_files.sys.platform", "win32"):
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
        with patch("supervisor.workspace_files.sys.platform", "win32"):
            preview = self.reader.preview("notes/hello.md")
            self.assertEqual(preview, "Привет\n")
            name, content = self.reader.download("image.bin")
            self.assertEqual(name, "image.bin")
            self.assertEqual(content, b"\x00\xffbinary")
            with self.assertRaises(WorkspaceFileError):
                self.reader.preview("image.bin")

    def test_directory_listing_is_bounded_and_paginated(self):
        with patch("supervisor.workspace_files.sys.platform", "win32"):
            for index in range(57):
                (self.workspace / f"file-{index:03d}.txt").write_text("x", encoding="utf-8")
            first = self.reader.list_directory("", 0)
            self.assertEqual(len(first["entries"]), 50)
            self.assertEqual(first["next_offset"], 50)
            second = self.reader.list_directory("", first["next_offset"])
            self.assertEqual(len(second["entries"]), 9)
            self.assertIsNone(second["next_offset"])

    def test_hardlinked_workspace_files_are_not_exposed(self):
        with patch("supervisor.workspace_files.sys.platform", "win32"):
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
        with patch("supervisor.workspace_files.sys.platform", "win32"):
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


@unittest.skipUnless(sys.platform == "linux", "Linux descriptor-based workspace tests")
class LinuxRetainedWorkspaceDescriptorTests(unittest.TestCase):
    """Exercise the Linux dirfd path with mocked trusted ownership, never chown/sudo."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "instance"
        self.state = self.root / "state"
        self.workspace = self.state / "workspace"
        (self.workspace / "notes").mkdir(parents=True)
        (self.workspace / "notes" / "hello.md").write_text("safe text\n", encoding="utf-8")
        self.outside = base / "outside"
        self.outside.mkdir()
        (self.outside / "private.txt").write_text("outside data", encoding="utf-8")
        paths = {
            "root": self.root,
            "state": self.state,
            "workspace": self.workspace,
            "notes": self.workspace / "notes",
            "hello": self.workspace / "notes" / "hello.md",
            "outside": self.outside,
            "private": self.outside / "private.txt",
        }
        self._real_stat = os.stat
        self._real_fstat = os.fstat
        self._inode_labels = {
            self._real_stat(path, follow_symlinks=False).st_ino: label
            for label, path in paths.items()
        }

    def _synthetic_stat(self, info, owner_overrides):
        label = self._inode_labels.get(info.st_ino)
        owner = (0, 0) if label == "root" else (1000, 1000)
        uid, gid = owner_overrides.get(label, owner)
        return SimpleNamespace(
            st_mode=info.st_mode, st_dev=info.st_dev, st_uid=uid, st_gid=gid,
            st_ino=info.st_ino, st_nlink=info.st_nlink, st_size=info.st_size,
            st_mtime_ns=info.st_mtime_ns,
        )

    @contextmanager
    def _linux_reader(self, *, owner_overrides=None, mount_overrides=None, host_path=None):
        owner_overrides = owner_overrides or {}
        mount_overrides = mount_overrides or {}
        open_calls = []
        real_open = os.open

        def stat_call(path, *args, **kwargs):
            return self._synthetic_stat(
                self._real_stat(path, *args, **kwargs), owner_overrides)

        def fstat_call(fd):
            return self._synthetic_stat(self._real_fstat(fd), owner_overrides)

        def mount_id(fd):
            label = self._inode_labels.get(self._real_fstat(fd).st_ino)
            return mount_overrides.get(label, 71)

        def open_call(path, flags, mode=0o777, **kwargs):
            open_calls.append((path, kwargs.get("dir_fd"), flags))
            return real_open(path, flags, mode, **kwargs)

        with ExitStack() as stack:
            stack.enter_context(patch.object(workspace_files.os, "stat", side_effect=stat_call))
            stack.enter_context(patch.object(workspace_files.os, "fstat", side_effect=fstat_call))
            stack.enter_context(patch.object(workspace_files.os, "open", side_effect=open_call))
            yield RetainedWorkspace(host_path or self.root, mount_id=mount_id), open_calls

    def test_linux_descriptor_access_accepts_trusted_owners_and_matching_mount(self):
        with self._linux_reader() as (reader, open_calls):
            self.assertEqual(reader.list_directory(""), {
                "directory": "", "entries": [{"name": "notes", "kind": "directory", "size": 0}],
                "next_offset": None,
            })
            self.assertEqual(reader.preview("notes/hello.md"), "safe text\n")
            self.assertTrue(any(dir_fd is not None for _path, dir_fd, _flags in open_calls))
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            self.assertTrue(nofollow)
            self.assertTrue(all(flags & nofollow for _path, _dir_fd, flags in open_calls))

    def test_linux_descriptor_access_rejects_wrong_root_state_or_workspace_owner(self):
        for label, wrong_owner in (
            ("root", (1000, 1000)),
            ("state", (1000, 1001)),
            ("workspace", (1000, 1001)),
        ):
            with self.subTest(directory=label):
                with self._linux_reader(owner_overrides={label: wrong_owner}) as (reader, _calls):
                    with self.assertRaises(WorkspaceFileError) as error:
                        reader.list_directory("")
                self.assertIn(error.exception.code, {"file_not_found", "workspace_unavailable"})

    def test_linux_descriptor_access_rejects_mount_identity_mismatch(self):
        for label, operation, path in (
            ("state", "list", ""),
            ("workspace", "list", ""),
            ("notes", "preview", "notes/hello.md"),
            ("hello", "preview", "notes/hello.md"),
        ):
            with self.subTest(component=label):
                with self._linux_reader(mount_overrides={label: 72}) as (reader, _calls):
                    with self.assertRaises(WorkspaceFileError):
                        (reader.list_directory(path) if operation == "list"
                         else reader.preview(path))

    def test_linux_descriptor_access_rejects_wrong_nested_entry_owner(self):
        with self._linux_reader(owner_overrides={"notes": (1000, 1001)}) as (reader, _calls):
            self.assertEqual(reader.list_directory("")["entries"], [])
        with self._linux_reader(owner_overrides={"hello": (1000, 1001)}) as (reader, _calls):
            with self.assertRaises(WorkspaceFileError):
                reader.preview("notes/hello.md")

    def test_linux_descriptor_access_fails_closed_without_mount_identity(self):
        reader = RetainedWorkspace(self.root)
        with self.assertRaises(WorkspaceFileError) as error:
            reader.list_directory("")
        self.assertEqual(error.exception.code, "workspace_unavailable")

    def test_linux_descriptor_access_rejects_symlinked_state_and_workspace(self):
        for directory in (self.state, self.workspace):
            backup = directory.with_name(directory.name + "-target")
            with self.subTest(directory=directory.name):
                directory.rename(backup)
                try:
                    directory.symlink_to(backup, target_is_directory=True)
                    with self._linux_reader() as (reader, _calls):
                        with self.assertRaises(WorkspaceFileError):
                            reader.list_directory("")
                finally:
                    if directory.is_symlink():
                        directory.unlink()
                    backup.rename(directory)

    def test_linux_descriptor_access_rejects_root_symlink(self):
        root_link = Path(self.temp.name) / "instance-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        with self._linux_reader(host_path=root_link) as (reader, _calls):
            with self.assertRaises(WorkspaceFileError) as error:
                reader.list_directory("")
        self.assertEqual(error.exception.code, "workspace_unavailable")

    def test_linux_descriptor_access_rejects_symlink_and_workspace_escape(self):
        (self.workspace / "outside-file").symlink_to(self.outside / "private.txt")
        (self.workspace / "outside-directory").symlink_to(self.outside, target_is_directory=True)
        with self._linux_reader() as (reader, _calls):
            with self.assertRaises(WorkspaceFileError):
                reader.download("../outside/private.txt")
            with self.assertRaises(WorkspaceFileError) as file_link:
                reader.download("outside-file")
            self.assertEqual(file_link.exception.code, "file_not_found")
            with self.assertRaises(WorkspaceFileError) as directory_link:
                reader.list_directory("outside-directory")
            self.assertEqual(directory_link.exception.code, "file_not_found")


if __name__ == "__main__":
    unittest.main()
