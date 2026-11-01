"""Owner-workspace browsing for retained instances.

Production uses descriptor-relative, no-follow traversal on Linux. The path-based
branch exists only for portable unit tests; the privileged service is Linux-only.
"""
from contextlib import contextmanager
import errno
import heapq
import os
from pathlib import Path
import stat
import sys

MAX_DIRECTORY_ENTRIES = 50
MAX_RELATIVE_PATH = 1024
MAX_PATH_COMPONENTS = 16
MAX_PREVIEW_BYTES = 256 * 1024
MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024


class WorkspaceFileError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _parts(value, *, allow_empty=False):
    if type(value) is not str or "\x00" in value or "\\" in value:
        raise WorkspaceFileError("invalid_file_path")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise WorkspaceFileError("invalid_file_path")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise WorkspaceFileError("invalid_file_path") from None
    if len(encoded) > MAX_RELATIVE_PATH:
        raise WorkspaceFileError("invalid_file_path")
    if not value and allow_empty:
        return ()
    parts = value.split("/")
    if (value.startswith("/") or len(parts) > MAX_PATH_COMPONENTS
            or any(part in ("", ".", "..") or part.startswith(".")
                   or len(part.encode("utf-8")) > 255 for part in parts)):
        raise WorkspaceFileError("invalid_file_path")
    return tuple(parts)


class RetainedWorkspace:
    def __init__(self, host_path, *, mount_id=None):
        self.host_path = Path(host_path)
        self.mount_id = mount_id

    @staticmethod
    def _directory_flags():
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
        if not directory_flag or not nofollow_flag:
            raise WorkspaceFileError("workspace_unavailable")
        return os.O_RDONLY | directory_flag | nofollow_flag

    def _mount(self, fd):
        if not callable(self.mount_id):
            raise WorkspaceFileError("workspace_unavailable")
        try:
            return self.mount_id(fd)
        except Exception:
            raise WorkspaceFileError("workspace_unavailable") from None

    @staticmethod
    def _check_directory(info, *, device=None, owner=None):
        if (not stat.S_ISDIR(info.st_mode) or (device is not None and info.st_dev != device)
                or (owner is not None and (info.st_uid != owner or info.st_gid != owner))):
            raise WorkspaceFileError("file_not_found")

    @contextmanager
    def _workspace(self):
        if sys.platform != "linux":
            # Unit-test fallback only. Production Supervisor requires Linux/root.
            try:
                root = self.host_path
                root_info = root.lstat()
                state = root / "state"
                state_info = state.lstat()
                workspace = state / "workspace"
                workspace_info = workspace.lstat()
                for info in (root_info, state_info, workspace_info):
                    self._check_directory(info)
                if any(stat.S_ISLNK(info.st_mode) for info in (root_info, state_info, workspace_info)):
                    raise WorkspaceFileError("workspace_unavailable")
            except WorkspaceFileError:
                raise
            except OSError:
                raise WorkspaceFileError("workspace_unavailable") from None
            yield workspace
            return

        if not callable(self.mount_id):
            raise WorkspaceFileError("workspace_unavailable")
        root_fd = state_fd = workspace_fd = None
        try:
            root_fd = os.open(self.host_path, self._directory_flags())
            root_info = os.fstat(root_fd)
            self._check_directory(root_info, owner=0)
            root_mount = self._mount(root_fd)
            state_fd = os.open("state", self._directory_flags(), dir_fd=root_fd)
            state_info = os.fstat(state_fd)
            self._check_directory(state_info, device=root_info.st_dev, owner=1000)
            if self._mount(state_fd) != root_mount:
                raise WorkspaceFileError("workspace_unavailable")
            workspace_fd = os.open("workspace", self._directory_flags(), dir_fd=state_fd)
            workspace_info = os.fstat(workspace_fd)
            self._check_directory(workspace_info, device=root_info.st_dev, owner=1000)
            if self._mount(workspace_fd) != root_mount:
                raise WorkspaceFileError("workspace_unavailable")
            yield workspace_fd
        except WorkspaceFileError:
            raise
        except OSError:
            raise WorkspaceFileError("workspace_unavailable") from None
        finally:
            for fd in (workspace_fd, state_fd, root_fd):
                if fd is not None:
                    os.close(fd)

    @contextmanager
    def _open_directory(self, root, root_device, relative_parts):
        if isinstance(root, int):
            mount_id = self._mount
            fd = os.dup(root)
            try:
                for part in relative_parts:
                    child = os.open(part, self._directory_flags(), dir_fd=fd)
                    try:
                        info = os.fstat(child)
                        self._check_directory(info, device=root_device, owner=1000)
                        if mount_id(child) != mount_id(root):
                            raise WorkspaceFileError("file_not_found")
                    except BaseException:
                        os.close(child)
                        raise
                    os.close(fd)
                    fd = child
                yield fd
            except WorkspaceFileError:
                raise
            except OSError as error:
                code = "file_not_found" if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP) else "workspace_unavailable"
                raise WorkspaceFileError(code) from None
            finally:
                os.close(fd)
            return

        current = root
        try:
            root_real = root.resolve(strict=True)
            for part in relative_parts:
                current = current / part
                info = current.lstat()
                self._check_directory(info)
                if stat.S_ISLNK(info.st_mode) or not current.resolve(strict=True).is_relative_to(root_real):
                    raise WorkspaceFileError("file_not_found")
            yield current
        except WorkspaceFileError:
            raise
        except OSError:
            raise WorkspaceFileError("file_not_found") from None

    @staticmethod
    def _entry_info(info, root_device, owner_required):
        if info.st_dev != root_device:
            return None
        if stat.S_ISDIR(info.st_mode):
            if owner_required and (info.st_uid != 1000 or info.st_gid != 1000):
                return None
            return "directory", 0
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            if owner_required and (info.st_uid != 1000 or info.st_gid != 1000):
                return None
            if info.st_size >= 0:
                return "file", info.st_size
        return None

    def _verified_entry_info(self, directory_fd, name, root_device):
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return None
        candidate = self._entry_info(before, root_device, True)
        if candidate is None:
            return None
        mount_id = self._mount
        kind = candidate[0]
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if kind == "directory":
            flags |= getattr(os, "O_DIRECTORY", 0)
        try:
            fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError:
            return None
        try:
            opened = os.fstat(fd)
            if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or mount_id(fd) != mount_id(directory_fd)):
                return None
            return self._entry_info(opened, root_device, True)
        finally:
            os.close(fd)

    def list_directory(self, directory, offset=0):
        parts = _parts(directory, allow_empty=True)
        if type(offset) is not int or not 0 <= offset <= 10000:
            raise WorkspaceFileError("invalid_file_path")
        with self._workspace() as root:
            root_device = os.fstat(root).st_dev if isinstance(root, int) else root.stat().st_dev
            with self._open_directory(root, root_device, parts) as target:
                return self._list(target, root_device, directory, offset,
                                  owner_required=isinstance(target, int))

    def _list(self, target, root_device, directory, offset, *, owner_required):
        def candidates():
            with os.scandir(target) as scan:
                for entry in scan:
                    if entry.name.startswith("."):
                        continue
                    try:
                        name_bytes = entry.name.encode("utf-8", errors="strict")
                        if len(name_bytes) > 128:
                            continue
                        if isinstance(target, int):
                            kind_size = self._verified_entry_info(target, entry.name, root_device)
                        else:
                            info = os.lstat(entry.path)
                            kind_size = self._entry_info(info, root_device, owner_required)
                    except (OSError, UnicodeError):
                        continue
                    if kind_size is None:
                        continue
                    kind, size = kind_size
                    yield {"name": entry.name, "kind": kind, "size": size}

        selected = heapq.nsmallest(offset + MAX_DIRECTORY_ENTRIES + 1, candidates(),
                                   key=lambda item: item["name"].casefold())
        entries = selected[offset:offset + MAX_DIRECTORY_ENTRIES]
        next_offset = (offset + MAX_DIRECTORY_ENTRIES
                       if len(selected) > offset + MAX_DIRECTORY_ENTRIES and offset < 10000 else None)
        return {"directory": directory, "entries": entries, "next_offset": next_offset}

    def _file_bytes(self, path, maximum):
        parts = _parts(path)
        if not parts:
            raise WorkspaceFileError("invalid_file_path")
        parent_parts, name = parts[:-1], parts[-1]
        with self._workspace() as root:
            root_device = os.fstat(root).st_dev if isinstance(root, int) else root.stat().st_dev
            with self._open_directory(root, root_device, parent_parts) as parent:
                if isinstance(parent, int):
                    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
                    if not nofollow_flag:
                        raise WorkspaceFileError("workspace_unavailable")
                    flags = os.O_RDONLY | nofollow_flag | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
                    try:
                        fd = os.open(name, flags, dir_fd=parent)
                    except OSError as error:
                        code = "file_not_found" if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP) else "workspace_unavailable"
                        raise WorkspaceFileError(code) from None
                    with os.fdopen(fd, "rb") as stream:
                        if self._mount(fd) != self._mount(root):
                            raise WorkspaceFileError("file_not_found")
                        return self._read_stream(stream, maximum, root_device, owner_required=True)

                candidate = parent / name
                try:
                    before = candidate.lstat()
                    if stat.S_ISLNK(before.st_mode):
                        raise WorkspaceFileError("file_not_found")
                    stream = candidate.open("rb")
                except WorkspaceFileError:
                    raise
                except OSError:
                    raise WorkspaceFileError("file_not_found") from None
                with stream:
                    return self._read_stream(stream, maximum, root_device,
                                             owner_required=False, before=before)

    @staticmethod
    def _read_stream(stream, maximum, root_device, *, owner_required, before=None):
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_dev != root_device or info.st_nlink != 1
                or (owner_required and (info.st_uid != 1000 or info.st_gid != 1000))):
            raise WorkspaceFileError("file_not_found")
        if before is not None and (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise WorkspaceFileError("file_not_found")
        if info.st_size > maximum:
            raise WorkspaceFileError("file_too_large")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (len(data) > maximum or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or len(data) != info.st_size):
            raise WorkspaceFileError("file_changed")
        return data

    def preview(self, path):
        data = self._file_bytes(path, MAX_PREVIEW_BYTES)
        if b"\x00" in data:
            raise WorkspaceFileError("preview_not_supported")
        try:
            return data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise WorkspaceFileError("preview_not_supported") from None

    def download(self, path):
        parts = _parts(path)
        return parts[-1], self._file_bytes(path, MAX_DOWNLOAD_BYTES)
