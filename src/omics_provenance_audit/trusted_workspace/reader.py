"""Conventional read-only I/O under an explicit trusted-workspace assumption.

This is NOT the Phase 1B strict native backend. Path prechecks and postchecks
have TOCTOU windows. No hostile rename/mount/device substitution is supported.
Only the current Windows local fixed NTFS development candidate is enabled.
"""

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import sys

from .models import ReadLimits


class _Refused(Exception):
    def __init__(self, code):
        self.code = code


@dataclass(slots=True)
class _Outcome:
    presence: str = "NOT_VERIFIED"
    observed_type: str | None = None
    primary: str = "NOT_STARTED"
    result: str = "NOT_STARTED"
    cleanup: tuple[str, ...] = ()
    known_bytes: int = 0
    requested: int = 0
    calls: int = 0
    counts_complete: bool = True
    size: int | None = None
    sha256: str | None = None
    data: bytes | None = None


def _normalise(path):
    value = os.fspath(path)
    if type(value) is not str or not value or "\x00" in value:
        raise _Refused("PATH_INVALID")
    if value.startswith(("\\\\", "//")) or ".." in value.replace("\\", "/").split("/"):
        raise _Refused("PATH_INVALID")
    result = Path(os.path.abspath(value))
    if len(result.drive) != 2 or result.drive[1] != ":" or not result.drive[0].isalpha():
        raise _Refused("OPEN_SAFETY_UNSUPPORTED")
    return result


def _local_ntfs(path):
    """Metadata-only volume check, not native safe-open certification."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes = [wintypes.LPCWSTR]
    drive_type.restype = wintypes.UINT
    if drive_type(path.anchor) != 3:  # DRIVE_FIXED; remote/removable are excluded.
        raise _Refused("LOCAL_FIXED_VOLUME_REQUIRED")
    volume_info = kernel.GetVolumeInformationW
    pointer = ctypes.POINTER(wintypes.DWORD)
    volume_info.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                           pointer, pointer, pointer, wintypes.LPWSTR, wintypes.DWORD]
    volume_info.restype = wintypes.BOOL
    fs_name = ctypes.create_unicode_buffer(32)
    if not volume_info(path.anchor, None, 0, None, None, None, fs_name, len(fs_name)):
        raise _Refused("OPEN_SAFETY_UNSUPPORTED")
    if fs_name.value != "NTFS":
        raise _Refused("FILESYSTEM_UNSUPPORTED")


def _attributes(info):
    attrs = getattr(info, "st_file_attributes", None)
    if type(attrs) is not int:
        raise _Refused("OPEN_SAFETY_UNSUPPORTED")
    if stat.S_ISLNK(info.st_mode) or attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise _Refused("LINK_REJECTED")
    if attrs & stat.FILE_ATTRIBUTE_OFFLINE:
        raise _Refused("OFFLINE_OBJECT_REJECTED")
    names = ("READONLY", "HIDDEN", "SYSTEM", "DIRECTORY", "ARCHIVE", "NORMAL",
             "TEMPORARY", "SPARSE_FILE", "COMPRESSED", "NOT_CONTENT_INDEXED", "ENCRYPTED")
    allowed = 0
    for name in names:
        allowed |= getattr(stat, "FILE_ATTRIBUTE_" + name, 0)
    if attrs & ~allowed:
        raise _Refused("FILE_ATTRIBUTES_UNSUPPORTED")


def _identity(info):
    if not info.st_ino or not info.st_dev:
        raise _Refused("FILE_IDENTITY_UNAVAILABLE")
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _signature(info):
    return (_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_nlink, getattr(info, "st_file_attributes", None))


def _binding_signature(info):
    # Windows path-stat and fd-stat ctime can differ on a stable new file.
    # Compare ctime before/after within each source, never across sources.
    return (_identity(info), info.st_size, info.st_mtime_ns, info.st_nlink,
            getattr(info, "st_file_attributes", None))


def _io_code(exc):
    if isinstance(exc, PermissionError):
        return "ACCESS_DENIED"
    if isinstance(exc, FileNotFoundError):
        return "FILE_MISSING"
    return "READ_ERROR"


class _Workspace:
    def __init__(self, root, limits):
        if sys.platform != "win32" or os.name != "nt":
            raise _Refused("PLATFORM_NOT_IMPLEMENTED")
        if type(limits) is not ReadLimits:
            raise TypeError("READ_LIMITS_REQUIRED")
        self.root = _normalise(root)
        self.limits = limits
        self.total_bytes = 0
        self.total_calls = 0
        self.blocked_reason = None
        try:
            _local_ntfs(self.root)
        except (AttributeError, OSError):
            raise _Refused("OPEN_SAFETY_UNSUPPORTED") from None
        try:
            self.root_nodes = self._root_chain()
        except FileNotFoundError:
            raise _Refused("ROOT_UNAVAILABLE") from None

    def _root_chain(self):
        current = Path(self.root.anchor)
        nodes = []
        for part in (None,) + self.root.parts[1:]:
            if part is not None:
                current = current / part
            info = os.lstat(current)
            _attributes(info)
            if not stat.S_ISDIR(info.st_mode):
                raise _Refused("ROOT_NOT_DIRECTORY")
            _identity(info)
            nodes.append((current, info))
        return nodes

    def _chain(self, relative):
        if type(relative) is not str:
            raise _Refused("PATH_INVALID")
        parts = relative.split("/")
        if any(p in ("", ".", "..") for p in parts) or "\\" in relative or ":" in relative:
            raise _Refused("PATH_INVALID")
        try:
            nodes = self._root_chain()
        except FileNotFoundError:
            raise _Refused("READ_UNSTABLE") from None
        if [(p, _identity(s)) for p, s in nodes] != [
            (p, _identity(s)) for p, s in self.root_nodes
        ]:
            raise _Refused("READ_UNSTABLE")
        current = self.root
        for index, part in enumerate(parts):
            current = current / part
            info = os.lstat(current)
            _attributes(info)
            if index != len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                raise _Refused("PATH_COMPONENT_NOT_DIRECTORY")
            nodes.append((current, info))
        return nodes

    def read(self, relative, *, capture_limit=None):
        """Internal single-owner read. No public callback or injected observations.

        Exact exhaustion without a budgeted EOF returns BUDGET_ABORTED. An
        expected length or stat size never stands in for an observed EOF.
        """
        out = _Outcome()
        if self.blocked_reason:
            out.primary = out.result = self.blocked_reason
            return out
        fd = None
        phase = "PRECHECK"
        digest = None
        chunks = [] if capture_limit is not None else None
        read_pending = False
        try:
            before = self._chain(relative)
            path, metadata = before[-1]
            out.presence = "PRESENT"
            out.observed_type = "REGULAR_FILE" if stat.S_ISREG(metadata.st_mode) else "NON_REGULAR"
            if not stat.S_ISREG(metadata.st_mode):
                raise _Refused("NON_REGULAR_FILE")
            if metadata.st_nlink != 1:
                raise _Refused("HARDLINK_REJECTED")
            if metadata.st_size > self.limits.max_file_bytes:
                raise _Refused("BUDGET_ABORTED")
            if metadata.st_size > self.limits.max_total_bytes - self.total_bytes:
                raise _Refused("BUDGET_ABORTED")
            if capture_limit is not None and metadata.st_size > capture_limit:
                raise _Refused("INPUT_BYTE_LIMIT")
            _identity(metadata)
            phase = "OPEN"
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            _attributes(opened)
            if not stat.S_ISREG(opened.st_mode) or _binding_signature(opened) != _binding_signature(metadata):
                raise _Refused("READ_UNSTABLE")
            digest = hashlib.sha256() if capture_limit is None else None
            phase = "READ"
            while True:
                remaining = min(self.limits.max_file_bytes - out.known_bytes,
                                self.limits.max_total_bytes - self.total_bytes)
                if remaining <= 0 or self.total_calls >= self.limits.max_read_calls:
                    raise _Refused("BUDGET_ABORTED")
                requested = min(self.limits.block_bytes, remaining)
                out.requested += requested
                out.calls += 1
                self.total_calls += 1
                read_pending = True
                block = os.read(fd, requested)
                out.known_bytes += len(block)
                self.total_bytes += len(block)
                read_pending = False
                if not block:
                    break
                if len(block) > requested:
                    out.counts_complete = False
                    raise _Refused("READ_ERROR")
                if capture_limit is not None:
                    if out.known_bytes > capture_limit:
                        raise _Refused("INPUT_BYTE_LIMIT")
                    chunks.append(block)
                else:
                    digest.update(block)
            phase = "POSTCHECK"
            after_fd = os.fstat(fd)
            _attributes(after_fd)
            after = self._chain(relative)
            if (out.known_bytes != opened.st_size or
                _signature(after_fd) != _signature(opened) or
                _signature(after[-1][1]) != _signature(metadata) or
                _binding_signature(after[-1][1]) != _binding_signature(after_fd) or
                [(p, _identity(s)) for p, s in before] != [(p, _identity(s)) for p, s in after]):
                raise _Refused("READ_UNSTABLE")
            out.primary = "READ_COMPLETED"
        except _Refused as exc:
            out.primary = "READ_UNSTABLE" if phase == "POSTCHECK" else exc.code
        except OSError as exc:
            out.primary = _io_code(exc)
            if phase == "PRECHECK" and out.primary == "FILE_MISSING":
                out.presence = "MISSING"
            elif out.primary == "FILE_MISSING":
                out.primary = "OBJECT_DISAPPEARED" if phase == "OPEN" else "READ_UNSTABLE"
            if phase == "READ":
                out.counts_complete = False
        except KeyboardInterrupt:
            out.primary = "CANCELLED"
            if read_pending:
                out.counts_complete = False
        except Exception:
            out.primary = "INTERNAL_ERROR"
            if read_pending:
                out.counts_complete = False
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except (Exception, KeyboardInterrupt):
                    out.cleanup = ("CLOSE_UNCONFIRMED",)
        out.result = "CLEANUP_INCOMPLETE" if out.cleanup else out.primary
        if out.cleanup:
            self.blocked_reason = "PRIOR_CLEANUP_INCOMPLETE"
        elif not out.counts_complete:
            self.blocked_reason = "READ_COUNTS_INCOMPLETE"
        if out.result == "READ_COMPLETED":
            try:
                out.size = out.known_bytes
                out.sha256 = digest.hexdigest() if digest is not None else None
                out.data = b"".join(chunks) if chunks is not None else None
            except Exception:
                out.primary = out.result = "INTERNAL_ERROR"
                out.size = out.sha256 = out.data = None
        return out


def _input_bytes(path, limit):
    """Explicitly authorised declaration input, separate from payload budgets."""
    if sys.platform != "win32" or os.name != "nt":
        raise _Refused("PLATFORM_NOT_IMPLEMENTED")
    absolute = _normalise(path)
    # One bounded extra byte permits EOF at exactly the parser's byte limit.
    limits = ReadLimits(max_file_bytes=limit + 1, max_total_bytes=limit + 1)
    reader = _Workspace(absolute.parent, limits)
    out = reader.read(absolute.name, capture_limit=limit)
    if out.result != "READ_COMPLETED":
        raise _Refused(out.result)
    return out.data
