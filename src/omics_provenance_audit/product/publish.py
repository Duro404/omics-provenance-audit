"""R05 on a trusted Windows local fixed NTFS output directory.

Only an exclusive directory is used. Windows rename has no-replace semantics;
no exists/replace sequence, rollback, final-file deletion or directory reuse.
Namespace pre/postchecks do not defend against hostile concurrent replacement.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

from ..trusted_workspace.models import ReadLimits
from ..trusted_workspace.reader import _Workspace, _normalise, _identity, _input_bytes, _Refused
from .projection import MAX_REPORT_BYTES, ReportError, json_bytes
from .render import render_companions

COMPANIONS = ("audit_details.tsv", "audit.md")
REPORT_NAMES = COMPANIONS + ("audit.json",)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("REPORT_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ReportError("REPORT_JSON_INVALID")


def strict_json(data):
    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_unique,
                          parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ReportError("REPORT_JSON_INVALID") from None


def _read(path):
    try:
        return _input_bytes(path, MAX_REPORT_BYTES)
    except (OSError, _Refused, ValueError, TypeError):
        raise ReportError("REPORT_READ_FAILED") from None


def verify_package(output_dir):
    """Consumer check, not origin authentication or scientific verification.

    Returns the parsed JSON only after current companion bytes match the fixed
    names, exact lengths and digests. It never trusts report_complete alone.
    """
    directory = Path(output_dir)
    document = strict_json(_read(directory / "audit.json"))
    required = {"report_schema_version", "tool_version", "policy_version", "audit_completion",
                "report_complete", "input_manifest_digest", "report_profile", "scope", "records",
                "runs", "findings", "coverage", "report_files"}
    if (type(document) is not dict or not required <= document.keys() or
        document["report_schema_version"] != "1.0" or document["report_complete"] is not True or
        document["audit_completion"] not in ("COMPLETE", "PARTIAL", "REJECTED") or
        type(document["report_files"]) is not dict or set(document["report_files"]) != set(COMPANIONS)):
        raise ReportError("REPORT_PACKAGE_INVALID")
    for name in COMPANIONS:
        expected = document["report_files"][name]
        if (type(expected) is not dict or set(expected) != {"bytes", "sha256"} or
            type(expected["bytes"]) is not int or not 0 <= expected["bytes"] <= MAX_REPORT_BYTES or
            type(expected["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]) is None):
            raise ReportError("REPORT_PACKAGE_INVALID")
        data = _read(directory / name)
        if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ReportError("REPORT_COMPANION_MISMATCH")
    return document


@dataclass(frozen=True, slots=True)
class ReportReceipt:
    audit_completion: str
    report_complete: bool = True


class OutputTransaction:
    report_names = REPORT_NAMES

    def __init__(self, *, root, input_paths, output_dir):
        if sys.platform != "win32" or os.name != "nt":
            raise ReportError("REPORT_PLATFORM_UNSUPPORTED")
        try:
            self.directory, workspace = _normalise(output_dir), _normalise(root)
            inputs = tuple(_normalise(path) for path in input_paths)
            if (self.directory.is_relative_to(workspace) or workspace.is_relative_to(self.directory) or
                any(path == self.directory or path.is_relative_to(self.directory) for path in inputs)):
                raise ReportError("OUTPUT_INPUT_OVERLAP")
            # Existing parent only. Its full ancestor chain must be local NTFS,
            # ordinary directories and not links/reparse/offline objects.
            self.parent = _Workspace(self.directory.parent, ReadLimits())
            self.parent_signature = tuple((str(path), _identity(info)) for path, info in self.parent.root_nodes)
            os.mkdir(self.directory)  # Exclusive; an existing name always fails.
            self.workspace = _Workspace(self.directory, ReadLimits())
            self.signature = tuple((str(path), _identity(info)) for path, info in self.workspace.root_nodes)
        except ReportError:
            raise
        except (OSError, ValueError, TypeError, _Refused):
            raise ReportError("OUTPUT_DIRECTORY_REFUSED") from None

    def _guard(self):
        try:
            current = tuple((str(path), _identity(info)) for path, info in self.workspace._root_chain())
            if current != self.signature or current[:-1] != self.parent_signature:
                raise ReportError("OUTPUT_DIRECTORY_CHANGED")
        except (OSError, _Refused):
            raise ReportError("OUTPUT_DIRECTORY_CHANGED") from None

    def _stage(self, data):
        if type(data) is not bytes or len(data) > MAX_REPORT_BYTES:
            raise ReportError("REPORT_BYTE_LIMIT")
        self._guard()
        name = ".pending-" + uuid.uuid4().hex
        path = self.directory / name
        # No automatic deletion on error. An uncommitted residue is harmless
        # to the consumer and must never be reused as a successful package.
        with path.open("xb") as stream:
            count = stream.write(data)
            if count != len(data):
                raise ReportError("REPORT_SHORT_WRITE")
            stream.flush()
            os.fsync(stream.fileno())
        self._guard()
        if _read(path) != data:
            raise ReportError("REPORT_STAGE_MISMATCH")
        return path

    def _publish_no_replace(self, temporary, name):
        self._guard()
        if name not in self.report_names or temporary.parent != self.directory:
            raise ReportError("REPORT_PUBLICATION_INVALID")
        # Windows os.rename uses MoveFileExW without REPLACE_EXISTING. The
        # source and target here share the same checked NTFS directory/volume.
        # On other OSs this call would have different semantics: never enabled.
        if sys.platform != "win32":
            raise ReportError("REPORT_PUBLICATION_UNSUPPORTED")
        os.rename(temporary, self.directory / name)
        self._guard()

    def commit(self, facts):
        try:
            companions = render_companions(facts)
            staged = {name: self._stage(companions[name]) for name in COMPANIONS}
            report_files = {}
            for name in COMPANIONS:
                self._publish_no_replace(staged[name], name)
                actual = _read(self.directory / name)
                if actual != companions[name]:
                    raise ReportError("REPORT_COMPANION_MISMATCH")
                report_files[name] = dict(bytes=len(actual), sha256=hashlib.sha256(actual).hexdigest())
            document = facts.document()
            document["report_files"] = report_files
            document["report_complete"] = True
            data = json_bytes(document)
            staged_json = self._stage(data)
            if strict_json(_read(staged_json)) != document:
                raise ReportError("REPORT_JSON_INVALID")
            for name in COMPANIONS:
                if _read(self.directory / name) != companions[name]:
                    raise ReportError("REPORT_COMPANION_MISMATCH")
            self._publish_no_replace(staged_json, "audit.json")  # Only commit point.
            self._guard()
            if _read(self.directory / "audit.json") != data:
                raise ReportError("REPORT_JSON_MISMATCH")
            verified = verify_package(self.directory)
            if verified != document:
                raise ReportError("REPORT_PACKAGE_INVALID")
            return ReportReceipt(document["audit_completion"])
        except ReportError:
            raise
        except (OSError, ValueError, TypeError, _Refused, KeyboardInterrupt):
            raise ReportError("REPORT_SUBMISSION_FAILED") from None
