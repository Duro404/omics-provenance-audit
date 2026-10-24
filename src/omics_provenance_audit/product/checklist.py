"""Bounded checklist parsing and explicit-directory metadata enumeration.

Only export invokes the unchanged C1 payload reader. No recursive glob, format
interpretation, scientific execution or provenance inference is performed.
Matching uses actual directory-entry spelling (case sensitive, no Unicode fold).
"""

from dataclasses import dataclass, replace
import csv
import fnmatch
import io
import json
import os
import re
import stat

from ..manifest import parse_manifest
from ..trusted_workspace import audit_bytes, ReadLimits, WORKSPACE_MODE
from ..trusted_workspace.provenance import _qualified
from ..trusted_workspace.reader import _Workspace, _Refused, _identity, _signature, _io_code
from .profile import fixed_profile
from .projection import ReportError

COLUMNS = ("step_id", "step_name", "expected_path", "required", "min_matches")


@dataclass(frozen=True, slots=True)
class ChecklistLimits:
    max_input_bytes: int = 1024**2
    max_rules: int = 1000
    max_entries: int = 20_000
    max_matches: int = 10_000  # Raw rule/entry matches before path deduplication.
    max_directories: int = 2048
    max_path_parts: int = 32

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError("CHECKLIST_LIMIT_INVALID")
        if self.max_matches > 10_000 or self.max_rules > 10_000:
            raise ValueError("CHECKLIST_LIMIT_EXCEEDS_SCHEMA_CAPACITY")


@dataclass(frozen=True, slots=True)
class Rule:
    line: int
    step_id: str | None
    step_name: str | None
    expected_path: str | None
    required: bool | None
    min_matches: int | None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ChecklistInput:
    rules: tuple[Rule, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleResult:
    rule: Rule
    state: str
    matched_paths: tuple[str, ...] = ()
    eligible_paths: tuple[str, ...] = ()
    qualified_paths: tuple[str, ...] = ()
    count_complete: bool = False
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MatchedFile:
    relative_path: str
    metadata_code: str
    observation: object = None  # Existing immutable FileAudit, when requested.
    draft_record_id: str | None = None


@dataclass(frozen=True, slots=True)
class ChecklistResult:
    input: ChecklistInput
    rules: tuple[RuleResult, ...]
    files: tuple[MatchedFile, ...]
    export_requested: bool
    manifest_bytes: bytes | None
    draft_schema_status: str
    entries_scanned: int = 0
    directories_scanned: int = 0
    raw_matches: int = 0
    tool_error: bool = False


def _path_code(value):
    # Reuse the public, frozen path/schema validator with one inert record.
    data = json.dumps({"schema_version": "1.0", "records": [{"record_id": "candidate", "relative_path": value}]}).encode()
    parsed = parse_manifest(data, "json")
    return None if parsed.schema_status == "VALID" else parsed.findings[0].code


def _pattern_code(value, limits):
    if "**" in value or "[" in value or "]" in value or "*" in value.rpartition("/")[0] or "?" in value.rpartition("/")[0]:
        return "UNSUPPORTED_WILDCARD"
    if len(value.split("/")) > limits.max_path_parts:
        return "CHECKLIST_PATH_DEPTH_LIMIT"
    return _path_code(value.replace("*", "x").replace("?", "x"))


def parse_checklist(data, limits=None):
    limits = ChecklistLimits() if limits is None else limits
    if type(limits) is not ChecklistLimits:
        raise TypeError("CHECKLIST_LIMITS_REQUIRED")
    if type(data) is not bytes:
        return ChecklistInput(errors=("CHECKLIST_BYTES_REQUIRED",))
    if len(data) > limits.max_input_bytes:
        return ChecklistInput(errors=("CHECKLIST_INPUT_LIMIT",))
    try:
        text = data.decode("utf-8-sig", "strict")
        reader = csv.reader(io.StringIO(text, newline=""), delimiter="\t", strict=True)
        if tuple(next(reader, ())) != COLUMNS:
            return ChecklistInput(errors=("CHECKLIST_HEADER_INVALID",))
        rules = []
        for index, row in enumerate(reader, 1):
            if index > limits.max_rules:
                return ChecklistInput(errors=("CHECKLIST_RULE_LIMIT",))
            if not row:
                continue
            line = reader.line_num
            if len(row) != 5:
                rules.append(Rule(line, None, None, None, None, None, ("CHECKLIST_ROW_WIDTH_INVALID",)))
                continue
            sid, name, path, required, minimum = row
            errors = []
            if any(len(value.encode("utf-8")) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value) for value in row):
                rules.append(Rule(line, None, None, None, None, None, ("CHECKLIST_FIELD_INVALID",)))
                continue
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", sid, re.ASCII) is None:
                errors.append("STEP_ID_INVALID"); sid = None
            if not name.strip() or len(name.encode("utf-8")) > 256:
                errors.append("STEP_NAME_INVALID"); name = None
            code = _pattern_code(path, limits)
            if code:
                errors.append(code); path = None
            if required not in ("yes", "no"):
                errors.append("REQUIRED_INVALID")
            needed = None
            if minimum.isascii() and minimum.isdigit() and len(minimum) <= 10:
                number = int(minimum)
                if 1 <= number <= limits.max_matches:
                    needed = number
            if needed is None:
                errors.append("MIN_MATCHES_INVALID")
            elif path is not None and not any(c in path for c in "*?") and needed != 1:
                errors.append("EXACT_PATH_MIN_MATCHES_MUST_BE_ONE")
            rules.append(Rule(line, sid, name, path, required == "yes" if required in ("yes", "no") else None,
                              needed, tuple(errors)))
    except (UnicodeError, csv.Error):
        return ChecklistInput(errors=("CHECKLIST_ENCODING_OR_TSV_INVALID",))
    if not rules:
        return ChecklistInput(errors=("CHECKLIST_EMPTY",))
    pairs, names = {}, {}
    for index, rule in enumerate(rules):
        if rule.step_id is not None:
            names.setdefault(rule.step_id, {}).setdefault(rule.step_name, []).append(index)
        if rule.step_id is not None and rule.expected_path is not None:
            pairs.setdefault((rule.step_id, rule.expected_path), []).append(index)
    for group in pairs.values():
        if len(group) > 1:
            declarations = {(rules[i].required, rules[i].min_matches) for i in group}
            code = "DUPLICATE_RULE" if len(declarations) == 1 else "CONFLICTING_RULE"
            for i in group:
                rules[i] = replace(rules[i], errors=rules[i].errors + (code,))
    for group in names.values():
        if len(group) > 1:
            for indices in group.values():
                for i in indices:
                    rules[i] = replace(rules[i], errors=rules[i].errors + ("STEP_NAME_CONFLICT",))
    return ChecklistInput(tuple(rules))


class _ScanBlocked(Exception):
    def __init__(self, code):
        self.code = code


class _Scanner:
    def __init__(self, root, limits):
        self.workspace = _Workspace(root, ReadLimits())
        self.limits = limits
        self.entries = self.directories = self.matches = 0
        self.cache, self.snapshots = {}, {}

    def _nodes(self, relative):
        nodes = self.workspace._chain(relative) if relative else self.workspace._root_chain()
        if not relative and [(p, _identity(s)) for p, s in nodes] != [
                (p, _identity(s)) for p, s in self.workspace.root_nodes]:
            raise _Refused("READ_UNSTABLE")
        if not stat.S_ISDIR(nodes[-1][1].st_mode):
            raise _Refused("PATH_COMPONENT_NOT_DIRECTORY")
        return nodes

    @staticmethod
    def _snapshot(nodes):
        return tuple((str(path), _identity(info)) for path, info in nodes), _signature(nodes[-1][1])

    def directory(self, relative):
        if relative in self.cache:
            cached = self.cache[relative]
            if isinstance(cached, str):
                raise _ScanBlocked(cached)
            return cached
        try:
            if self.directories >= self.limits.max_directories:
                raise _ScanBlocked("SCAN_DIRECTORY_LIMIT")
            self.directories += 1
            nodes = self._nodes(relative)
            before = self._snapshot(nodes)
            names = []
            # Only this explicitly selected directory. No DirEntry follow or
            # recursive glob; links are checked by the existing C1 prechecks.
            with os.scandir(nodes[-1][0]) as entries:
                for entry in entries:
                    if self.entries >= self.limits.max_entries:
                        raise _ScanBlocked("SCAN_ENTRY_LIMIT")
                    self.entries += 1
                    names.append(entry.name)
            if self._snapshot(self._nodes(relative)) != before:
                raise _ScanBlocked("SCAN_DIRECTORY_CHANGED")
            self.cache[relative] = tuple(sorted(names))
            self.snapshots[relative] = before
            return self.cache[relative]
        except _Refused as exc:
            code = exc.code
        except OSError as exc:
            code = _io_code(exc)
        except _ScanBlocked as exc:
            code = exc.code
        self.cache[relative] = code
        raise _ScanBlocked(code)

    def match(self, pattern):
        parts = pattern.split("/")
        parent, dependencies = "", [""]
        for component in parts[:-1]:
            if component not in self.directory(parent):
                return (), tuple(dependencies)
            parent = component if not parent else parent + "/" + component
            dependencies.append(parent)
        names = self.directory(parent)
        selected = []
        for name in names:
            if fnmatch.fnmatchcase(name, parts[-1]):
                if self.matches >= self.limits.max_matches:
                    raise _ScanBlocked("SCAN_MATCH_LIMIT")
                self.matches += 1
                selected.append(name if not parent else parent + "/" + name)
        return tuple(selected), tuple(dependencies)

    def metadata(self, relative):
        code = _path_code(relative)
        if code:
            return code
        try:
            info = self.workspace._chain(relative)[-1][1]
            if not stat.S_ISREG(info.st_mode):
                return "NON_REGULAR_FILE"
            if info.st_nlink != 1:
                return "HARDLINK_REJECTED"
            _identity(info)
            return "ELIGIBLE_METADATA"
        except _Refused as exc:
            return exc.code
        except OSError as exc:
            return "MATCH_DISAPPEARED" if isinstance(exc, FileNotFoundError) else _io_code(exc)

    def changed_directories(self):
        changed = set()
        for relative, before in self.snapshots.items():
            try:
                if self._snapshot(self._nodes(relative)) != before:
                    changed.add(relative)
            except (OSError, _Refused):
                changed.add(relative)
        return changed


def run_checklist(parsed, *, root, workspace_mode, export_manifest=False, limits=None, read_limits=None):
    if type(parsed) is not ChecklistInput or type(export_manifest) is not bool:
        raise TypeError("CHECKLIST_INPUT_REQUIRED")
    limits = ChecklistLimits() if limits is None else limits
    if type(limits) is not ChecklistLimits:
        raise TypeError("CHECKLIST_LIMITS_REQUIRED")
    valid = [rule for rule in parsed.rules if not rule.errors]
    results, rule_paths, dependencies = {}, {}, {}
    for rule in parsed.rules:
        if rule.errors:
            results[rule.line] = RuleResult(rule, "INVALID_RULE", reason_codes=rule.errors)
    scanner, root_error = None, None
    if valid:
        if workspace_mode != WORKSPACE_MODE:
            root_error = "WORKSPACE_MODE_REQUIRED"
        else:
            fixed_profile(root)
            try:
                scanner = _Scanner(root, limits)
            except _Refused as exc:
                root_error = exc.code
            except OSError as exc:
                root_error = _io_code(exc)
    for rule in valid:
        try:
            if root_error:
                raise _ScanBlocked(root_error)
            matches, deps = scanner.match(rule.expected_path)
            rule_paths[rule.line], dependencies[rule.line] = matches, deps
        except _ScanBlocked as exc:
            results[rule.line] = RuleResult(rule, "BLOCKED", reason_codes=(exc.code,))
    paths = sorted({path for matches in rule_paths.values() for path in matches})
    files = {path: MatchedFile(path, scanner.metadata(path)) for path in paths}
    eligible = [path for path in paths if files[path].metadata_code == "ELIGIBLE_METADATA"]
    tool_error = False
    if export_manifest and eligible:
        records = [{"record_id": f"observed-{i:06d}", "relative_path": path} for i, path in enumerate(eligible, 1)]
        data = json.dumps({"schema_version": "1.0", "records": records}).encode()
        observed = audit_bytes(data, "json", root=root, workspace_mode=workspace_mode, read_limits=read_limits)
        if observed.declarations is None or observed.declarations.schema_status != "VALID":
            for path in eligible:
                files[path] = replace(files[path], metadata_code="EXPORT_DECLARATION_LIMIT")
        else:
            for record, observation in zip(records, observed.files):
                path = record["relative_path"]
                files[path] = replace(files[path], observation=observation)
                if observation.result_code in ("INTERNAL_ERROR", "CLEANUP_INCOMPLETE", "PRIOR_CLEANUP_INCOMPLETE"):
                    tool_error = True
    changed = scanner.changed_directories() if scanner is not None else set()
    for path in files:
        if any(not directory or path.startswith(directory + "/") for directory in changed):
            files[path] = replace(files[path], metadata_code="SCAN_DIRECTORY_CHANGED", observation=None)
    qualified = [path for path in eligible if files[path].metadata_code == "ELIGIBLE_METADATA" and _qualified(files[path].observation)]
    draft_records = []
    if export_manifest:
        for i, path in enumerate(qualified, 1):
            identifier = f"file-{i:06d}"
            observation = files[path].observation
            draft_records.append(dict(record_id=identifier, relative_path=path, logical_role="unspecified", artifact_type="other",
                                      expected_size=observation.observed_size, hash_algorithm="sha256", expected_digest=observation.observed_sha256))
            files[path] = replace(files[path], draft_record_id=identifier)
    draft = None
    if draft_records:
        draft = json.dumps(dict(schema_version="1.0", records=draft_records, runs=[]), ensure_ascii=True, sort_keys=True, indent=2).encode() + b"\n"
        if parse_manifest(draft, "json").schema_status != "VALID":
            raise ReportError("EXPORTED_MANIFEST_SCHEMA_INVALID")
    for rule in valid:
        if rule.line in results:
            continue
        matches = rule_paths[rule.line]
        okay = tuple(path for path in matches if files[path].metadata_code == "ELIGIBLE_METADATA")
        good = tuple(path for path in matches if files[path].draft_record_id is not None)
        reasons = {files[path].metadata_code for path in matches if files[path].metadata_code != "ELIGIBLE_METADATA"}
        if changed.intersection(dependencies[rule.line]):
            reasons.add("SCAN_DIRECTORY_CHANGED")
        if export_manifest:
            for path in okay:
                if not _qualified(files[path].observation):
                    reasons.add("FILE_OBSERVATION_NOT_AVAILABLE" if files[path].observation is None else files[path].observation.result_code)
        if reasons:
            state = "BLOCKED"
        elif len(okay) >= rule.min_matches:
            state = "SATISFIED"
        elif not okay:
            state = "REQUIRED_MISSING" if rule.required else "OPTIONAL_MISSING"
        else:
            state = "REQUIRED_INSUFFICIENT" if rule.required else "OPTIONAL_INSUFFICIENT"
        results[rule.line] = RuleResult(rule, state, matches, okay, good, True, tuple(sorted(reasons)))
    return ChecklistResult(parsed, tuple(results[rule.line] for rule in parsed.rules), tuple(files[path] for path in paths),
                           export_manifest, draft, "VALID" if draft is not None else "NOT_EVALUATED",
                           0 if scanner is None else scanner.entries, 0 if scanner is None else scanner.directories,
                           0 if scanner is None else scanner.matches, tool_error)


def checklist_exit(result):
    if result.tool_error or any(code in ("CLEANUP_INCOMPLETE", "INTERNAL_ERROR") for code in result.input.errors):
        return 4
    blocked_input = {"ACCESS_DENIED", "READ_ERROR", "READ_UNSTABLE", "BUDGET_ABORTED", "LINK_REJECTED",
                     "HARDLINK_REJECTED", "OFFLINE_OBJECT_REJECTED", "FILE_ATTRIBUTES_UNSUPPORTED",
                     "OPEN_SAFETY_UNSUPPORTED", "NON_REGULAR_FILE", "FILE_IDENTITY_UNAVAILABLE"}
    if any(code not in blocked_input for code in result.input.errors) or any(row.state in ("INVALID_RULE", "REQUIRED_MISSING", "REQUIRED_INSUFFICIENT") for row in result.rules):
        return 2
    if result.input.errors or any(row.state == "BLOCKED" for row in result.rules) or (result.export_requested and result.manifest_bytes is None):
        return 3
    return 0
