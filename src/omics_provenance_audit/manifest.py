"""Bounded in-memory parsing under the frozen phase0.1 declaration contract.

The caller owns obtaining bytes. This module has no path-based input adapter.
Error diagnostics use fixed codes and locations, never exception text or payloads.
"""

import json
import re

from .models import (
    Finding, Limits, Manifest, ParseResult, Record, ReferenceOccurrence, Run,
    RecordRoleCheck, RelationState, SchemaStatus, Severity, StructureStatus, UnverifiedCheck,
)
from .structure import check_structure

ROLES = frozenset(("input", "output", "intermediate", "script", "run_log",
                   "config", "environment", "other", "unspecified"))
ARTIFACT_TYPES = frozenset(("data", "script", "log", "execution_record",
                            "reproduction_record", "config", "report", "environment", "other"))
ADOPTIONS = frozenset(("not_declared", "candidate", "adopted", "superseded", "excluded"))
RECORD_FIELDS = frozenset((
    "record_id", "logical_role", "relative_path", "expected_size", "hash_algorithm",
    "expected_digest", "artifact_type", "source_record_ids", "evidence_reference",
    "location_type", "external_reference", "logical_artifact_id", "version_label",
    "adoption_declaration", "adoption_scope",
))
RUN_FIELDS = frozenset(("run_id", "script_record_ids", "input_record_ids",
                       "output_record_ids", "evidence_reference"))
ARRAY_FIELDS = frozenset(("source_record_ids", "evidence_reference"))
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
ALGORITHM_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
DECIMAL_PATTERN = re.compile(r"[0-9]+\Z", re.ASCII)
HEX_PATTERN = re.compile(r"[0-9a-fA-F]+\Z", re.ASCII)
_ABSENT = object()


class _Rejected(Exception):
    def __init__(self, code, field=None, positions=()):
        self.finding = Finding(code, Severity.ERROR, field=field, positions=positions)


def _reject(code, field=None, positions=()):
    raise _Rejected(code, field, positions)


def _text(data, limits):
    if type(data) is not bytes:
        _reject("INPUT_BYTES_REQUIRED")
    if len(data) > limits.max_input_bytes:
        _reject("INPUT_BYTE_LIMIT")
    try:
        return data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        _reject("INPUT_ENCODING_INVALID")


def _string_bytes(value):
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        _reject("STRING_UNICODE_INVALID")


def _json_preflight(text, limits):
    """Linear scan before json.loads; braces inside strings do not count.

    Count decoded UTF-8 string bytes, including escaped surrogate pairs, without
    building a decoded string/object. JSON syntax is subsequently checked by json.
    """
    depth = 0
    index = 0
    while index < len(text):
        ch = text[index]
        if ch in "[{":
            depth += 1
            if depth > limits.max_json_depth:
                _reject("JSON_DEPTH_LIMIT")
        elif ch in "]}":
            depth -= 1
            if depth < 0:
                _reject("JSON_INVALID")
        elif ch == '"':
            index += 1
            size = 0
            while index < len(text) and text[index] != '"':
                ch = text[index]
                if ch == "\\":
                    index += 1
                    if index >= len(text):
                        _reject("JSON_INVALID")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1:index + 5]
                        if len(digits) != 4 or not HEX_PATTERN.fullmatch(digits):
                            _reject("JSON_INVALID")
                        cp = int(digits, 16)
                        index += 4
                        if 0xD800 <= cp <= 0xDBFF:
                            if text[index + 1:index + 3] != "\\u":
                                _reject("STRING_UNICODE_INVALID")
                            low = text[index + 3:index + 7]
                            if len(low) != 4 or not HEX_PATTERN.fullmatch(low):
                                _reject("STRING_UNICODE_INVALID")
                            low_cp = int(low, 16)
                            if not 0xDC00 <= low_cp <= 0xDFFF:
                                _reject("STRING_UNICODE_INVALID")
                            index += 6
                            size += 4
                        elif 0xDC00 <= cp <= 0xDFFF:
                            _reject("STRING_UNICODE_INVALID")
                        else:
                            size += 1 if cp < 128 else 2 if cp < 2048 else 3
                    elif escape in '"\\/bfnrt':
                        size += 1
                    else:
                        _reject("JSON_INVALID")
                elif ord(ch) < 32:
                    _reject("JSON_INVALID")
                else:
                    size += _string_bytes(ch)
                if size > limits.max_field_bytes:
                    _reject("STRING_BYTE_LIMIT")
                index += 1
            if index >= len(text):
                _reject("JSON_INVALID")
        index += 1
    if depth != 0:
        _reject("JSON_INVALID")


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _number(value):
    # No manifest field permits integers outside signed 64-bit magnitude.
    if len(value.lstrip("-")) > 19:
        _reject("INTEGER_LIMIT")
    return int(value)


def _no_float(value):
    # No manifest field permits floating-point values, finite or otherwise.
    _reject("JSON_NUMBER_TYPE_INVALID")


def _json(text, limits):
    _json_preflight(text, limits)
    try:
        return json.loads(text, object_pairs_hook=_object_pairs, parse_int=_number,
                          parse_float=_no_float, parse_constant=_no_float)
    except (json.JSONDecodeError, ValueError, RecursionError):
        _reject("JSON_INVALID")


def _object(value, allowed, required):
    if type(value) is not dict:
        _reject("OBJECT_REQUIRED")
    if not set(value) <= allowed:
        _reject("FIELD_UNKNOWN")
    if not required <= set(value):
        _reject("FIELD_REQUIRED")


def _optional(value, field, limits, *, label=False):
    if value is _ABSENT or value is None or value == "":
        return None
    if type(value) is not str:
        _reject("FIELD_TYPE_INVALID", field)
    if _string_bytes(value) > (limits.max_label_bytes if label else limits.max_field_bytes):
        _reject("STRING_BYTE_LIMIT", field)
    return value


def _identifier(value, field):
    if type(value) is not str or not ID_PATTERN.fullmatch(value):
        _reject("ID_INVALID", field)
    return value


def _enum(value, field, choices, default, limits):
    value = _optional(value, field, limits)
    if value is None:
        return default
    if value not in choices:
        _reject("ENUM_INVALID", field)
    return value


def _path(value):
    """Portable lexical policy only; no operating-system path operations."""
    if "\\" in value:
        _reject("PATH_NONPORTABLE", "relative_path")
    if any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value):
        _reject("PATH_INVALID", "relative_path")
    if any(ch in '<>:"|?*' for ch in value):
        _reject("PATH_INVALID", "relative_path")
    for component in value.split("/"):
        if not component or component in (".", "..") or component.endswith((" ", ".")):
            _reject("PATH_INVALID", "relative_path")
        stem = component.split(".", 1)[0].rstrip(" ").upper()
        if stem in ("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$") or re.fullmatch(
            r"(?:COM|LPT)[1-9¹²³]", stem
        ):
            _reject("PATH_INVALID", "relative_path")
    return value


class _Schema:
    def __init__(self, limits):
        self.limits = limits
        self.raw_count = 0
        self.occurrences = []
        self.findings = []

    def array(self, value, owner_kind, owner_id, field):
        if value is _ABSENT:
            value = []
        if type(value) is not list:
            _reject("ARRAY_REQUIRED", field)
        self.raw_count += len(value)
        if self.raw_count > self.limits.max_references:
            _reject("REFERENCE_LIMIT", field)
        positions = {}
        for index, member in enumerate(value):
            target = _identifier(member, field)
            positions.setdefault(target, []).append(index)
        for target in sorted(positions):
            indexes = tuple(positions[target])
            self.occurrences.append(ReferenceOccurrence(owner_kind, owner_id, field, target, indexes))
            if len(indexes) > 1:
                code = ("EVIDENCE_REFERENCE_DUPLICATE" if field == "evidence_reference"
                        else "DECLARATION_REFERENCE_DUPLICATE")
                self.findings.append(Finding(code, Severity.WARN, owner_kind, owner_id,
                                             field, target, indexes))
        return tuple(sorted(positions))

    def record(self, raw, tabular):
        _object(raw, RECORD_FIELDS, {"record_id"})
        get = lambda key: raw.get(key, _ABSENT)
        rid = _identifier(get("record_id"), "record_id")
        location = _enum(get("location_type"), "location_type", {"local", "external"}, "local", self.limits)
        path = _optional(get("relative_path"), "relative_path", self.limits)
        if location == "local":
            if path is None:
                _reject("FIELD_REQUIRED", "relative_path")
            _path(path)
        elif path is not None:
            _reject("EXTERNAL_PATH_CONFLICT", "relative_path")
        role = _enum(get("logical_role"), "logical_role", ROLES, "unspecified", self.limits)
        artifact = _enum(get("artifact_type"), "artifact_type", ARTIFACT_TYPES, "other", self.limits)
        adoption = _enum(get("adoption_declaration"), "adoption_declaration", ADOPTIONS,
                         "not_declared", self.limits)
        scope = _optional(get("adoption_scope"), "adoption_scope", self.limits, label=True)
        if scope is not None and not scope.strip():
            scope = None
        if adoption != "not_declared" and scope is None:
            adoption_check = UnverifiedCheck(("ADOPTION_SCOPE_MISSING",))
            self.findings.append(Finding("ADOPTION_SCOPE_MISSING", Severity.WARN, "record", rid,
                                         "adoption_scope"))
        elif adoption == "not_declared":
            adoption_check = UnverifiedCheck(("ADOPTION_NOT_DECLARED",))
            if scope is not None:
                self.findings.append(Finding("ADOPTION_SCOPE_WITHOUT_DECLARATION", Severity.INFO,
                                             "record", rid, "adoption_scope"))
        else:
            adoption_check = UnverifiedCheck()
        size = get("expected_size")
        if size is _ABSENT or size is None or size == "":
            size = None
        else:
            if tabular:
                if type(size) is not str or not DECIMAL_PATTERN.fullmatch(size):
                    _reject("SIZE_INVALID", "expected_size")
                significant = size.lstrip("0") or "0"
                if len(significant) > 19:
                    _reject("SIZE_INVALID", "expected_size")
                size = int(significant)
            if type(size) is not int or not 0 <= size <= 2**63 - 1:
                _reject("SIZE_INVALID", "expected_size")
        algorithm = _optional(get("hash_algorithm"), "hash_algorithm", self.limits)
        digest = _optional(get("expected_digest"), "expected_digest", self.limits)
        if algorithm is not None:
            if not ALGORITHM_PATTERN.fullmatch(algorithm):
                _reject("HASH_ALGORITHM_INVALID", "hash_algorithm")
            algorithm = algorithm.lower()
        reasons = []
        if (algorithm is None) != (digest is None):
            reasons.append("HASH_DECLARATION_INCOMPLETE")
        if algorithm is not None and algorithm not in ("sha256", "md5"):
            reasons.append("UNSUPPORTED_HASH_ALGORITHM")
        if algorithm in ("sha256", "md5") and digest is not None:
            if len(digest) != (64 if algorithm == "sha256" else 32) or not HEX_PATTERN.fullmatch(digest):
                _reject("DIGEST_FORMAT_INVALID", "expected_digest")
            digest = digest.lower()
        for reason in reasons:
            self.findings.append(Finding(reason, Severity.WARN, "record", rid, "expected_digest"))
        logical_id = _optional(get("logical_artifact_id"), "logical_artifact_id", self.limits)
        if logical_id is not None:
            _identifier(logical_id, "logical_artifact_id")
        return Record(
            record_id=rid, logical_role=role, relative_path=path, expected_size=size,
            hash_algorithm=algorithm, expected_digest=digest, artifact_type=artifact,
            source_record_ids=self.array(get("source_record_ids"), "record", rid, "source_record_ids"),
            evidence_reference=self.array(get("evidence_reference"), "record", rid, "evidence_reference"),
            location_type=location,
            external_reference=_optional(get("external_reference"), "external_reference", self.limits),
            logical_artifact_id=logical_id,
            version_label=_optional(get("version_label"), "version_label", self.limits, label=True),
            adoption_declaration=adoption, adoption_scope=scope, adoption=adoption_check,
            digest_declaration=UnverifiedCheck(tuple(reasons) or ("PHASE1A_NOT_PERFORMED",)),
        )

    def run(self, raw):
        _object(raw, RUN_FIELDS, RUN_FIELDS - {"evidence_reference"})
        rid = _identifier(raw["run_id"], "run_id")
        fields = {}
        for name in sorted(RUN_FIELDS - {"run_id"}):
            fields[name] = self.array(raw.get(name, _ABSENT), "run", rid, name)
        if not fields["script_record_ids"] or not (fields["input_record_ids"] or fields["output_record_ids"]):
            _reject("RUN_CARDINALITY_INVALID")
        return Run(run_id=rid, **fields)


def _csv_rows(text, delimiter):
    """Strict delimited text without csv.field_size_limit's process-global cap.

    At most one input-byte-bounded row is buffered. Reject extra fields while
    scanning, before constructing a wide row. Preserve newlines inside quotes.
    """
    row, chars = [], []
    state = "start"
    index = 0
    active = False
    while index < len(text):
        ch = text[index]
        active = True
        if state == "quoted":
            if ch == '"':
                state = "closed"
            else:
                chars.append(ch)
        elif state == "closed" and ch == '"':
            chars.append('"')
            state = "quoted"
        elif ch == delimiter or ch in "\r\n":
            row.append("".join(chars))
            chars = []
            state = "start"
            if len(row) > len(RECORD_FIELDS):
                _reject("CSV_ROW_WIDTH_INVALID")
            if ch != delimiter:
                yield row
                row = []
                active = False
                if ch == "\r" and text[index + 1:index + 2] == "\n":
                    index += 1
        elif state == "closed":
            _reject("CSV_INVALID")
        elif ch == '"':
            if state != "start":
                _reject("CSV_INVALID")
            state = "quoted"
        else:
            chars.append(ch)
            state = "bare"
        index += 1
    if state == "quoted":
        _reject("CSV_INVALID")
    if active:
        row.append("".join(chars))
        if len(row) > len(RECORD_FIELDS):
            _reject("CSV_ROW_WIDTH_INVALID")
        yield row


def _tabular(text, fmt, limits):
    reader = _csv_rows(text, "," if fmt == "csv" else "\t")
    header = next(reader, None)
    if not header or header == [""]:
        _reject("MANIFEST_EMPTY")
    if len(set(header)) != len(header):
        _reject("CSV_HEADER_INVALID")
    if not set(header) <= RECORD_FIELDS or "record_id" not in header:
        _reject("CSV_HEADER_INVALID")
    for index, row in enumerate(reader):
        if index >= limits.max_records:
            _reject("RECORD_LIMIT")
        if len(row) != len(header):
            _reject("CSV_ROW_WIDTH_INVALID", positions=(index,))
        raw = {}
        for key, value in zip(header, row):
            # Reference cells are JSON arrays: the field budget applies to each
            # decoded string, not to the array's serialized representation.
            if key not in ARRAY_FIELDS and _string_bytes(value) > limits.max_field_bytes:
                _reject("STRING_BYTE_LIMIT", key, (index,))
            if value != "":
                raw[key] = _json(value, limits) if key in ARRAY_FIELDS else value
        yield raw


def _top(value, *, runs_only=False):
    allowed = {"schema_version", "runs"} if runs_only else {"schema_version", "records", "runs"}
    required = {"schema_version", "runs"} if runs_only else {"schema_version", "records"}
    _object(value, allowed, required)
    if value["schema_version"] != "1.0" or type(value["schema_version"]) is not str:
        _reject("SCHEMA_VERSION_UNSUPPORTED")
    for name in ("runs",) if runs_only else ("records", "runs"):
        if type(value.get(name, [])) is not list:
            _reject("ARRAY_REQUIRED", name)
    return value


def parse_manifest(data: bytes, format: str, *, runs_data: bytes | None = None,
                   manifest_version: str = "1.0", limits: Limits | None = None) -> ParseResult:
    """Parse supplied bytes and check declarations; never dereference a path/URI.

    Formats are exactly 'csv', 'tsv', 'json'. JSON inline runs (even []) and
    runs_data are mutually exclusive. Invalid schema returns no usable manifest
    or graph. Semantic errors retain the normalized manifest and other edges.
    Raw occurrence positions are zero-based within each reference array.
    """
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise TypeError("LIMITS_REQUIRED")
    try:
        if type(format) is not str or format not in ("csv", "tsv", "json"):
            _reject("FORMAT_UNSUPPORTED")
        if type(manifest_version) is not str or manifest_version != "1.0":
            _reject("SCHEMA_VERSION_UNSUPPORTED")
        text = _text(data, limits)
        if format == "json":
            top = _top(_json(text, limits))
            if runs_data is not None and "runs" in top:
                _reject("RUNS_INPUT_CONFLICT")
            record_values = top["records"]
            run_values = top.get("runs", [])
        else:
            record_values = _tabular(text, format, limits)
            run_values = []
        if runs_data is not None:
            run_values = _top(_json(_text(runs_data, limits), limits), runs_only=True)["runs"]
        if len(run_values) > limits.max_runs:
            _reject("RUN_LIMIT")
        schema = _Schema(limits)
        records = {}
        for index, raw in enumerate(record_values):
            if index >= limits.max_records:
                _reject("RECORD_LIMIT")
            record = schema.record(raw, format != "json")
            if record.record_id in records:
                _reject("RECORD_ID_DUPLICATE", "record_id", (index,))
            records[record.record_id] = record
        if not records:
            _reject("MANIFEST_EMPTY")
        runs = {}
        for raw in run_values:
            run = schema.run(raw)
            if run.run_id in runs:
                _reject("RUN_ID_DUPLICATE", "run_id")
            runs[run.run_id] = run
        manifest = Manifest("1.0", tuple(records[key] for key in sorted(records)),
                            tuple(runs[key] for key in sorted(runs)),
                            tuple(sorted(schema.occurrences, key=lambda o: (
                                o.owner_kind, o.owner_id, o.field, o.target_id))), schema.raw_count)
        relations, structural_findings = check_structure(manifest)
        findings = schema.findings + list(structural_findings)
        findings.sort(key=lambda f: (f.subject_kind, f.subject_id or "", f.field or "",
                                      f.target_id or "", f.code, f.related_ids))
        conflict_ids = {f.subject_id for f in structural_findings if f.code == "ROLE_DECLARATION_CONFLICT"}
        role_checks = tuple(RecordRoleCheck(
            record.record_id,
            RelationState.DECLARATION_CONFLICT if record.record_id in conflict_ids else RelationState.DECLARED,
            ("ROLE_DECLARATION_CONFLICT",) if record.record_id in conflict_ids else (),
        ) for record in manifest.records)
        return ParseResult(SchemaStatus.VALID, StructureStatus.EVALUATED, manifest,
                           tuple(findings), relations, role_checks)
    except _Rejected as error:
        return ParseResult(SchemaStatus.INVALID, StructureStatus.NOT_EVALUATED,
                           None, (error.finding,))
