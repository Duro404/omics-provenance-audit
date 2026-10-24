"""Immutable declaration models. Observation capabilities are intentionally absent."""

from dataclasses import dataclass, field
from enum import StrEnum


class SchemaStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"


class StructureStatus(StrEnum):
    EVALUATED = "EVALUATED"
    NOT_EVALUATED = "NOT_EVALUATED"


class RelationState(StrEnum):
    DECLARED = "DECLARED"
    INVALID_REFERENCE = "INVALID_REFERENCE"
    DECLARATION_CONFLICT = "DECLARATION_CONFLICT"


class Severity(StrEnum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class Limits:
    max_input_bytes: int = 8 * 1024 * 1024
    max_records: int = 10_000
    max_runs: int = 10_000
    max_references: int = 100_000
    max_field_bytes: int = 4096
    max_label_bytes: int = 256
    max_json_depth: int = 16

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError("LIMIT_MUST_BE_POSITIVE_INTEGER")


@dataclass(frozen=True, slots=True)
class UnverifiedCheck:
    reason_codes: tuple[str, ...] = ("PHASE1A_NOT_PERFORMED",)
    state: str = field(default="NOT_VERIFIED", init=False)


@dataclass(frozen=True, slots=True)
class ObservationChecks:
    presence: UnverifiedCheck = field(default_factory=UnverifiedCheck)
    fingerprint: UnverifiedCheck = field(default_factory=UnverifiedCheck)
    size: UnverifiedCheck = field(default_factory=UnverifiedCheck)
    digest: UnverifiedCheck = field(default_factory=UnverifiedCheck)
    execution: UnverifiedCheck = field(default_factory=UnverifiedCheck)
    reproduction: UnverifiedCheck = field(default_factory=UnverifiedCheck)


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: Severity
    subject_kind: str = "input"
    subject_id: str | None = None
    field: str | None = None
    target_id: str | None = None
    positions: tuple[int, ...] = ()
    related_ids: tuple[str, ...] = ()
    conflict_fields: tuple[str, ...] = ()

    @property
    def occurrence_count(self) -> int:
        return len(self.positions)


@dataclass(frozen=True, slots=True)
class ReferenceOccurrence:
    owner_kind: str
    owner_id: str
    field: str
    target_id: str
    positions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Record:
    record_id: str
    logical_role: str = "unspecified"
    relative_path: str | None = None
    expected_size: int | None = None
    hash_algorithm: str | None = None
    expected_digest: str | None = None
    artifact_type: str = "other"
    source_record_ids: tuple[str, ...] = ()
    evidence_reference: tuple[str, ...] = ()
    location_type: str = "local"
    external_reference: str | None = None
    logical_artifact_id: str | None = None
    version_label: str | None = None
    adoption_declaration: str = "not_declared"
    adoption_scope: str | None = None
    digest_declaration: UnverifiedCheck = field(default_factory=UnverifiedCheck)
    adoption: UnverifiedCheck = field(default_factory=UnverifiedCheck)
    observations: ObservationChecks = field(default_factory=ObservationChecks)


@dataclass(frozen=True, slots=True)
class Run:
    run_id: str
    script_record_ids: tuple[str, ...]
    input_record_ids: tuple[str, ...]
    output_record_ids: tuple[str, ...]
    evidence_reference: tuple[str, ...] = ()
    execution: UnverifiedCheck = field(default_factory=UnverifiedCheck)
    reproduction: UnverifiedCheck = field(default_factory=UnverifiedCheck)


@dataclass(frozen=True, slots=True)
class Manifest:
    schema_version: str
    records: tuple[Record, ...]
    runs: tuple[Run, ...]
    reference_occurrences: tuple[ReferenceOccurrence, ...]
    raw_reference_count: int


@dataclass(frozen=True, slots=True)
class Relation:
    owner_kind: str
    owner_id: str
    field: str
    target_id: str
    state: RelationState
    reason_codes: tuple[str, ...] = ()
    route: str | None = None


@dataclass(frozen=True, slots=True)
class RecordRoleCheck:
    record_id: str
    state: RelationState
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ParseResult:
    schema_status: SchemaStatus
    structure_status: StructureStatus
    manifest: Manifest | None
    findings: tuple[Finding, ...]
    relations: tuple[Relation, ...] = ()
    record_role_checks: tuple[RecordRoleCheck, ...] = ()
