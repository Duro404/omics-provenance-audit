"""Private in-memory observations for the trusted-workspace prototype.

These objects are not public reports or evidence of execution/reproduction.
The Phase 1A declaration models remain unchanged.
"""

from dataclasses import dataclass, field

from ..models import Finding, ParseResult

WORKSPACE_MODE = "TRUSTED_LOCAL_WORKSPACE_V010"


@dataclass(frozen=True, slots=True)
class ReadLimits:
    max_file_bytes: int = 10 * 1024**3
    max_total_bytes: int = 100 * 1024**3
    block_bytes: int = 1024**2
    max_read_calls: int = 1_000_000

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 2**63 - 1:
                raise ValueError("READ_LIMIT_INVALID")
        if self.block_bytes > 1024**2:
            raise ValueError("BLOCK_LIMIT_INVALID")


@dataclass(frozen=True, slots=True)
class Check:
    state: str = "NOT_VERIFIED"
    reason_codes: tuple[str, ...] = ("PHASE1C1_NOT_PERFORMED",)


@dataclass(frozen=True, slots=True)
class FileAudit:
    record_id: str
    presence: Check
    fingerprint: Check
    size: Check
    digest: Check
    observed_type: str | None
    observed_size: int | None
    observed_sha256: str | None
    primary_code: str
    result_code: str
    cleanup_errors: tuple[str, ...]
    read_bytes: int | None
    known_read_bytes: int
    requested_bytes: int
    read_calls: int
    read_consistency: str = "NOT_VERIFIED"
    execution: Check = field(default_factory=Check)
    reproduction: Check = field(default_factory=Check)
    atomic_snapshot: str = field(default="NOT_ESTABLISHED", init=False)


@dataclass(frozen=True, slots=True)
class AuditResult:
    declarations: ParseResult | None
    files: tuple[FileAudit, ...]
    findings: tuple[Finding, ...]
    audit_completion: str
    input_reason_codes: tuple[str, ...] = ()
    known_read_bytes: int = 0
    workspace_mode: str = field(default=WORKSPACE_MODE, init=False)
    profile_status: str = field(default="TARGET_PROFILE_PENDING_VALIDATION", init=False)
    implementation_scope: str = field(default="PHASE1C1_PROTOTYPE", init=False)
    privacy: str = field(default="PRIVATE_IN_MEMORY", init=False)
    atomic_snapshot: str = field(default="NOT_ESTABLISHED", init=False)

