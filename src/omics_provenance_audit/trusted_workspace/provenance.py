"""Phase 1C-2 pure inventory over an existing trusted-workspace result.

No file access, digest calculation, evidence-content parsing or run aggregation.
Input is an internal Phase 1C-1 result, never a deserialized manifest/result dict.
Outputs contain private declaration IDs and are not public reports. Qualified
observations retain the trust limits of that reader, not a strict backend claim.
"""

from dataclasses import dataclass, field
import re

from ..models import Finding, Relation, RelationState, SchemaStatus, Severity
from .models import AuditResult, Check, FileAudit

_DEFERRED = "EVIDENCE_CONTENT_NOT_EVALUATED_V010"
_ADOPTION = {value: "DECLARED_" + value.upper()
             for value in ("candidate", "adopted", "superseded", "excluded")}
# Current adopted status contradicts exclusion or supersession only within the
# exact explicit family/version/scope. Other different labels are not enough.
_ADOPTION_OPPOSITES = {frozenset(("adopted", "excluded")),
                       frozenset(("adopted", "superseded"))}


def _unverified(*reasons):
    return Check("NOT_VERIFIED", tuple(reasons) or (_DEFERRED,))


@dataclass(frozen=True, slots=True)
class ContentVariant:
    observed_size: int
    observed_sha256: str
    record_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContentGroup(ContentVariant):
    kind: str = field(default="OBSERVED_CONTENT_EQUIVALENCE", init=False)


@dataclass(frozen=True, slots=True)
class LocatorGroup:
    relative_path: str
    record_ids: tuple[str, ...]
    kind: str = field(default="SAME_LOCATOR_MULTIPLE_RECORDS", init=False)


@dataclass(frozen=True, slots=True)
class VersionScope:
    logical_artifact_id: str
    version_label: str
    record_ids: tuple[str, ...]
    observed_record_ids: tuple[str, ...]
    unverified_record_ids: tuple[str, ...]
    content_variants: tuple[ContentVariant, ...]
    conflict_observed: bool
    comparison_complete: bool  # Observation coverage, NOT version correctness.


@dataclass(frozen=True, slots=True)
class VersionLabelAlias:
    logical_artifact_id: str
    version_labels: tuple[str, ...]
    content: ContentGroup
    kind: str = field(default="VERSION_LABEL_ALIAS_CANDIDATE", init=False)


@dataclass(frozen=True, slots=True)
class AdoptionAudit:
    record_id: str
    declaration: str
    scope: str | None
    declared: Check  # Original mapped declaration survives a conflict.
    assessment: Check
    conflicting_record_ids: tuple[str, ...]
    known_integrity_conflict: bool


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    relation: Relation
    positions: tuple[int, ...]
    target_logical_role: str | None
    target_artifact_type: str | None
    target_location_type: str | None
    file: FileAudit | None
    qualified_read: bool
    known_integrity_conflict: bool
    material_reason_codes: tuple[str, ...]
    reproduction: Check
    execution: Check = field(default_factory=_unverified)
    content_evaluation: str = field(default="NOT_EVALUATED", init=False)

    @property
    def occurrence_count(self):
        return len(self.positions)


@dataclass(frozen=True, slots=True)
class EvidenceOwner:
    owner_kind: str
    owner_id: str
    references: tuple[EvidenceItem, ...]
    raw_reference_count: int
    unique_reference_count: int
    duplicate_reference_count: int
    invalid_reference_count: int
    execution: Check
    execution_evaluation: str = field(default="NOT_EVALUATED", init=False)

    @property
    def reproduction_materials(self):
        # Each claim stays local. No strongest-claim owner aggregation is made.
        return tuple(item for item in self.references
                     if item.target_artifact_type == "reproduction_record")


@dataclass(frozen=True, slots=True)
class ProvenanceAudit:
    file_audit: AuditResult
    evaluation_status: str
    content_groups: tuple[ContentGroup, ...] = ()
    locator_groups: tuple[LocatorGroup, ...] = ()
    version_scopes: tuple[VersionScope, ...] = ()
    version_label_aliases: tuple[VersionLabelAlias, ...] = ()
    adoptions: tuple[AdoptionAudit, ...] = ()
    evidence_owners: tuple[EvidenceOwner, ...] = ()
    findings: tuple[Finding, ...] = ()
    implementation_scope: str = field(default="PHASE1C2_PROTOTYPE", init=False)
    privacy: str = field(default="PRIVATE_IN_MEMORY", init=False)
    atomic_snapshot: str = field(default="NOT_ESTABLISHED", init=False)

    @property
    def relations(self):
        parsed = self.file_audit.declarations
        return () if parsed is None else parsed.relations


def _qualified(item):
    """Require the complete C1 success shape; do not promote mere presence.

    This consistency guard cannot authenticate a forged in-process object.
    Expected-digest/size mismatch does not invalidate observed bytes themselves.
    """
    return (item is not None and item.primary_code == "READ_COMPLETED" and
            item.result_code == "READ_COMPLETED" and not item.cleanup_errors and
            item.presence.state == "PRESENT" and item.observed_type == "REGULAR_FILE" and
            item.fingerprint.state == "OBSERVED_SHA256" and
            type(item.observed_size) is int and item.observed_size >= 0 and
            type(item.observed_sha256) is str and
            re.fullmatch(r"[0-9a-f]{64}", item.observed_sha256) is not None and
            type(item.read_bytes) is int and type(item.known_read_bytes) is int and
            item.read_bytes == item.known_read_bytes == item.observed_size and
            item.read_consistency == "NO_CHANGE_DETECTED")


def _integrity_conflict(item):
    return item is not None and (item.size.state == "MISMATCH" or item.digest.state == "MISMATCH")


def _content_key(item):
    return item.observed_size, item.observed_sha256


def _content_groups(record_ids, files, minimum=2):
    groups = {}
    for rid in record_ids:
        item = files.get(rid)
        if _qualified(item):
            groups.setdefault(_content_key(item), []).append(rid)
    group_type = ContentVariant if minimum == 1 else ContentGroup
    return tuple(group_type(size, digest, tuple(sorted(ids)))
                 for (size, digest), ids in sorted(groups.items()) if len(ids) >= minimum)


def _versions(records, files, findings):
    scopes, alias_keys = {}, {}
    for record in records.values():
        family, label = record.logical_artifact_id, record.version_label
        if family is None or label is None:
            continue
        scopes.setdefault((family, label), []).append(record.record_id)
        item = files.get(record.record_id)
        if _qualified(item):
            alias_keys.setdefault((family, *_content_key(item)), []).append(record)
    versions = []
    for (family, label), members in sorted(scopes.items()):
        ids = tuple(sorted(members))
        variants = _content_groups(ids, files, minimum=1)
        observed = tuple(sorted(rid for variant in variants for rid in variant.record_ids))
        observed_set = set(observed)
        unknown = tuple(rid for rid in ids if rid not in observed_set)
        conflict = len(variants) > 1
        versions.append(VersionScope(family, label, ids, observed, unknown, variants,
                                     conflict, not unknown))
        if conflict:
            findings.append(Finding("VERSION_CONTENT_CONFLICT", Severity.ERROR,
                                     "version", family, "version_label", label,
                                     related_ids=observed))
    aliases = []
    for (family, size, digest), members in sorted(alias_keys.items()):
        labels = tuple(sorted({r.version_label for r in members}))
        if len(labels) > 1:
            aliases.append(VersionLabelAlias(family, labels, ContentGroup(
                size, digest, tuple(sorted(r.record_id for r in members)))))
    return tuple(versions), tuple(aliases)


def _adoptions(records, files, findings):
    scopes, peers = {}, {}
    for record in records.values():
        if (record.adoption_declaration in _ADOPTION and record.adoption_scope is not None and
            record.logical_artifact_id is not None and record.version_label is not None):
            key = record.logical_artifact_id, record.version_label, record.adoption_scope
            scopes.setdefault(key, {}).setdefault(record.adoption_declaration, []).append(record.record_id)
    # Group by four fixed declaration values, rather than all record pairs.
    for declarations in scopes.values():
        for value, members in declarations.items():
            opposites = tuple(sorted(rid for other, ids in declarations.items()
                                      if frozenset((value, other)) in _ADOPTION_OPPOSITES
                                      for rid in ids))
            if opposites:
                for rid in members:
                    peers[rid] = opposites
    results = []
    for rid, record in sorted(records.items()):
        value, scope = record.adoption_declaration, record.adoption_scope
        if value == "not_declared":
            declared = _unverified("ADOPTION_NOT_DECLARED")
        elif scope is None:
            declared = _unverified("ADOPTION_SCOPE_MISSING")
        else:
            declared = Check(_ADOPTION[value], ())
        conflicts = peers.get(rid, ())
        assessment = declared
        if conflicts:
            assessment = Check("DECLARATION_CONFLICT", ("ADOPTION_DECLARATION_CONFLICT",))
            findings.append(Finding("ADOPTION_DECLARATION_CONFLICT", Severity.ERROR, "record",
                                     rid, "adoption_declaration", related_ids=conflicts))
        bad_integrity = _integrity_conflict(files.get(rid))
        if declared.state == "DECLARED_ADOPTED" and bad_integrity:
            findings.append(Finding("ADOPTED_ARTIFACT_INTEGRITY_CONFLICT", Severity.ERROR,
                                     "record", rid, "adoption_declaration"))
        results.append(AdoptionAudit(rid, value, scope, declared, assessment, conflicts, bad_integrity))
    return tuple(results)


def _material(relation, positions, records, files):
    target = records.get(relation.target_id)
    item = files.get(relation.target_id)
    qualified = _qualified(item)
    conflict = _integrity_conflict(item)
    reasons = list(relation.reason_codes)
    if target is None:
        reasons.append("EVIDENCE_TARGET_UNKNOWN")
    elif target.location_type == "external":
        reasons.append("EXTERNAL_NOT_READ")
        qualified = False
    elif item is None:
        reasons.append("FILE_OBSERVATION_NOT_AVAILABLE")
    elif not qualified:
        reasons.append(item.result_code if item.result_code != "READ_COMPLETED"
                       else "QUALIFIED_OBSERVATION_NOT_AVAILABLE")
    if conflict:
        reasons.append("EVIDENCE_MATERIAL_INTEGRITY_CONFLICT")
    reproduction = _unverified("NO_REPRODUCTION_REFERENCE")
    if target is not None and target.artifact_type == "reproduction_record":
        valid = relation.state == RelationState.DECLARED and relation.route == "reproduction_material"
        if not valid:
            reproduction = _unverified("EVIDENCE_REFERENCE_INVALID")
        elif qualified and not conflict:
            reproduction = Check("CLAIM_RECORD_PRESENT_UNVERIFIED", (_DEFERRED,))
        else:
            reproduction = Check("CLAIM_DECLARED_UNVERIFIED", tuple(dict.fromkeys(reasons + [_DEFERRED])))
    return EvidenceItem(relation, positions,
                        None if target is None else target.logical_role,
                        None if target is None else target.artifact_type,
                        None if target is None else target.location_type,
                        item, qualified, conflict, tuple(dict.fromkeys(reasons)), reproduction)


def _evidence(manifest, parsed, records, files):
    occurrences = {(o.owner_kind, o.owner_id, o.field, o.target_id): o.positions
                   for o in manifest.reference_occurrences}
    by_owner, invalid_runs = {}, set()
    for relation in parsed.relations:
        if relation.field == "evidence_reference":
            key = relation.owner_kind, relation.owner_id
            positions = occurrences[(relation.owner_kind, relation.owner_id, relation.field,
                                     relation.target_id)]
            by_owner.setdefault(key, []).append(_material(relation, positions, records, files))
        elif relation.owner_kind == "run" and relation.state != RelationState.DECLARED:
            invalid_runs.add(relation.owner_id)
    owners = []
    keys = [("record", rid) for rid in records] + [("run", run.run_id) for run in manifest.runs]
    for kind, oid in sorted(keys):
        items = tuple(sorted(by_owner.get((kind, oid), ()), key=lambda i: i.relation.target_id))
        raw = sum(item.occurrence_count for item in items)
        reasons = [_DEFERRED]
        if kind == "run" and oid in invalid_runs:
            reasons.append("RUN_DECLARATION_INVALID")
        if not items:
            reasons.append("NO_EVIDENCE_REFERENCE_DECLARED")
        owners.append(EvidenceOwner(kind, oid, items, raw, len(items), raw - len(items),
                                    sum(i.relation.state != RelationState.DECLARED for i in items),
                                    _unverified(*reasons)))
    return tuple(owners)


def audit_provenance(file_audit: AuditResult) -> ProvenanceAudit:
    """Derive only C12-01/C12-02 facts; never reopen any declared path.

    Accept the original internal C1 result. No dict deserialization, callback,
    automatic replacement, reference inheritance or global scientific pass.
    """
    if type(file_audit) is not AuditResult:
        raise TypeError("PHASE1C1_AUDIT_RESULT_REQUIRED")
    parsed = file_audit.declarations
    if parsed is None or parsed.schema_status != SchemaStatus.VALID or parsed.manifest is None:
        return ProvenanceAudit(file_audit, "NOT_EVALUATED", findings=file_audit.findings)
    records = {r.record_id: r for r in parsed.manifest.records}
    files = {}
    for item in file_audit.files:
        if type(item) is not FileAudit or item.record_id not in records or item.record_id in files:
            raise ValueError("FILE_OBSERVATION_ID_INVALID")
        files[item.record_id] = item
    findings = list(file_audit.findings)
    # External declarations never qualify as locally observed content, even
    # if an inconsistent caller supplied a success-shaped observation for one.
    local_files = {rid: item for rid, item in files.items() if records[rid].location_type == "local"}
    groups = _content_groups(records, local_files)
    locators = {}
    for rid, record in records.items():
        if record.location_type == "local":
            locators.setdefault(record.relative_path, []).append(rid)
    locator_groups = tuple(LocatorGroup(path, tuple(sorted(ids)))
                           for path, ids in sorted(locators.items()) if len(ids) > 1)
    for group in locator_groups:
        findings.append(Finding(group.kind, Severity.INFO, "locator", related_ids=group.record_ids))
    versions, aliases = _versions(records, local_files, findings)
    adoptions = _adoptions(records, files, findings)
    owners = _evidence(parsed.manifest, parsed, records, files)
    findings.sort(key=lambda f: (f.subject_kind, f.subject_id or "", f.field or "", f.code,
                                 f.target_id or "", f.related_ids, f.positions))
    return ProvenanceAudit(file_audit, "EVALUATED", groups, locator_groups, versions, aliases,
                           adoptions, owners, tuple(findings))
