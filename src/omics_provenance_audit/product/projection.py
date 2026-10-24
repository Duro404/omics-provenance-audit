"""Single private-to-report projection. Renderers never infer evidence states."""

from dataclasses import dataclass
import json
import re

from ..models import Finding, Severity
from ..trusted_workspace.models import Check
from ..trusted_workspace.provenance import ProvenanceAudit
from . import __version__

MAX_REPORT_BYTES = 64 * 1024**2
MAX_ROWS = 250_000
MAX_LINKS = 500_000
BOUNDARY = "文件匹配不证明实际执行；材料存在不证明独立复现或科研结论正确。"
_FIELDS = frozenset(("record_id", "run_id", "relative_path", "expected_size", "hash_algorithm",
                     "expected_digest", "artifact_type", "logical_role", "source_record_ids",
                     "evidence_reference", "location_type", "external_reference", "logical_artifact_id",
                     "version_label", "adoption_declaration", "adoption_scope", "script_record_ids",
                     "input_record_ids", "output_record_ids", "records", "runs", "schema_version",
                     "record_role_conflict"))


class ReportError(Exception):
    """Only fixed codes may cross the CLI boundary."""


def json_bytes(document):
    chunks, size = [], 0
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False)
    for part in encoder.iterencode(document):
        block = part.encode("utf-8")
        size += len(block)
        if size + 1 > MAX_REPORT_BYTES:
            raise ReportError("REPORT_BYTE_LIMIT")
        chunks.append(block)
    return b"".join(chunks) + b"\n"


@dataclass(frozen=True, slots=True)
class ReportFacts:
    canonical_json: bytes  # Immutable, already projected; never private asdict().

    def document(self):
        return json.loads(self.canonical_json)


def operation_exit(inventory):
    original = inventory.file_audit
    codes = set(original.input_reason_codes)
    codes.update(f.primary_code for f in original.files)
    codes.update(f.result_code for f in original.files)
    if codes & {"INTERNAL_ERROR", "CLEANUP_INCOMPLETE", "PRIOR_CLEANUP_INCOMPLETE"}:
        return 4
    if any(f.severity == Severity.ERROR for f in inventory.findings):
        return 2
    if "FILE_MISSING" in codes or "INPUT_BYTE_LIMIT" in codes:
        return 2
    if original.audit_completion != "COMPLETE":
        return 3
    return 0


def project(inventory: ProvenanceAudit, *, report_profile="public", manifest_digest=None,
            runs_digest=None, platform_profile=None) -> ReportFacts:
    if type(inventory) is not ProvenanceAudit or report_profile not in ("public", "local"):
        raise ReportError("REPORT_INPUT_INVALID")
    local = report_profile == "local"
    for value in (manifest_digest, runs_digest):
        if value is not None and (type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None):
            raise ReportError("REPORT_DIGEST_INVALID")
    if platform_profile is not None:
        allowed = {"profile_id", "system", "windows_build", "python_version", "architecture", "filesystem", "validation_status"}
        if (type(platform_profile) is not dict or set(platform_profile) - allowed or
            any(type(v) not in (str, int) or (type(v) is str and re.fullmatch(r"[A-Za-z0-9_.:-]+", v) is None)
                for v in platform_profile.values())):
            raise ReportError("REPORT_PLATFORM_PROFILE_INVALID")
    original = inventory.file_audit
    parsed = original.declarations
    manifest = None if parsed is None else parsed.manifest
    records = {} if manifest is None else {r.record_id: r for r in manifest.records}
    runs = {} if manifest is None else {r.run_id: r for r in manifest.runs}
    files = {f.record_id: f for f in original.files}
    owners = {(o.owner_kind, o.owner_id): o for o in inventory.evidence_owners}
    adoptions = {a.record_id: a for a in inventory.adoptions}
    redacted, rows = [], []
    link_count = 0

    def aliases(values, prefix):
        return {value: f"{prefix}-{index:06d}" for index, value in enumerate(sorted(set(values)), 1)}

    record_aliases = aliases(records, "file")
    run_aliases = aliases(runs, "run")
    unknown_ids = {r.target_id for r in inventory.relations if r.target_id not in records}
    record_aliases.update(aliases(unknown_ids, "unresolved"))
    families = aliases((r.logical_artifact_id for r in records.values()
                        if r.logical_artifact_id is not None), "family")
    labels = aliases((r.version_label for r in records.values() if r.version_label is not None), "version")
    scopes = aliases((r.adoption_scope for r in records.values() if r.adoption_scope is not None), "scope")

    def linked(values, mapping=record_aliases):
        nonlocal link_count
        link_count += len(values)
        if link_count > MAX_LINKS:
            raise ReportError("REPORT_REFERENCE_LIMIT")
        return [mapping[v] for v in values]

    def subject(kind, value):
        if kind == "record":
            return record_aliases.get(value, "input-000001")
        if kind == "run":
            return run_aliases.get(value, "input-000001")
        if kind == "version":
            return families.get(value, "input-000001")
        return "input-000001"

    def hidden(path, value, *, allow_local=True, free_text=False):
        # Local scope/version text may itself contain absolute paths. Do not
        # publish those incidentally, even inside an otherwise allowed mapping.
        unsafe = (type(value) is str and
                  (any(token in value for token in ("EXECUTION_VERIFIED", "REPRODUCED", "SCIENTIFICALLY_VALID", "scientific_pass")) or
                   (free_text and re.search(r"[A-Za-z]:[\\/]|\\\\|(?:^|\s)/\S+|/(?:[^\s/]+/)", value) is not None)))
        if (not local or not allow_local or unsafe) and value is not None:
            redacted.append(path)
            return None
        return value

    def check(alias, kind, dimension, name, value, *, target=None):
        state = dict(state=value.state, reason_codes=list(value.reason_codes))
        row = dict(subject_alias=alias, subject_kind=kind, dimension=dimension, check=name,
                   state=value.state, reason_codes=list(value.reason_codes), target_alias=target,
                   finding_code=None, severity=None)
        rows.append(row)
        if len(rows) > MAX_ROWS:
            raise ReportError("REPORT_ROW_LIMIT")
        return state

    relations = []
    by_owner = {}
    for relation in inventory.relations:
        alias = subject(relation.owner_kind, relation.owner_id)
        item = dict(owner_kind=relation.owner_kind, owner_alias=alias, field=relation.field,
                    target_alias=record_aliases[relation.target_id], state=str(relation.state),
                    reason_codes=list(relation.reason_codes), route=relation.route)
        relations.append(item)
        by_owner.setdefault((relation.owner_kind, relation.owner_id), []).append(item)
        check(alias, relation.owner_kind, "relationship", relation.field,
              Check(str(relation.state), relation.reason_codes), target=item["target_alias"])

    def evidence(kind, rid):
        owner = owners.get((kind, rid))
        if owner is None:
            return dict(references=[], raw_reference_count=0, unique_reference_count=0,
                        duplicate_reference_count=0, invalid_reference_count=0)
        alias = subject(kind, rid)
        references = []
        for index, item in enumerate(owner.references):
            target = record_aliases[item.relation.target_id]
            entry = dict(target_alias=target, positions=list(item.positions),
                         occurrence_count=item.occurrence_count, route=item.relation.route,
                         reference_state=str(item.relation.state),
                         target_logical_role=item.target_logical_role,
                         target_artifact_type=item.target_artifact_type,
                         target_location_type=item.target_location_type,
                         qualified_read=item.qualified_read, known_integrity_conflict=item.known_integrity_conflict,
                         material_reason_codes=list(item.material_reason_codes),
                         content_evaluation=item.content_evaluation,
                         reproduction=check(alias, kind, "reproduction", "material_claim", item.reproduction, target=target),
                         execution=check(alias, kind, "execution", "material_content", item.execution, target=target))
            # File facts are projected from the original observation, not
            # reopened, reevaluated or inferred from a route/name.
            for name in ("presence", "fingerprint", "size", "digest"):
                value = Check("NOT_VERIFIED", ("FILE_OBSERVATION_NOT_AVAILABLE",)) if item.file is None else getattr(item.file, name)
                entry[name] = check(alias, kind, "evidence_material", name, value, target=target)
            references.append(entry)
        return dict(references=references, raw_reference_count=owner.raw_reference_count,
                    unique_reference_count=owner.unique_reference_count,
                    duplicate_reference_count=owner.duplicate_reference_count,
                    invalid_reference_count=owner.invalid_reference_count)

    record_views, run_views, mapping = [], [], dict(records=[], runs=[])
    for rid, record in sorted(records.items()):
        alias = record_aliases[rid]
        base = f"records/{alias}"
        observed = files.get(rid)
        view = dict(subject_alias=alias, logical_role=record.logical_role, artifact_type=record.artifact_type,
                    location_type=record.location_type, family_alias=families.get(record.logical_artifact_id),
                    version_alias=labels.get(record.version_label), scope_alias=scopes.get(record.adoption_scope),
                    source_record_aliases=linked(record.source_record_ids),
                    relations=by_owner.get(("record", rid), []), evidence=evidence("record", rid),
                    hash_algorithm=record.hash_algorithm if record.hash_algorithm in (None, "sha256", "md5") else "unsupported",
                    expected_size=hidden(base + "/expected_size", record.expected_size),
                    expected_digest=hidden(base + "/expected_digest", record.expected_digest, free_text=True),
                    observed_size=hidden(base + "/observed_size", None if observed is None else observed.observed_size),
                    observed_sha256=hidden(base + "/observed_sha256", None if observed is None else observed.observed_sha256),
                    atomic_snapshot="NOT_ESTABLISHED")
        for name in ("presence", "fingerprint", "size", "digest"):
            value = Check("NOT_VERIFIED", ("FILE_OBSERVATION_NOT_AVAILABLE",)) if observed is None else getattr(observed, name)
            view[name] = check(alias, "record", "identity" if name in ("presence", "fingerprint") else "integrity", name, value)
        view["read_consistency"] = "NOT_VERIFIED" if observed is None else observed.read_consistency
        view["primary_code"] = None if observed is None else observed.primary_code
        view["result_code"] = None if observed is None else observed.result_code
        view["cleanup_errors"] = [] if observed is None else list(observed.cleanup_errors)
        view["read_statistics"] = {name: hidden(base + "/read_statistics/" + name,
                                               None if observed is None else getattr(observed, name))
                                    for name in ("read_bytes", "known_read_bytes", "requested_bytes", "read_calls")}
        owner = owners.get(("record", rid))
        view["execution"] = check(alias, "record", "execution", "content", Check("NOT_VERIFIED", ("EVIDENCE_CONTENT_NOT_EVALUATED_V010",)) if owner is None else owner.execution)
        view["execution_evaluation"] = "NOT_EVALUATED"
        claims = [dict(target_alias=e["target_alias"], **e["reproduction"]) for e in view["evidence"]["references"]
                  if e["target_artifact_type"] == "reproduction_record"]
        view["reproduction"] = dict(material_claims=claims, authentication="NOT_VERIFIED")
        if not claims:
            check(alias, "record", "reproduction", "materials", Check("NOT_VERIFIED", ("NO_REPRODUCTION_REFERENCE",)))
        if not record.source_record_ids:
            check(alias, "record", "relationship", "source_record_ids", Check("NOT_VERIFIED", ("NO_SOURCE_REFERENCE_DECLARED",)))
        adopted = adoptions.get(rid)
        declaration = Check("NOT_VERIFIED", ("ADOPTION_NOT_EVALUATED",)) if adopted is None else adopted.declared
        assessment = declaration if adopted is None else adopted.assessment
        view["adoption"] = dict(declaration=record.adoption_declaration,
                                declared=check(alias, "record", "adoption", "declared", declaration),
                                assessment=check(alias, "record", "adoption", "assessment", assessment),
                                scope_alias=scopes.get(record.adoption_scope),
                                conflicting_record_aliases=[] if adopted is None else linked(adopted.conflicting_record_ids))
        record_views.append(view)
        raw = dict(subject_alias=alias,
                   record_id=hidden(base + "/mapping/record_id", rid),
                   relative_path=hidden(base + "/mapping/relative_path", record.relative_path),
                   hash_algorithm=hidden(base + "/mapping/hash_algorithm", record.hash_algorithm),
                   logical_artifact_id=hidden(base + "/mapping/logical_artifact_id", record.logical_artifact_id),
                   version_label=hidden(base + "/mapping/version_label", record.version_label, free_text=True),
                   adoption_scope=hidden(base + "/mapping/adoption_scope", record.adoption_scope, free_text=True))
        mapping["records"].append(raw)
    for rid, run in sorted(runs.items()):
        alias = run_aliases[rid]
        owner = owners.get(("run", rid))
        run_evidence = evidence("run", rid)
        claims = [dict(target_alias=e["target_alias"], **e["reproduction"]) for e in run_evidence["references"]
                  if e["target_artifact_type"] == "reproduction_record"]
        if not claims:
            check(alias, "run", "reproduction", "materials", Check("NOT_VERIFIED", ("NO_REPRODUCTION_REFERENCE",)))
        run_views.append(dict(subject_alias=alias, script_record_aliases=linked(run.script_record_ids),
                              input_record_aliases=linked(run.input_record_ids), output_record_aliases=linked(run.output_record_ids),
                              relations=by_owner.get(("run", rid), []), evidence=run_evidence,
                              reproduction=dict(material_claims=claims, authentication="NOT_VERIFIED"),
                              execution=check(alias, "run", "execution", "content", Check("NOT_VERIFIED", ("EVIDENCE_CONTENT_NOT_EVALUATED_V010",)) if owner is None else owner.execution),
                              execution_evaluation="NOT_EVALUATED", atomic_snapshot="NOT_ESTABLISHED"))
        mapping["runs"].append(dict(subject_alias=alias, run_id=hidden("runs/" + alias + "/mapping/run_id", rid)))
    findings = []
    source_findings = list(inventory.findings)
    for code in original.input_reason_codes:
        source_findings.append(Finding(code, Severity.ERROR if code in ("FILE_MISSING", "INPUT_BYTE_LIMIT") else Severity.WARN))
    for finding in source_findings:
        alias = subject(finding.subject_kind, finding.subject_id)
        target = labels.get(finding.target_id) if finding.subject_kind == "version" else record_aliases.get(finding.target_id)
        related = linked(finding.related_ids, run_aliases if finding.code == "EVIDENCE_SHARED_ACROSS_RUNS" else record_aliases)
        entry = dict(subject_alias=alias, subject_kind=finding.subject_kind, code=finding.code,
                     severity=str(finding.severity), field=finding.field if finding.field in _FIELDS else None,
                     target_alias=target, positions=list(finding.positions), related_aliases=related,
                     conflict_fields=[v for v in finding.conflict_fields if v in _FIELDS])
        findings.append(entry)
        rows.append(dict(subject_alias=alias, subject_kind=finding.subject_kind, dimension="diagnostic",
                         check="finding", state=str(finding.severity), reason_codes=[], target_alias=target,
                         finding_code=finding.code, severity=str(finding.severity)))
    groups = [dict(kind=g.kind, record_aliases=linked(g.record_ids),
                   observed_size=hidden(f"content_groups/{i}/observed_size", g.observed_size),
                   observed_sha256=hidden(f"content_groups/{i}/observed_sha256", g.observed_sha256))
              for i, g in enumerate(inventory.content_groups)]
    versions = [dict(family_alias=families[v.logical_artifact_id], version_alias=labels[v.version_label],
                     record_aliases=linked(v.record_ids), observed_record_aliases=linked(v.observed_record_ids),
                     unverified_record_aliases=linked(v.unverified_record_ids), conflict_observed=v.conflict_observed,
                     comparison_complete=v.comparison_complete,
                     content_variants=[dict(record_aliases=linked(c.record_ids)) for c in v.content_variants])
                for v in inventory.version_scopes]
    rows.sort(key=lambda row: (row["subject_kind"], row["subject_alias"], row["dimension"], row["check"],
                               row["target_alias"] or "", row["finding_code"] or "", row["state"], row["reason_codes"]))
    coverage = dict(records=len(record_views), runs=len(run_views), relations=len(relations), findings=len(findings),
                    error_findings=sum(f["severity"] == "ERROR" for f in findings),
                    warning_findings=sum(f["severity"] == "WARN" for f in findings),
                    execution_content_evaluated=0, execution_content_not_evaluated=len(record_views) + len(run_views),
                    checks=len(rows), states={}, dimensions={},
                    blocked_record_aliases=[record_aliases[f.record_id] for f in original.files
                                            if f.result_code not in ("READ_COMPLETED", "FILE_MISSING", "EXTERNAL_NOT_READ")],
                    not_evaluated=["EXECUTION_CONTENT_ASSOCIATION", "R03_AGGREGATION", "REPRODUCTION_AUTHENTICATION",
                                   "APPROVAL_AUTHENTICATION", "SCIENTIFIC_CONCLUSION", "MD5_COMPARISON"])
    for row in rows:
        coverage["states"][row["state"]] = coverage["states"].get(row["state"], 0) + 1
        dimension = coverage["dimensions"].setdefault(row["dimension"], {})
        dimension[row["state"]] = dimension.get(row["state"], 0) + 1
    document = dict(report_schema_version="1.0", tool_version=__version__, policy_version="trusted-workspace-v010-c0",
                     audit_completion=original.audit_completion, report_complete=False, report_files={},
                     report_profile=report_profile, input_manifest_digest=hidden("input_manifest_digest", manifest_digest),
                     input_manifest_digest_available=manifest_digest is not None,
                     input_runs_digest=hidden("input_runs_digest", runs_digest), input_runs_digest_available=runs_digest is not None,
                     scope=dict(root_alias="root-000001", workspace_mode=original.workspace_mode,
                                platform_profile=platform_profile, atomic_snapshot="NOT_ESTABLISHED",
                                boundary=BOUNDARY, execution_content="NOT_EVALUATED", reproduction_authentication="NOT_VERIFIED"),
                     schema_status="NOT_EVALUATED" if parsed is None else str(parsed.schema_status),
                     structure_status="NOT_EVALUATED" if parsed is None else str(parsed.structure_status),
                     records=record_views, runs=run_views, findings=findings, relations=relations, checks=rows,
                     content_groups=groups, version_scopes=versions,
                     locator_groups=[dict(kind=g.kind, record_aliases=linked(g.record_ids)) for g in inventory.locator_groups],
                     version_label_aliases=[dict(kind=a.kind, family_alias=families[a.logical_artifact_id],
                                                 version_aliases=[labels[v] for v in a.version_labels],
                                                 record_aliases=linked(a.content.record_ids)) for a in inventory.version_label_aliases],
                     coverage=coverage, mapping=mapping, redacted_fields=sorted(redacted))
    if len(rows) > MAX_ROWS:
        raise ReportError("REPORT_ROW_LIMIT")
    return ReportFacts(json_bytes(document))
