"""Pure declaration relations. No execution evidence evaluation or aggregation."""

from .models import Finding, Relation, RelationState, Severity


def _role_conflict(record):
    role, artifact = record.logical_role, record.artifact_type
    if role in ("unspecified", "other", "input", "output", "intermediate") or artifact == "other":
        return False
    allowed = {"script": {"script"}, "run_log": {"log", "execution_record", "report"},
               "config": {"config"}, "environment": {"environment"}}
    return artifact not in allowed[role]


def _components(graph):
    """Iterative Kosaraju: 10,000-node chains must not consume Python recursion."""
    seen = set()
    order = []
    for start in sorted(graph):
        if start in seen:
            continue
        seen.add(start)
        stack = [(start, iter(graph[start]))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                order.append(node)
                stack.pop()
            elif child not in seen:
                seen.add(child)
                stack.append((child, iter(graph[child])))
    reverse = {node: [] for node in graph}
    for node, children in graph.items():
        for child in children:
            reverse[child].append(node)
    seen.clear()
    components = []
    for start in reversed(order):
        if start in seen:
            continue
        component = []
        seen.add(start)
        stack = [start]
        while stack:
            node = stack.pop()
            component.append(node)
            for child in reverse[node]:
                if child not in seen:
                    seen.add(child)
                    stack.append(child)
        if len(component) > 1:
            components.append(tuple(sorted(component)))
    return tuple(sorted(components))


def check_structure(manifest):
    records = {record.record_id: record for record in manifest.records}
    findings = []
    relations = []
    conflicts = {rid for rid, record in records.items() if _role_conflict(record)}
    for rid in sorted(conflicts):
        findings.append(Finding("ROLE_DECLARATION_CONFLICT", Severity.ERROR, "record", rid,
                                 conflict_fields=("logical_role", "artifact_type")))
    graph = {rid: tuple(target for target in record.source_record_ids
                        if target in records and target != rid) for rid, record in records.items()}
    component_by_node = {}
    for index, component in enumerate(_components(graph)):
        for rid in component:
            component_by_node[rid] = index
        findings.append(Finding("SOURCE_CYCLE", Severity.ERROR, "source_graph",
                                 related_ids=component))
    for record in manifest.records:
        for target in record.source_record_ids:
            state = RelationState.DECLARED
            code = None
            if target == record.record_id:
                state, code = RelationState.DECLARATION_CONFLICT, "SOURCE_SELF_REFERENCE"
            elif target not in records:
                state, code = RelationState.INVALID_REFERENCE, "SOURCE_REFERENCE_UNKNOWN"
            elif (record.record_id in component_by_node and
                  component_by_node.get(target) == component_by_node[record.record_id]):
                state, code = RelationState.DECLARATION_CONFLICT, "SOURCE_CYCLE"
            if code and code != "SOURCE_CYCLE":
                findings.append(Finding(code, Severity.ERROR, "record", record.record_id,
                                         "source_record_ids", target))
            relations.append(Relation("record", record.record_id, "source_record_ids", target,
                                       state, (code,) if code else ()))
    for run in manifest.runs:
        for position in ("script_record_ids", "input_record_ids", "output_record_ids"):
            for target in getattr(run, position):
                state = RelationState.DECLARED
                code = None
                bad_fields = []
                if target not in records:
                    state, code = RelationState.INVALID_REFERENCE, "RUN_MEMBER_UNKNOWN"
                else:
                    record = records[target]
                    if target in conflicts:
                        bad_fields.append("record_role_conflict")
                    if position == "script_record_ids":
                        if record.artifact_type not in ("script", "other"):
                            bad_fields.append("artifact_type")
                        if record.logical_role in ("run_log", "config", "environment"):
                            bad_fields.append("logical_role")
                    if bad_fields:
                        state, code = RelationState.DECLARATION_CONFLICT, "RUN_ROLE_CONFLICT"
                if code:
                    findings.append(Finding(code, Severity.ERROR, "run", run.run_id, position,
                                             target, conflict_fields=tuple(bad_fields)))
                relations.append(Relation("run", run.run_id, position, target, state,
                                           (code,) if code else ()))
    shared = {}
    for kind, owners in (("record", manifest.records), ("run", manifest.runs)):
        for owner in owners:
            owner_id = owner.record_id if kind == "record" else owner.run_id
            members = (set(owner.script_record_ids + owner.input_record_ids + owner.output_record_ids)
                       if kind == "run" else set())
            for target in owner.evidence_reference:
                code, route = None, None
                if kind == "record" and target == owner_id:
                    code = "EVIDENCE_SELF_REFERENCE"
                elif target not in records:
                    code = "EVIDENCE_REFERENCE_UNKNOWN"
                elif records[target].artifact_type not in (
                    "log", "execution_record", "reproduction_record", "report", "other"
                ):
                    code = "EVIDENCE_TYPE_NOT_ALLOWED"
                else:
                    artifact = records[target].artifact_type
                    route = ("reproduction_material" if artifact == "reproduction_record" else
                             "record_attachment" if kind == "record" else "run_evidence_candidate")
                    if artifact == "other":
                        findings.append(Finding("EVIDENCE_TYPE_UNSPECIFIED", Severity.WARN, kind,
                                                 owner_id, "evidence_reference", target))
                    if kind == "run":
                        shared.setdefault(target, []).append(owner_id)
                        if target in members:
                            findings.append(Finding("RUN_EVIDENCE_MEMBER_OVERLAP", Severity.WARN,
                                                     kind, owner_id, "evidence_reference", target))
                if code:
                    findings.append(Finding(code, Severity.ERROR, kind, owner_id,
                                             "evidence_reference", target))
                relations.append(Relation(kind, owner_id, "evidence_reference", target,
                                           RelationState.INVALID_REFERENCE if code else RelationState.DECLARED,
                                           (code,) if code else (), route))
    for target, runs in sorted(shared.items()):
        if len(runs) > 1:
            findings.append(Finding("EVIDENCE_SHARED_ACROSS_RUNS", Severity.INFO, "record", target,
                                     "evidence_reference", related_ids=tuple(sorted(runs))))
    relations.sort(key=lambda r: (r.owner_kind, r.owner_id, r.field, r.target_id))
    return tuple(relations), tuple(findings)
