"""Checklist-only projection and CHECKLIST_COMMIT_V1 (not Audit R05).

Renderers share one projected document. A complete bundle may truthfully report
missing requirements or a partial draft. Neither means a scientific workflow ran.
"""

from dataclasses import dataclass
import csv
import hashlib
import io
import re

from ..manifest import parse_manifest
from ..trusted_workspace import WORKSPACE_MODE
from . import __version__
from .projection import ReportError, json_bytes, MAX_REPORT_BYTES
from .publish import OutputTransaction, strict_json, _read

COMPANIONS = ("checklist_details.tsv", "checklist.md")
DRAFT = "manifest_draft.json"
TSV_FIELDS = ("rule_alias", "step_alias", "line", "state", "required", "min_matches",
              "matched_count", "eligible_count", "exported_count", "reason_codes",
              "file_aliases", "draft_record_ids", "step_name_display", "expected_path_display")
BOUNDARY = ("仅核对用户声明的文件要求；数量满足不证明分析成功。导出摘要仅为当前观察基线，"
            "重新审核匹配不证明上游来源、真实执行、样本正确、正式采用或独立复现。")


@dataclass(frozen=True, slots=True)
class ChecklistFacts:
    encoded: bytes

    def document(self):
        return strict_json(self.encoded)


def _local_text(value):
    # The checklist has no absolute-path display field. Free-text names can
    # themselves contain private absolute locations; redact those as a whole.
    if value is None:
        return None
    if re.search(r"[A-Za-z]:[\\/]|(?:^|\s)[/\\]", value):
        return "[REDACTED_PATH_TEXT]"
    return value


def project_checklist(result, *, report_profile="public", platform_profile=None):
    if report_profile not in ("public", "local"):
        raise ReportError("REPORT_PROFILE_INVALID")
    if result.export_requested and report_profile != "local":
        raise ReportError("CHECKLIST_EXPORT_REQUIRES_LOCAL")
    local = report_profile == "local"
    step_ids = sorted({row.rule.step_id for row in result.rules if row.rule.step_id is not None})
    steps = {sid: f"step-{i:06d}" for i, sid in enumerate(step_ids, 1)}
    paths = {file.relative_path: f"file-{i:06d}" for i, file in enumerate(result.files, 1)}
    file_map = {file.relative_path: file for file in result.files}
    rows = []
    for i, row in enumerate(result.rules, 1):
        rule = row.rule
        item = dict(rule_alias=f"rule-{i:06d}", step_alias=steps.get(rule.step_id), line=rule.line,
                    state=row.state, required=rule.required, min_matches=rule.min_matches,
                    matched_count=len(row.matched_paths) if row.count_complete else None,
                    eligible_count=len(row.eligible_paths) if row.count_complete else None,
                    exported_count=len(row.qualified_paths), reason_codes=list(row.reason_codes),
                    file_aliases=[paths[path] for path in row.matched_paths],
                    draft_record_ids=[file_map[path].draft_record_id for path in row.qualified_paths])
        if local:
            item["local"] = dict(step_id=rule.step_id, step_name=_local_text(rule.step_name),
                                 expected_path=rule.expected_path)
        rows.append(item)
    step_rows = []
    for sid in step_ids:
        owned = [row for row in result.rules if row.rule.step_id == sid]
        required = [row for row in owned if row.rule.required is True]
        if any(row.state in ("REQUIRED_MISSING", "REQUIRED_INSUFFICIENT") for row in required):
            state = "FILE_REQUIREMENTS_NOT_MET"
        elif any(row.state == "INVALID_RULE" or row.rule.required is None for row in owned) or any(row.state == "BLOCKED" for row in required):
            state = "NOT_VERIFIED"
        elif not required:
            state = "NO_REQUIRED_RULES"
        else:
            state = "FILE_REQUIREMENTS_MET"
        step_rows.append(dict(step_alias=steps[sid], file_requirement_state=state,
                              rule_aliases=[item["rule_alias"] for item, row in zip(rows, result.rules) if row.rule.step_id == sid]))
    definite_missing = any(row.state in ("REQUIRED_MISSING", "REQUIRED_INSUFFICIENT") for row in result.rules)
    uncertain = bool(result.input.errors) or any(row.state == "INVALID_RULE" or
                    (row.rule.required is True and row.state == "BLOCKED") for row in result.rules)
    has_required = any(row.rule.required is True for row in result.rules)
    required_satisfied = False if definite_missing else (None if uncertain or not has_required else True)
    complete = not result.input.errors and all(row.state not in ("INVALID_RULE", "BLOCKED") for row in result.rules)
    generated = result.manifest_bytes is not None
    all_rules = generated and complete and all(row.state == "SATISFIED" and
                  len(row.qualified_paths) == len(row.matched_paths) for row in result.rules)
    files = []
    for file in result.files:
        observed = file.observation
        item = dict(file_alias=paths[file.relative_path], metadata_code=file.metadata_code,
                    read_state="NOT_CHECKED" if observed is None else observed.result_code,
                    sha256_state="CURRENT_BASELINE_OBSERVED" if file.draft_record_id else "NOT_VERIFIED",
                    exported=file.draft_record_id is not None, draft_record_id=file.draft_record_id)
        if local:
            item["local"] = dict(relative_path=file.relative_path,
                                 observed_size=None if observed is None else observed.observed_size,
                                 observed_sha256=None if file.draft_record_id is None else observed.observed_sha256,
                                 primary_code=None if observed is None else observed.primary_code,
                                 cleanup_errors=[] if observed is None else list(observed.cleanup_errors),
                                 read_bytes=None if observed is None else observed.read_bytes,
                                 known_read_bytes=None if observed is None else observed.known_read_bytes,
                                 requested_bytes=None if observed is None else observed.requested_bytes,
                                 read_calls=None if observed is None else observed.read_calls)
        files.append(item)
    document = dict(report_kind="WORKFLOW_CHECKLIST", checklist_schema_version="1.0",
                    commit_protocol="CHECKLIST_COMMIT_V1", tool_version=__version__, report_profile=report_profile,
                    workspace_mode=WORKSPACE_MODE, platform_profile=platform_profile,
                    bundle_complete=False, checklist_check_complete=complete,
                    required_rules_satisfied=required_satisfied, workflow_execution_state="NOT_VERIFIED",
                    reproduction_state="NOT_VERIFIED", atomic_snapshot="NOT_ESTABLISHED",
                    strict_native_backend="HOLD", input_errors=list(result.input.errors),
                    steps=step_rows, rules=rows, files=files,
                    coverage=dict(entries_scanned=result.entries_scanned, directories_scanned=result.directories_scanned,
                                  raw_rule_matches=result.raw_matches, unique_matched_files=len(files)),
                    draft=dict(export_requested=result.export_requested, manifest_draft_generated=generated,
                               schema_status=result.draft_schema_status, record_count=sum(file.draft_record_id is not None for file in result.files),
                               covers_all_rules=all_rules, incomplete_current_observation=bool(result.export_requested and not all_rules),
                               reason_code=("CURRENT_OBSERVATION_ONLY" if all_rules else "PARTIAL_CURRENT_OBSERVATION") if generated else
                                           ("NO_QUALIFIED_FILES" if result.export_requested else "EXPORT_NOT_REQUESTED"),
                               baseline_kind="CURRENT_OBSERVATION_ONLY" if generated else "NOT_GENERATED"),
                    limitations=[BOUNDARY, "仅限固定 Windows 本地 NTFS 可信工作区；不抵御恶意并发替换，不提供原子快照。",
                                 "未解析科研文件格式、日志或执行记录；未判断来源、版本继承、采用批准和科研结论。",
                                 "公开视图仍含数量与关系结构；分享前需人工审阅。"], package_files={})
    return ChecklistFacts(json_bytes(document))


def _display(value):
    # An apostrophe is an intentional display prefix, including before =,+,-,@.
    # Raw recoverable local strings live only in JSON, not spreadsheet cells.
    return "" if value is None else "'" + value


def _md_cell(value):
    text = str(value).replace("|", "\\|")
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    return fence + " " + text + " " + fence


def render_checklist(facts):
    document = facts.document()
    tsv = io.StringIO(newline="")
    writer = csv.DictWriter(tsv, TSV_FIELDS, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    md = ["# Omics Provenance Audit — Workflow Checklist", "", BOUNDARY, "",
          "Checklist 独立报告，协议 `CHECKLIST_COMMIT_V1`；不属于 Audit 三文件 R05。", "",
          f"视图：`{document['report_profile']}`；工作区：`{document['workspace_mode']}`。", "",
          f"检查完成：`{document['checklist_check_complete']}`；必需规则满足：`{document['required_rules_satisfied']}`。",
          f"草稿生成：`{document['draft']['manifest_draft_generated']}`；覆盖全部规则：`{document['draft']['covers_all_rules']}`。", "",
          "## 逐条文件要求", "",
          "| 规则 | 步骤 | 状态 | 必需 | 最低数量 | 匹配数量 | 可用普通文件 | 导出数量 | 原因 | 步骤名称 | 相对路径或模式 |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for rule in document["rules"]:
        row = {key: rule[key] for key in TSV_FIELDS if key in rule}
        row["required"] = "" if rule["required"] is None else ("yes" if rule["required"] else "no")
        for key in ("reason_codes", "file_aliases", "draft_record_ids"):
            row[key] = ";".join(rule[key])
        local = rule.get("local", {})
        row["step_name_display"] = _display(local.get("step_name"))
        row["expected_path_display"] = _display(local.get("expected_path"))
        writer.writerow(row)
        md.append("| " + " | ".join(_md_cell(value) for value in (
            rule["rule_alias"], rule["step_alias"], rule["state"], row["required"], rule["min_matches"],
            rule["matched_count"], rule["eligible_count"], rule["exported_count"], row["reason_codes"],
            local.get("step_name", ""), local.get("expected_path", ""))) + " |")
    md += ["", "## 步骤的文件要求", ""]
    md += [f"- `{step['step_alias']}`：`{step['file_requirement_state']}`。" for step in document["steps"]]
    md += ["", "## 导出覆盖与未验证项目", "", f"草稿记录数：{document['draft']['record_count']}；`{document['draft']['reason_code']}`。",
           "规则与草稿 record 的对应关系见 JSON 的 rules[].draft_record_ids。缺失或受阻项保留原状态，未制造记录或摘要。",
           "输入问题：" + ("、".join(document["input_errors"]) or "无"), ""]
    md += document["limitations"]
    md += ["", "## 包完整性", "", "本文件不能单独证明提交完成。消费者须调用 verify_checklist_bundle，核对最终 checklist.json 的",
           "bundle_complete、协议身份、伴随文件清单、当前大小和 SHA256；有草稿时还须复核原 Manifest schema。",
           "该核验不认证作者或科研真实性；未完成残留目录不得重复使用。", ""]
    result = {"checklist_details.tsv": tsv.getvalue().encode("utf-8"), "checklist.md": "\n".join(md).encode("utf-8")}
    if any(len(data) > MAX_REPORT_BYTES for data in result.values()):
        raise ReportError("REPORT_BYTE_LIMIT")
    return result


def verify_checklist_bundle(output_dir):
    from pathlib import Path
    directory = Path(output_dir)
    document = strict_json(_read(directory / "checklist.json"))
    if (type(document) is not dict or document.get("report_kind") != "WORKFLOW_CHECKLIST" or
        document.get("checklist_schema_version") != "1.0" or document.get("commit_protocol") != "CHECKLIST_COMMIT_V1" or
        document.get("bundle_complete") is not True or document.get("report_profile") not in ("local", "public") or
        type(document.get("draft")) is not dict or type(document["draft"].get("manifest_draft_generated")) is not bool):
        raise ReportError("CHECKLIST_PACKAGE_INVALID")
    generated = document["draft"]["manifest_draft_generated"]
    names = COMPANIONS + ((DRAFT,) if generated else ())
    if type(document.get("package_files")) is not dict or set(document["package_files"]) != set(names):
        raise ReportError("CHECKLIST_PACKAGE_INVALID")
    if generated and (document["report_profile"] != "local" or document["draft"].get("export_requested") is not True):
        raise ReportError("CHECKLIST_PACKAGE_INVALID")
    if not generated and (directory / DRAFT).exists():
        raise ReportError("CHECKLIST_UNDECLARED_DRAFT")
    for name in names:
        expected = document["package_files"][name]
        if (type(expected) is not dict or set(expected) != {"bytes", "sha256"} or
            type(expected["bytes"]) is not int or not 0 <= expected["bytes"] <= MAX_REPORT_BYTES or
            type(expected["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]) is None):
            raise ReportError("CHECKLIST_PACKAGE_INVALID")
        data = _read(directory / name)
        if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ReportError("CHECKLIST_COMPANION_MISMATCH")
        if name == DRAFT:
            parsed = parse_manifest(data, "json")
            if (parsed.schema_status != "VALID" or parsed.structure_status != "EVALUATED" or
                any(finding.severity == "ERROR" for finding in parsed.findings) or parsed.manifest is None or
                not parsed.manifest.records or type(document["draft"].get("record_count")) is not int or
                len(parsed.manifest.records) != document["draft"].get("record_count")):
                raise ReportError("CHECKLIST_DRAFT_INVALID")
            ids = {record.record_id for record in parsed.manifest.records}
            rows = document.get("rules")
            if (type(rows) is not list or any(type(row) is not dict or type(row.get("draft_record_ids")) is not list or
                any(type(rid) is not str for rid in row["draft_record_ids"]) for row in rows) or
                {rid for row in rows for rid in row["draft_record_ids"]} != ids):
                raise ReportError("CHECKLIST_DRAFT_MAP_INVALID")
    return document


class ChecklistTransaction(OutputTransaction):
    report_names = COMPANIONS + (DRAFT, "checklist.json")

    def commit(self, facts, manifest_bytes=None):
        try:
            document = facts.document()
            generated = document["draft"]["manifest_draft_generated"]
            if generated != (manifest_bytes is not None) or (generated and document["report_profile"] != "local"):
                raise ReportError("CHECKLIST_EXPORT_CONTRACT_INVALID")
            companions = render_checklist(facts)
            if generated:
                if parse_manifest(manifest_bytes, "json").schema_status != "VALID":
                    raise ReportError("CHECKLIST_DRAFT_INVALID")
                companions[DRAFT] = manifest_bytes
            staged = {name: self._stage(data) for name, data in companions.items()}
            for name, data in companions.items():
                self._publish_no_replace(staged[name], name)
                actual = _read(self.directory / name)
                if actual != data:
                    raise ReportError("CHECKLIST_COMPANION_MISMATCH")
                document["package_files"][name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            document["bundle_complete"] = True
            data = json_bytes(document)
            staged_json = self._stage(data)
            if strict_json(_read(staged_json)) != document:
                raise ReportError("CHECKLIST_PACKAGE_INVALID")
            for name, original in companions.items():
                if _read(self.directory / name) != original:
                    raise ReportError("CHECKLIST_COMPANION_MISMATCH")
            self._publish_no_replace(staged_json, "checklist.json")
            self._guard()
            if _read(self.directory / "checklist.json") != data or verify_checklist_bundle(self.directory) != document:
                raise ReportError("CHECKLIST_PACKAGE_INVALID")
            return document
        except ReportError:
            raise
        except (OSError, ValueError, TypeError, KeyboardInterrupt):
            raise ReportError("CHECKLIST_SUBMISSION_FAILED") from None
