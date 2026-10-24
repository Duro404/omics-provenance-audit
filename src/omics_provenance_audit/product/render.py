"""Render only the projected canonical checks; never re-evaluate evidence."""

import csv
import io

from .projection import BOUNDARY, MAX_REPORT_BYTES, ReportError

TSV_FIELDS = ("subject_alias", "subject_kind", "dimension", "check", "state",
              "finding_code", "severity", "reason_code", "target_alias")


def render_companions(facts):
    document = facts.document()
    tsv = io.StringIO(newline="")
    writer = csv.DictWriter(tsv, TSV_FIELDS, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    md = ["# Omics Provenance Audit", "", BOUNDARY, "", "## 范围与环境", "",
          "审计操作范围：`" + document["audit_completion"] + "`。视图：`" + document["report_profile"] + "`。", "",
          "工作区模式：`" + document["scope"]["workspace_mode"] + "`。",
          "仅审核用户控制的本地工作区；不抵御恶意并发路径替换，不提供原子科研快照。", ""]
    profile = document["scope"]["platform_profile"]
    if profile:
        md += ["平台：`" + profile["profile_id"] + "`；状态：`" + profile["validation_status"] + "`。", ""]
    md += ["## 文件完整性", ""]
    for state, count in sorted(document["coverage"]["dimensions"].get("integrity", {}).items()):
        md.append(f"- `{state}`: {count}")
    md += ["", "## 确定问题及声明缺口", ""]
    if not document["findings"]:
        md.append("本次所选检查未生成 finding；这不证明证据充分。")
    for finding in document["findings"]:
        md.append("- `" + finding["severity"] + "` / `" + finding["code"] + "` / `" + finding["subject_alias"] + "`")
    md += ["", "## 来源与版本", "", f"声明关系：{len(document['relations'])}；观察内容等价组：{len(document['content_groups'])}。", ""]
    for version in document["version_scopes"]:
        md.append("- `" + version["family_alias"] + "` / `" + version["version_alias"] + "`："
                  + ("VERSION_CONTENT_CONFLICT" if version["conflict_observed"] else "未观察到版本内容冲突")
                  + f"；未验证记录数 {len(version['unverified_record_aliases'])}。")
    md += ["", "## 运行与复现材料", "", "运行内容未评估；附件、文件匹配和自述均不认证真实执行。", ""]
    for owner in document["records"] + document["runs"]:
        evidence = owner["evidence"]
        md.append(f"- `{owner['subject_alias']}`：原始引用 {evidence['raw_reference_count']}，唯一引用 {evidence['unique_reference_count']}，无效引用 {evidence['invalid_reference_count']}；运行 `{owner['execution']['state']}`。")
        for claim in owner["reproduction"]["material_claims"]:
            md.append(f"  - 复现材料 `{claim['target_alias']}`：`{claim['state']}`。")
    md += ["", "## 未验证与限制", "", "复现独立性、采用批准者、科研结论正确性未验证；MD5比较、运行内容关联及多材料聚合未实施。",
           "统计与关系仍可能具有识别性，公开前需人工审阅；local 明细只在 JSON 受控字段中显示。", "",
           "## 报告完整性核验", "", "须同时核验audit.json及伴随摘要；本文件不单独证明报告包已完整提交。",
           "最终 JSON 的 report_complete 与当前两伴随文件的大小和 SHA256 必须同时符合；这不认证作者或科学结论。", "",
           "## 审计明细", "",
          "| subject_alias | subject_kind | dimension | check | state | finding_code | severity | reason_code | target_alias |",
          "|---|---|---|---|---|---|---|---|---|"]
    for check in document["checks"]:
        row = {key: check.get(key) or "" for key in TSV_FIELDS if key != "reason_code"}
        row["reason_code"] = ";".join(check["reason_codes"])
        # All cells come from tool enums/codes or generated aliases. Local raw
        # values never enter either table, including formula/HTML-looking text.
        writer.writerow(row)
        md.append("| " + " | ".join(row[key] for key in TSV_FIELDS) + " |")
    md += ["", "覆盖计数：", "", f"- records: {document['coverage']['records']}",
           f"- runs: {document['coverage']['runs']}", f"- checks: {document['coverage']['checks']}",
           f"- findings: {document['coverage']['findings']}", ""]
    result = {"audit_details.tsv": tsv.getvalue().encode("utf-8"), "audit.md": "\n".join(md).encode("utf-8")}
    if any(len(value) > MAX_REPORT_BYTES for value in result.values()):
        raise ReportError("REPORT_BYTE_LIMIT")
    return result
