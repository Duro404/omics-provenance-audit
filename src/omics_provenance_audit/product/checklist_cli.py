"""Checklist orchestration over existing trusted-workspace and output helpers."""

from ..trusted_workspace import ReadLimits
from ..trusted_workspace.reader import _input_bytes, _Refused, _io_code
from .checklist import ChecklistLimits, ChecklistInput, parse_checklist, run_checklist, checklist_exit
from .checklist_report import ChecklistTransaction, project_checklist
from .profile import fixed_profile
from .projection import ReportError


def main_checklist(args):
    # Check consent before input access, workspace scanning or output creation.
    if args.export_manifest and args.report_profile != "local":
        raise ReportError("CHECKLIST_EXPORT_REQUIRES_LOCAL")
    try:
        limits = ChecklistLimits(max_input_bytes=args.max_checklist_bytes, max_rules=args.max_rules,
                                 max_entries=args.max_entries, max_matches=args.max_matches,
                                 max_directories=args.max_directories)
        read_limits = ReadLimits(max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes)
    except ValueError:
        raise ReportError("CHECKLIST_BUDGET_INVALID") from None
    profile = fixed_profile(args.root)
    transaction = ChecklistTransaction(root=args.root, input_paths=[args.checklist], output_dir=args.out)
    try:
        parsed = parse_checklist(_input_bytes(args.checklist, limits.max_input_bytes), limits)
    except _Refused as exc:
        parsed = ChecklistInput(errors=(exc.code,))
    except OSError as exc:
        parsed = ChecklistInput(errors=(_io_code(exc),))
    result = run_checklist(parsed, root=args.root, workspace_mode=args.workspace_mode,
                           export_manifest=args.export_manifest, limits=limits, read_limits=read_limits)
    facts = project_checklist(result, report_profile=args.report_profile, platform_profile=profile)
    document = transaction.commit(facts, result.manifest_bytes)
    code = checklist_exit(result)
    print(f"CHECKLIST_BUNDLE_COMMITTED checklist_check_complete={document['checklist_check_complete']} "
          f"required_rules_satisfied={document['required_rules_satisfied']} "
          f"manifest_draft_generated={document['draft']['manifest_draft_generated']} exit_code={code}")
    print("报告位置：所指定的 --out 新目录内 checklist.json、checklist_details.tsv、checklist.md。")
    if result.manifest_bytes is not None:
        print("manifest_draft.json 是本地敏感的当前观察基线；请补充人工声明后交给 audit。")
    print("文件数量满足不证明流程成功；草稿摘要匹配不证明历史执行或独立复现。")
    return code
