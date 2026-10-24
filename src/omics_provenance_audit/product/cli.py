"""Thin CLI over unchanged parser, reader and provenance inventory."""

import argparse
import hashlib
import sys

from ..models import Limits
from ..trusted_workspace import audit_bytes, AuditResult, ReadLimits, WORKSPACE_MODE
from ..trusted_workspace.provenance import audit_provenance
from ..trusted_workspace.reader import _input_bytes, _Refused, _io_code
from . import __version__
from .profile import fixed_profile
from .projection import ReportError, operation_exit, project
from .publish import OutputTransaction, verify_package


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's ordinary errors echo hostile option values and paths.
        raise ReportError("ARGUMENT_INVALID")


def _positive(value):
    if not value.isascii() or not value.isdigit() or len(value) > 19:
        raise argparse.ArgumentTypeError("BUDGET_INVALID")
    number = int(value)
    if not 1 <= number <= 2**63 - 1:
        raise argparse.ArgumentTypeError("BUDGET_INVALID")
    return number


def parser():
    result = _Parser(prog="omics-provenance-audit", description="只读文件与证据材料审核。文件匹配不证明实际执行或科研结论正确。")
    result.add_argument("--version", action="version", version="Omics Provenance Audit " + __version__)
    sub = result.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", description=(
        "TRUSTED_LOCAL_WORKSPACE_V010 只适用于用户自己控制的本地工作区；"
        "不抵御恶意并发路径替换，不提供原子科研快照。输出必须为工作区外的新目录。"))
    audit.add_argument("--manifest", required=True)
    audit.add_argument("--format", required=True, choices=("csv", "tsv", "json"))
    audit.add_argument("--root", required=True)
    audit.add_argument("--out", "--output-dir", dest="out", required=True)
    audit.add_argument("--workspace-mode", required=True, choices=(WORKSPACE_MODE,))
    audit.add_argument("--report-profile", choices=("public", "local"), default="public")
    audit.add_argument("--runs")
    audit.add_argument("--manifest-version", default="1.0")
    audit.add_argument("--max-file-bytes", type=_positive, default=10 * 1024**3)
    audit.add_argument("--max-total-bytes", type=_positive, default=100 * 1024**3)
    verify = sub.add_parser("verify", description="核验当前报告包三文件的绑定完整性；不认证作者、执行或科学结论。")
    verify.add_argument("--out", "--output-dir", dest="out", required=True)
    checklist = sub.add_parser("checklist", description=(
        "在固定 Windows 本地 NTFS 可信工作区检查文件数量；*、? 仅限文件名，按实际大小写匹配。"
        "不递归、不解析科研格式、不认证执行。导出 SHA256 草稿须同时指定 local 与 --export-manifest。"))
    checklist.add_argument("--checklist", required=True)
    checklist.add_argument("--root", required=True)
    checklist.add_argument("--out", "--output-dir", dest="out", required=True)
    checklist.add_argument("--workspace-mode", required=True, choices=(WORKSPACE_MODE,))
    checklist.add_argument("--report-profile", choices=("public", "local"), default="public")
    checklist.add_argument("--export-manifest", action="store_true")
    for name, default in (("max-checklist-bytes", 1024**2), ("max-rules", 1000),
                          ("max-entries", 20_000), ("max-matches", 10_000), ("max-directories", 2048),
                          ("max-file-bytes", 10 * 1024**3), ("max-total-bytes", 100 * 1024**3)):
        checklist.add_argument("--" + name, type=_positive, default=default)
    return result


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="strict")
    try:
        args = parser().parse_args(argv)
        if args.command == "checklist":
            from .checklist_cli import main_checklist
            return main_checklist(args)
        if args.command == "verify":
            fixed_profile(args.out)
            verify_package(args.out)
            print("REPORT_PACKAGE_INTEGRITY_CONFIRMED")
            return 0
        profile = fixed_profile(args.root)
        inputs = [args.manifest] + ([] if args.runs is None else [args.runs])
        transaction = OutputTransaction(root=args.root, input_paths=inputs, output_dir=args.out)
        limits = Limits()
        data, runs = None, None
        try:
            data = _input_bytes(args.manifest, limits.max_input_bytes)
            if args.runs is not None:
                runs = _input_bytes(args.runs, limits.max_input_bytes)
            audit = audit_bytes(data, args.format, root=args.root, workspace_mode=args.workspace_mode,
                                runs_data=runs, manifest_version=args.manifest_version, limits=limits,
                                read_limits=ReadLimits(max_file_bytes=args.max_file_bytes,
                                                       max_total_bytes=args.max_total_bytes))
        except _Refused as exc:
            audit = AuditResult(None, (), (), "REJECTED", (exc.code,))
        except OSError as exc:
            audit = AuditResult(None, (), (), "REJECTED", (_io_code(exc),))
        inventory = audit_provenance(audit)
        facts = project(inventory, report_profile=args.report_profile,
                        manifest_digest=None if data is None else hashlib.sha256(data).hexdigest(),
                        runs_digest=None if runs is None else hashlib.sha256(runs).hexdigest(),
                        platform_profile=profile)
        receipt = transaction.commit(facts)
        code = operation_exit(inventory)
        print(f"REPORT_COMMITTED audit_completion={receipt.audit_completion} exit_code={code}")
        print("报告位置：所指定的 --out 目录内 audit.json、audit_details.tsv、audit.md。")
        print("文件匹配不证明实际执行；材料存在不证明独立复现或科研结论正确。")
        return code
    except ReportError as exc:
        # Exception text outside this class is never printed. Codes here are
        # tool-owned constants, not manifest names or raw OS error messages.
        print(str(exc), file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        print("AUDIT_CANCELLED", file=sys.stderr)
        return 4
    except Exception:
        print("INTERNAL_ERROR", file=sys.stderr)
        return 4
