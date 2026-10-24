"""Read-only wrapper over the unchanged candidate consumer."""
import sys
from pathlib import Path
def main():
    if len(sys.argv) != 3:
        print("Usage: verify_checklist_example.py CANDIDATE.pyz CHECKLIST_REPORT_DIR", file=sys.stderr)
        return 4
    package = Path(sys.argv[1])
    if not package.is_file() or package.suffix != ".pyz":
        print("CANDIDATE_REQUIRED", file=sys.stderr)
        return 4
    sys.path.insert(0, str(package))
    try:
        from omics_provenance_audit.product.checklist_report import verify_checklist_bundle
        verify_checklist_bundle(sys.argv[2])
    except Exception:
        print("CHECKLIST_PACKAGE_NOT_CONFIRMED", file=sys.stderr)
        return 4
    print("CHECKLIST_PACKAGE_INTEGRITY_CONFIRMED")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
