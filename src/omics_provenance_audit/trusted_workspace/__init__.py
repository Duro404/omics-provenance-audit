"""Trusted local workspace prototype; no CLI or formal report writer.

Import explicitly. Importing the Phase 1A package never enables file I/O.
Only a local fixed NTFS Windows candidate is currently implemented; native
profile acceptance remains pending. Linux is deliberately not enabled here.
"""

from .audit import audit_bytes, audit_paths
from .models import AuditResult, Check, FileAudit, ReadLimits, WORKSPACE_MODE

__all__ = ["audit_bytes", "audit_paths", "AuditResult", "Check", "FileAudit",
           "ReadLimits", "WORKSPACE_MODE"]
