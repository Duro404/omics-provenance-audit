"""Small composition layer. File facts do not mutate declaration observations."""

from ..manifest import parse_manifest
from ..models import Finding, Limits, SchemaStatus, Severity
from .models import AuditResult, Check, FileAudit, ReadLimits, WORKSPACE_MODE
from .reader import _Outcome, _Refused, _Workspace, _input_bytes, _io_code


def _check(state="NOT_VERIFIED", reason=None):
    return Check(state, (reason,) if reason else ())


def _file_result(record, out):
    good = out.result == "READ_COMPLETED"
    reason = out.result
    size = _check(reason=reason)
    digest = _check(reason=reason)
    if good:
        size = (_check(reason="NO_EXPECTED_SIZE") if record.expected_size is None else
                _check("MATCH" if record.expected_size == out.size else "MISMATCH"))
        if record.hash_algorithm == "sha256" and record.expected_digest is not None:
            digest = _check("SHA256_MATCH" if record.expected_digest == out.sha256 else "MISMATCH")
        elif record.hash_algorithm == "md5":
            digest = _check(reason="MD5_COMPARISON_NOT_IMPLEMENTED_V010")
        elif record.hash_algorithm is not None and record.hash_algorithm != "sha256":
            digest = _check(reason="UNSUPPORTED_HASH_ALGORITHM")
        elif record.hash_algorithm is not None or record.expected_digest is not None:
            digest = _check(reason="HASH_DECLARATION_INCOMPLETE")
        else:
            digest = _check(reason="NO_EXPECTED_DIGEST")
    return FileAudit(
        record_id=record.record_id,
        presence=_check(out.presence, None if out.presence == "PRESENT" else reason),
        fingerprint=_check("OBSERVED_SHA256") if good else _check(reason=reason),
        size=size, digest=digest, observed_type=out.observed_type,
        observed_size=out.size, observed_sha256=out.sha256,
        primary_code=out.primary, result_code=out.result, cleanup_errors=out.cleanup,
        read_bytes=out.known_bytes if out.counts_complete else None,
        known_read_bytes=out.known_bytes, requested_bytes=out.requested, read_calls=out.calls,
        read_consistency="NO_CHANGE_DETECTED" if good else "NOT_VERIFIED",
    )


def _findings(files):
    found = []
    for item in files:
        if item.result_code == "FILE_MISSING":
            found.append(Finding("FILE_MISSING", Severity.ERROR, "record", item.record_id))
        elif item.result_code not in ("READ_COMPLETED", "EXTERNAL_NOT_READ"):
            severity = Severity.ERROR if item.result_code == "INTERNAL_ERROR" else Severity.WARN
            found.append(Finding(item.result_code, severity, "record", item.record_id))
        if item.size.state == "MISMATCH":
            found.append(Finding("SIZE_MISMATCH", Severity.ERROR, "record", item.record_id,
                                 "expected_size"))
        if item.digest.state == "MISMATCH":
            found.append(Finding("DIGEST_MISMATCH", Severity.ERROR, "record", item.record_id,
                                 "expected_digest"))
        if (item.result_code == "READ_COMPLETED" and item.digest.state == "NOT_VERIFIED" and
            item.digest.reason_codes != ("NO_EXPECTED_DIGEST",)):
            found.append(Finding(item.digest.reason_codes[0], Severity.WARN,
                                 "record", item.record_id, "expected_digest"))
    return found


def audit_bytes(data: bytes, format: str, *, root, workspace_mode: str,
                runs_data: bytes | None = None, manifest_version: str = "1.0",
                limits: Limits | None = None, read_limits: ReadLimits | None = None) -> AuditResult:
    """Audit declared files in an explicitly trusted local development workspace.

    No scripts, evidence contents, adoption decisions, reports or CLI. The
    result includes private IDs and fingerprints and must not be published as
    a public report. Unsupported platforms/volumes fail closed. This mode does
    not defend against hostile path replacement or establish atomic snapshots.
    """
    parsed = parse_manifest(data, format, runs_data=runs_data,
                            manifest_version=manifest_version, limits=limits)
    if parsed.schema_status == SchemaStatus.INVALID:
        return AuditResult(parsed, (), parsed.findings, "REJECTED")
    read_limits = ReadLimits() if read_limits is None else read_limits
    if type(read_limits) is not ReadLimits:
        raise TypeError("READ_LIMITS_REQUIRED")
    reader, root_error = None, None
    if type(workspace_mode) is not str or workspace_mode != WORKSPACE_MODE:
        root_error = "WORKSPACE_MODE_REQUIRED"
    elif any(r.location_type == "local" for r in parsed.manifest.records):
        try:
            reader = _Workspace(root, read_limits)
        except _Refused as exc:
            root_error = exc.code
        except OSError as exc:
            root_error = _io_code(exc)
            if root_error == "FILE_MISSING":
                root_error = "ROOT_UNAVAILABLE"
        except (TypeError, ValueError):
            root_error = "PATH_INVALID"
        except Exception:
            root_error = "INTERNAL_ERROR"
    files = []
    for record in parsed.manifest.records:
        if record.location_type == "external":
            out = _Outcome(primary="EXTERNAL_NOT_READ", result="EXTERNAL_NOT_READ")
        elif root_error:
            out = _Outcome(primary=root_error, result=root_error)
        else:
            out = reader.read(record.relative_path)
        files.append(_file_result(record, out))
    files = tuple(files)
    findings = tuple(sorted(parsed.findings + tuple(_findings(files)), key=lambda f: (
        f.subject_kind, f.subject_id or "", f.field or "", f.code, f.target_id or "")))
    partial = bool(root_error) or any(
        f.result_code not in ("READ_COMPLETED", "FILE_MISSING", "EXTERNAL_NOT_READ") or
        (f.result_code == "READ_COMPLETED" and f.digest.state == "NOT_VERIFIED" and
         f.digest.reason_codes != ("NO_EXPECTED_DIGEST",)) for f in files)
    return AuditResult(parsed, files, findings, "PARTIAL" if partial else "COMPLETE",
                       (root_error,) if root_error else (),
                       sum(f.known_read_bytes for f in files))


def audit_paths(manifest_path, format: str, *, root, workspace_mode: str,
                runs_path=None, manifest_version: str = "1.0", limits: Limits | None = None,
                read_limits: ReadLimits | None = None) -> AuditResult:
    """Bounded, explicitly selected declaration files; never a directory scan."""
    if type(workspace_mode) is not str or workspace_mode != WORKSPACE_MODE:
        return AuditResult(None, (), (), "REJECTED", ("WORKSPACE_MODE_REQUIRED",))
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise TypeError("LIMITS_REQUIRED")
    try:
        data = _input_bytes(manifest_path, limits.max_input_bytes)
        runs = None if runs_path is None else _input_bytes(runs_path, limits.max_input_bytes)
    except _Refused as exc:
        return AuditResult(None, (), (), "REJECTED", (exc.code,))
    except OSError as exc:
        return AuditResult(None, (), (), "REJECTED", (_io_code(exc),))
    except (TypeError, ValueError):
        return AuditResult(None, (), (), "REJECTED", ("INPUT_PATH_INVALID",))
    except Exception:
        return AuditResult(None, (), (), "REJECTED", ("INTERNAL_ERROR",))
    return audit_bytes(data, format, root=root, workspace_mode=workspace_mode, runs_data=runs,
                       manifest_version=manifest_version, limits=limits, read_limits=read_limits)
