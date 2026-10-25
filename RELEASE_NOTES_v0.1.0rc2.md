# Omics Provenance Audit v0.1.0rc2 — prerelease candidate

Version 0.1.0rc2 is a pre-release candidate and is not a stable release.

Omics Provenance Audit is an offline, read-only research file checklist and declared
provenance audit. Checklist accepts TSV requirements and optionally exports a local
SHA256 Manifest draft. Audit accepts CSV/TSV/JSON Manifests. Audit and Checklist
produce JSON/TSV/Markdown reports, with separate existing-report consumers.

## License and portable distribution

License: [MIT](LICENSE).
Copyright (c) 2026 Shen Jianuo

Use the versioned distribution bundle supplied with the corresponding GitHub Release
when available. The recommended distribution is the complete ZIP containing LICENSE,
the unchanged RC2 PYZ, documentation and synthetic examples. LICENSE is not inside
the original PYZ.
Standalone PYZ distribution must separately supply the required license/copyright
notice and receive distribution-method approval. This is not a reproducible-build certification.

## Validated scope and evidence limits

Only Windows API10.0/build26200 + CPython3.13.2 AMD64/64 bit + local fixed NTFS.
TRUSTED_LOCAL_WORKSPACE_V010 assumes user control without hostile concurrent changes.
No Linux/general Windows/network/removable-volume/other-Python support is claimed.
atomic_snapshot=NOT_ESTABLISHED; STRICT_NATIVE_BACKEND_HOLD remains.

File matching does not authenticate historical execution or provenance. Material
availability does not establish independent reproduction or scientific correctness.
The private pilot remains OPA_REAL_DATA_PILOT_01_PASS_WITH_EVIDENCE_LIMITS.
Historical evidence gap G01: two past Checklist consumer calls lack individual
function-level receipts; later calls cannot authenticate the past.

MD5 comparison, structured execution correlation, complex aggregation, reproduction
certification and Linux product support remain deferred. No scientific formats
are interpreted or scripts executed. Local reports/drafts require privacy review.
Source uploads and public distribution are separate maintainer operations.
Repository visibility and available Release assets do not change the software's
scientific evidence limits.
