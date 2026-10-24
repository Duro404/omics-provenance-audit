# Scope and limitations — 0.1.0rc2

Only Windows API 10.0/build 26200 + CPython 3.13.2 AMD64/64 bit + local fixed NTFS
is a validated developer candidate. No general Windows, Linux, network/removable
drive, other-filesystem or other-Python support is claimed. Parser design baselines
do not expand product runtime support.

Checks cover file requirements, declared Manifest structure, file existence/size/SHA256,
declared source/version/adoption relationships and evidence material inventory.
No FASTQ/BAM/BED content parsing, log interpretation, workflow execution, external
URI retrieval, provenance authentication, scientific correctness or independent reproduction.

`TRUSTED_LOCAL_WORKSPACE_V010` assumes user control and no hostile concurrent mutation.
Conservative ordinary-file/link/reparse/hardlink checks are not a strict native backend.
Routine prechecks have time-of-check/time-of-use gaps.
`atomic_snapshot=NOT_ESTABLISHED` and `STRICT_NATIVE_BACKEND_HOLD` remain.
Real restricted ACLs, all link forms, dangerous devices and hostile race scenarios
are not comprehensively validated. Earlier spikes do not establish production support.

MD5 comparison, structured execution correlation, complex aggregation, reproduction
certification, Linux adapters and wider platform/scale tests remain deferred.
Default large-file budgets are not throughput/scale validation.

New isolated output directories and no-replace commits apply in the fixed profile.
Consumers bind report names/sizes/SHA256; they do not authenticate authors,
defeat later malicious tampering or guarantee multi-file power-loss durability.
A completion boolean alone is insufficient.

Private pilot limitation G01 persists: two historical Checklist API calls lack
individual function-level receipts. Later calls cannot establish that history.
Private data/logs are excluded from proposed public examples.
This v0.1.0rc2 prerelease candidate is licensed under [MIT](../LICENSE).
Copyright (c) 2026 Shen Jianuo
Publication remains unperformed and requires separate authorization.
