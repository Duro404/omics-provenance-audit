# Omics Provenance Audit

Offline, read-only research file checklist and declared provenance audit.

**Version 0.1.0rc2 is a pre-release candidate and is not a stable release.**

| Entry | Checks | Does not establish |
| --- | --- | --- |
| `checklist` | Declared file requirements; optional SHA256 Manifest draft | Workflow execution or correct samples |
| `audit` | Manifest structure, file existence/size/SHA256, declared source/version/adoption conflicts, evidence inventory | Historical authenticity or scientific correctness |
| `verify` | Binding integrity of an existing Audit report package | Authorship, execution or independent reproduction |

## Candidate environment and portable use

Only Windows version API 10.0/build 26200, CPython 3.13.2, AMD64/64 bit,
local fixed NTFS is validated as a bounded developer candidate.
Other Windows, Python, Linux, removable/network-drive and filesystem combinations
are not supported by the candidate entry points.

Runtime uses the Python standard library; no pip installation or network is needed.
Use the versioned distribution bundle supplied with the corresponding
[GitHub Release](https://github.com/Duro404/omics-provenance-audit/releases) when available.
The recommended distribution is the complete ZIP bundle containing the unchanged
RC2 PYZ, examples, documentation and root `LICENSE`. Check the bundle against its
accompanying SHA256 list, extract it into a new local folder, and run the commands
below from that folder. The source repository and GitHub-generated source archives
do not include the portable PYZ.
Keep `omics_provenance_audit-0.1.0rc2.pyz` unchanged beside `LICENSE`.
The original PYZ does not contain LICENSE internally. Any future standalone PYZ
distribution must also make the MIT copyright and permission notice available;
that separate distribution method needs its own signoff.

```powershell
python .\omics_provenance_audit-0.1.0rc2.pyz --version
python .\omics_provenance_audit-0.1.0rc2.pyz --help
python .\omics_provenance_audit-0.1.0rc2.pyz checklist --help
python .\omics_provenance_audit-0.1.0rc2.pyz audit --help
python .\omics_provenance_audit-0.1.0rc2.pyz verify --help
```

## First synthetic example

Follow [QUICKSTART](docs/QUICKSTART.md): default-public Checklist, explicit local
export, Manifest Audit, then Audit `verify`. All example files were newly constructed
under `examples/release_synthetic_v010rc2`. Every output is outside the audited
workspace and must not exist; the Quick Start creates unique output names.

- `--report-profile public` is the default privacy projection.
- `--report-profile local --export-manifest` is required for a Checklist draft,
  with at least one qualifying complete file observation.
- `--format json` selects the Audit Manifest input encoding, not the report format.
- `--workspace-mode TRUSTED_LOCAL_WORKSPACE_V010` selects the explicit trust mode.

Source entry: `python -m omics_provenance_audit.product` with `src` on the import
path. The portable candidate is the tested newcomer route; no source build is required.

## Input formats

Checklist accepts UTF-8 TSV with the five documented columns. Manifest Audit
accepts CSV, TSV or JSON through the frozen parser; JSON uses schema_version 1.0.
`--format` is required for Audit. No FASTQ/BAM/BED content is parsed.

## Reports and privacy

Audit: `audit.json`, `audit_details.tsv`, `audit.md`.
Checklist: `checklist.json`, `checklist_details.tsv`, `checklist.md` and optional
`manifest_draft.json`. Three formats share one projection.

Public reports hide raw IDs, names, paths, free labels and scientific file digests.
Counts and relationships can still identify projects; manually review before sharing.
Local reports/drafts can contain names and full observed digests: **do not publish by default**.
Companion-file SHA256 values bind report bytes only.

Audit `verify --out` is only for Audit packages. The existing Checklist Python
consumer `verify_checklist_bundle` is demonstrated in the Quick Start; there is no
`checklist verify` CLI. See [PRIVACY_AND_REPORTS](docs/PRIVACY_AND_REPORTS.md).

## Status meaning and limits

`PRESENT` observes existence; `SHA256_MATCH` compares current bytes to an expected
digest; `MISMATCH` is a definite difference; `NOT_VERIFIED` means absent, blocked or
unassessed evidence. `SATISFIED` only means a file-count rule was met.
None certifies actual execution, scientific correctness or independent reproduction.

Exit codes: 0 selected checks complete without definite ERROR; 2 definite
input/declaration/integrity problem; 3 blocked/incomplete; 4 tool/argument/submission
failure. Priority: `4 > 2 > 3 > 0`. Complete packages may accompany 2/3.
Exit 0 is not a scientific pass.

Trust mode requires user-controlled local files without hostile concurrent mutation.
Routine path prechecks do not defeat malicious path replacement.
`atomic_snapshot=NOT_ESTABLISHED`; `STRICT_NATIVE_BACKEND_HOLD` remains.
No scientific format parsing, workflow execution, external fetching or automatic uploads.
MD5 comparison, structured execution correlation/aggregation, reproduction certification
and Linux support are deferred. [Scope and limits](docs/SCOPE_AND_LIMITATIONS.md).

## Evidence and licensing

The bounded private pilot is recorded as
`OPA_REAL_DATA_PILOT_01_PASS_WITH_EVIDENCE_LIMITS`. G01 remains: two historical
Checklist consumer calls lack individual function-level receipts; later calls cannot
authenticate those past calls. No private pilot inputs/reports/logs are public examples.
This is not third-party scientific certification.

License: **MIT**, provided in the root [LICENSE](LICENSE).
Copyright (c) 2026 Shen Jianuo

The rights holder has authorized this license; that declaration is not third-party
legal certification. The software runs offline and does not upload reports or
publish releases. Repository visibility and release distribution are separate
maintainer actions.
[RC2 prerelease notes](RELEASE_NOTES_v0.1.0rc2.md).
