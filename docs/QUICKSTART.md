# Quick Start — v0.1.0rc2 prerelease candidate

Use Windows API 10.0/build 26200 + CPython 3.13.2 AMD64 + local fixed NTFS.
Start PowerShell in the supplied candidate folder with the `.pyz`, `docs/` and
`examples/`. `python` must resolve to the validated interpreter.
No installation is required. Use the complete versioned distribution bundle with
the unchanged PYZ and accompanying [MIT LICENSE](../LICENSE); this guide assumes
that extracted layout. The source repository and GitHub-generated source archives
do not include the portable PYZ.

Use the example files directly from the distribution ZIP. A Git checkout that
converts LF to CRLF changes their byte baseline. The supplied Manifest describes
the original ZIP bytes, not a line-ending-converted checkout. The ZIP workflow
does not require changing global Git settings.

## 1. Candidate and unique outputs

```powershell
$ErrorActionPreference = 'Stop'
$opaPackage = (Resolve-Path '.\omics_provenance_audit-0.1.0rc2.pyz').Path
$opaExample = (Resolve-Path '.\examples\release_synthetic_v010rc2').Path
$opaWorkspace = Join-Path $opaExample 'workspace'
$opaChecklist = Join-Path $opaExample 'checklist.tsv'
$opaRun = Join-Path $PWD ('opa_synthetic_run_' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $opaRun) { throw 'Use a new output parent.' }
New-Item -ItemType Directory -Path $opaRun | Out-Null
$opaPublic = Join-Path $opaRun 'checklist_public'
$opaLocal = Join-Path $opaRun 'checklist_local'
$opaAudit = Join-Path $opaRun 'audit'
python $opaPackage --version
if ($LASTEXITCODE -ne 0) { throw 'Version command failed.' }
```

The run is outside `workspace/`; report targets do not exist.
Two required rules cover three ordinary synthetic files.

## 2. Default-public Checklist

```powershell
python $opaPackage checklist --checklist $opaChecklist --root $opaWorkspace `
  --out $opaPublic --workspace-mode TRUSTED_LOCAL_WORKSPACE_V010
if ($LASTEXITCODE -ne 0) { throw 'Synthetic public Checklist did not complete.' }
```

Default is `--report-profile public`. No draft is requested. This mode observes
directory entries and ordinary metadata, without scientific payload hashing for export.

## 3. Explicit local export

```powershell
python $opaPackage checklist --checklist $opaChecklist --root $opaWorkspace `
  --out $opaLocal --workspace-mode TRUSTED_LOCAL_WORKSPACE_V010 `
  --report-profile local --export-manifest
if ($LASTEXITCODE -ne 0) { throw 'Synthetic local export did not complete.' }
$opaDraft = Join-Path $opaLocal 'manifest_draft.json'
if (-not (Test-Path -LiteralPath $opaDraft)) { throw 'No qualifying draft was produced.' }
```

Local + export + at least one qualified complete SHA256 observation are required.
The complete example produces three records. A partial Checklist can export only
the qualified subset: review gaps and `covers_all_rules` before using its draft.

## 4. Audit the draft and verify the Audit package

```powershell
python $opaPackage audit --manifest $opaDraft --format json --root $opaWorkspace `
  --out $opaAudit --workspace-mode TRUSTED_LOCAL_WORKSPACE_V010 --report-profile public
if ($LASTEXITCODE -ne 0) { throw 'Synthetic draft Audit did not complete.' }
python $opaPackage verify --out $opaAudit
if ($LASTEXITCODE -ne 0) { throw 'Audit package integrity check failed.' }
```

`--format json` is the input Manifest encoding. All report formats are generated
together. Matching a freshly observed baseline is not independent historical evidence.

## 5. Verify Checklist reports with the existing consumer

Audit `verify` does not verify Checklist packages. There is no Checklist verify subcommand.
The example includes a small read-only wrapper over the unchanged API:

```powershell
python -I -B -S (Join-Path $opaExample 'verify_checklist_example.py') $opaPackage $opaPublic
if ($LASTEXITCODE -ne 0) { throw 'Public Checklist package integrity check failed.' }
python -I -B -S (Join-Path $opaExample 'verify_checklist_example.py') $opaPackage $opaLocal
if ($LASTEXITCODE -ne 0) { throw 'Local Checklist package integrity check failed.' }
```

It imports the consumer from the supplied candidate and reads reports only.

## 6. Existing Manifest entry and bounded reads

`manifest_minimal.json` independently describes only `inputs/sample_a.txt`.
Use a separate new report directory:

```powershell
$opaMinimalAudit = Join-Path $opaRun 'minimal_audit'
python $opaPackage audit --manifest (Join-Path $opaExample 'manifest_minimal.json') `
  --format json --root $opaWorkspace --out $opaMinimalAudit `
  --workspace-mode TRUSTED_LOCAL_WORKSPACE_V010 --report-profile public `
  --max-file-bytes 1048576 --max-total-bytes 10485760
if ($LASTEXITCODE -ne 0) { throw 'Minimal Manifest Audit did not complete.' }
python $opaPackage verify --out $opaMinimalAudit
if ($LASTEXITCODE -ne 0) { throw 'Minimal Audit package check failed.' }
```

File byte defaults are 10 GiB per file/100 GiB total, not performance claims.
Manifest/runs inputs are each at most 8 MiB. Checklist defaults: 1 MiB, 1000 rows,
20,000 entries, 2048 directories and 10,000 rule matches.
Checklist paths use `/`; filename `*`/`?` only, no recursive globbing.

## Interpretation

Review gaps in `checklist.md` and findings/unassessed dimensions in `audit.md`.
These complete synthetic examples expect 0. Real gaps can correctly produce 2/3
with complete report packages. Public counts can still identify projects.
Do not share local reports/drafts without privacy review. Evidence inventory is not
execution or reproduction authentication.
