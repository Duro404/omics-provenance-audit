# Privacy and reports

Default `public` hides original IDs, names, paths, free labels, raw errors, file
payloads and scientific digests. References use consistent aliases. Hidden fields
are null with redaction metadata. Companion hashes bind report bytes only.

`local` retains allowed raw IDs, relative names, sizes/digests and declaration
fields in controlled JSON mappings. It does not generally expose raw errors,
absolute roots, external URI text or payloads. TSV/Markdown keep safe display rules.
Checklist local text may contain declared step names and relative paths.

Counts, relation topology, status patterns, report sizes and report hashes can still
identify projects. Public does not mean anonymous. Review before sharing.
Local reports and exported Manifest drafts are sensitive material, not public assets.

## Checklist

`checklist.json`, `checklist_details.tsv`, `checklist.md` and optional
`manifest_draft.json` use `CHECKLIST_COMMIT_V1`.
The existing API `omics_provenance_audit.product.checklist_report.verify_checklist_bundle(out)`
checks strict JSON, exact companion names, bytes/SHA256 and draft structure/mapping.
The Quick Start supplies a wrapper. There is no `checklist verify` CLI.
Audit `verify` is not a substitute.

`SATISFIED` only counts files. A committed package can describe gaps.
Read `covers_all_rules`, omissions and rule-to-record mapping. A draft can be a
qualified subset or absent when no files qualify. It is a current observation,
not a historical provenance certificate.

## Audit

`audit.json`, `audit_details.tsv` and `audit.md` use one projected fact model.
`verify --out` reads only the existing report package, checking strict JSON,
completion booleans, exact companion names and sizes/SHA256.
A JSON success flag alone is insufficient. Complete packages can accompany exit 2/3.

Source/run edges and adoption scopes are declarations. Evidence can be inventoried
for current existence/readability/integrity without its claims being parsed or authenticated.
`NOT_VERIFIED` differs from a definite `MISMATCH`.
No check establishes original execution, report authorship, scientific validity or
independent reproduction. The software never automatically uploads or publishes.

Software license: [MIT](../LICENSE). Licensing software does not authorize disclosure of private inputs or reports.
