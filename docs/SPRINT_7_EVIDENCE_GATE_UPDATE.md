# Sprint 7 Evidence Gate Update

Sprint 7 starts the evidence quality gate work.

Implemented:

- `ovk.core.evidence_invariants`
- `scripts/check_evidence_invariants.py`
- direct invariant tests
- checker script test
- `docs/EVIDENCE_INVARIANTS.md`
- `ovk.core.evidence_quality`
- `scripts/write_evidence_quality_report.py`
- evidence quality report tests
- `docs/EVIDENCE_QUALITY_REPORT.md`
- standard output helper support for optional quality reports
- infrastructure runner `--quality-output`
- infrastructure runner quality-output test
- manifest inclusion for quality reports under the `evidence_quality` artifact kind

The new gate checks evidence bundles for basic internal consistency before release or CI use. It can also emit an auditable JSON quality report for release archives, expose that artifact directly from the infrastructure runner, and hash-address the report in standard manifests.
