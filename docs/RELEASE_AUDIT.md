# Release audit responses — superseded

This document records the earlier v1.2.0 readiness response and is retained for audit history.

It has been superseded by the deeper code and artifact review completed on 2026-07-22:

- [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md)
- [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md)
- [BACKENDS.md](BACKENDS.md)

Do not use the former test counts, backend-execution descriptions, external-validation status, or release judgment in this file as current release evidence. The current audit found and corrected additional issues involving cache subject binding, package resource portability, CBMC and Cedar claim semantics, verification-policy parsing, evidence-quality enforcement, manifest boundaries, Sigstore identity binding, GitHub Action diff collection, release publication gates, provenance path privacy, and bundle identity invariants.

Badge-only commits tagged `[skip ci]` intentionally skip workflows. They do not invalidate prior green runs on the preceding feature commit. Always trace health claims to the last **non–skip-ci** commit that ran `ci.yml`, and prefer `benchmark_source_sha` for badge/bench provenance. Do not treat badge JSON `verified_source_sha` fields as authoritative unless the release ledger has authorized that SHA.

**Current product positioning** is tracked in [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md) (`1.3.0-rc.1` engineering candidate; signed pin `v1.2.1`). The historical "v1.2.0 release candidate" sentence below is audit history only.
