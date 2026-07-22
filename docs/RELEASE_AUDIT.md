# Release audit responses — superseded

This document records the earlier v1.2.0 readiness response and is retained for audit history.

It has been superseded by the deeper code and artifact review completed on 2026-07-22:

- [VISION_AUDIT_2026-07-22.md](VISION_AUDIT_2026-07-22.md)
- [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md)
- [BACKENDS.md](BACKENDS.md)

Do not use the former test counts, backend-execution descriptions, external-validation status, or release judgment in this file as current release evidence. The current audit found and corrected additional issues involving cache subject binding, package resource portability, CBMC and Cedar claim semantics, verification-policy parsing, evidence-quality enforcement, manifest boundaries, Sigstore identity binding, GitHub Action diff collection, release publication gates, provenance path privacy, and bundle identity invariants.

The current release remains a **v1.2.0 release candidate** until a non-`[skip ci]` source commit passes all release gates and the immutable Action or wheel is validated in an independent consumer repository.
