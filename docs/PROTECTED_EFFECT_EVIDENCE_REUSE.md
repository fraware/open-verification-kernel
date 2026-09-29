# Protected Effect Evidence Reuse v1

Protected Effect Integrity evaluations can be projected into ordinary sealed
VerificationEvidence records and reused across repository revisions only under a
strict semantic/provenance identity.

## Evidence status

Protected Effect evidence is shadow / non-controlling in v1.

A PASS claim therefore records:

    backend_claim.required = false
    decision_state = needs_review
    merge_recommendation = require_human_review
    controlling_finding_ids = []

The evidence can inform calibration and incremental verification without
silently granting merge authority.

## Semantic identity

Cross-revision reuse does not key on commit SHA. It keys on:

- repository;
- protected-effect ID;
- canonical protected-effect semantic-slice digest.

The semantic slice includes the paths, guards, bindings, contract uses and
versions, resource terms, effects, principals, conditions, extraction coverage,
and assumptions supporting that protected effect.

A new commit with an identical slice may reuse prior evidence. Any change to the
slice produces a cache miss.

## Execution identity

Reusable evidence binds two related provenance layers.

The pre-execution runtime fingerprint contains:

- environment digest;
- tool digest;
- worker image digest;
- native-execution flag.

The sealed execution fingerprint adds the exact resource-binding checker
identities, checker versions, engine names, and engine tool versions actually
observed during evaluation.

The binding-checker list is derived from the evaluation and compared against the
declared execution record before evidence is sealed. A caller cannot label a Z3
evaluation as a purely structural check.

During reuse, cache lookup uses only the runtime identity known before execution.
After retrieval, OVK validates the stored observed checker list against the
currently installed checker version and, for Z3 evidence, the current Z3 version.

## Reuse eligibility

A prior PASS is reusable only if all of the following hold:

1. the evidence schema is supported;
2. the integrity envelope is complete;
3. the evidence digest verifies;
4. the evidence signature verifies; signature presence is required by the default reuse policy;
5. the evidence digest is not revoked;
6. the evidence is within the configured age horizon;
7. repository identity matches;
8. protected-effect identity matches;
9. semantic-slice digest matches;
10. policy digest matches;
11. Protected Effect checker ID/version match;
12. the claim is a single shadow PASS with the expected guarantee type;
13. the prior decision is non-controlling;
14. the pre-execution runtime fingerprint matches exactly;
15. the stored observed checker engines remain compatible with the current checker/tool versions.

Any failed condition makes reuse ineligible.

The default reuse policy requires a signature. A trusted local deployment may
explicitly set require_signature=false when the cache itself is inside an
authenticated trusted boundary. This opt-out is never implicit.

## Hardened cache

Protected Effect evidence uses the existing HardenedResultCache under the new
semantic-evidence namespace.

The cross-revision cache key contains:

- repository, without head SHA;
- protected-effect ID;
- semantic-slice digest;
- policy digest;
- checker ID/version;
- guarantee type;
- environment digest;
- tool digest;
- worker image digest;
- runtime-fingerprint digest.

HardenedResultCache still validates the key-components digest and payload digest
on every read and applies its TTL.

## Reissuance

A cache hit does not rewrite the old evidence subject.

Instead OVK creates a new sealed evidence record for the current head revision.
The new record references:

    prior_evidence_digest
    strict reuse decision
    current semantic-slice digest
    current execution fingerprint

The reused record remains shadow / non-controlling.

This preserves an auditable chain:

    original verification
        -> sealed prior evidence
        -> strict reuse validation
        -> sealed current-head reuse evidence

## Current boundary

This layer does not yet promote Protected Effect evidence into a controlling
release gate. Promotion requires calibration against protected holdouts and an
explicit policy change.

The strict reuse mechanism is implemented first so future controlling use does
not need a weaker cache model.
