# Protected Effect Evidence v1

Protected Effect Integrity results are projected into the ordinary OVK evidence
envelope as sealed, content-addressed, non-controlling evidence.

## Evidence role

The evidence preserves the candidate claim status:

- pass
- fail
- unknown

The merge decision remains:

    decision_state = needs_review
    controlling = false

for every candidate status.

This is intentional. The current FastAPI dependency/effect profile is
executable advisory evidence. It has not yet completed the attested corpus and
external calibration needed for controlling merge decisions.

## Semantic input binding

Each evidence record contains one content-addressed semantic material whose
sha256 is the protected effect's canonical semantic-slice digest.

The slice includes the exact Assurance IR support used by the evaluator:
protected effect, paths, guards, bindings, resources, conditions, contract uses,
contract versions, extractor identity, coverage, and assumptions.

The evidence input digest is then derived by OVK's existing evidence-integrity
machinery from this material.

An evaluation produced from a different Assurance IR digest is rejected.

## Composite checker provenance

Protected Effect Integrity is a composite checker.

The top-level evidence checker is:

    ovk.protected_effect_integrity.v1

Resource-binding sub-checkers are preserved separately.

The current binding evaluator distinguishes:

    ovk.resource_binding.deterministic.v1

for structural/literal reasoning, and:

    ovk.resource_binding.z3.v1

for native SMT execution.

Native Z3 evidence records the Z3 tool version and native_execution=true.

Sub-checker provenance is included both in generated evidence artifacts and in
the evidence configuration digest. A future evidence-reuse predicate can
therefore reject evidence when the solver/checker configuration changes.

## Integrity

Evidence is emitted as ovk.evidence.v3 and sealed through the existing
seal_evidence path.

The envelope binds:

- checker identity/version;
- semantic input digest;
- configuration digest;
- policy digest;
- assumptions and unknowns;
- timestamps;
- evidence digest;
- optional signature.

## Current boundary

This PR does not authorize evidence caching or carry a prior PASS across a new
revision.

The next reuse gate must additionally require:

    semantic slice unchanged
    evidence digest valid
    checker identity/version unchanged
    sub-checker/tool versions unchanged
    configuration digest unchanged
    policy digest unchanged
    accepted guarantee unchanged
    evidence remains within any expiry/revocation policy

Only after those predicates hold may a semantic reuse candidate become a
reusable evidence candidate.
