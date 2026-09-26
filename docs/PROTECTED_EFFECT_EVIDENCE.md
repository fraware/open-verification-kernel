# Protected Effect Evidence v1

Protected Effect Integrity evaluations are converted into ordinary OVK
VerificationEvidence records and sealed with the existing evidence-integrity
machinery.

The evidence remains shadow/non-controlling. Its decision object always records
needs_review / require_human_review and controlling=false. A Protected Effect
PASS never grants merge authority by itself.

## Bound semantics

Each evidence record contains:

- the complete ProtectedEffectIntegrityEvaluation;
- the protected-effect semantic-slice digest;
- the exact Assurance IR subject;
- extraction coverage and assumptions;
- resource-binding sub-checker provenance;
- execution-environment digest;
- policy digest;
- checker/configuration identity;
- evidence digest and optional cryptographic signature.

Resource-binding sub-checkers identify whether an equality result came from:

- deterministic structural/literal evaluation; or
- native Z3, including its runtime version.

## Reuse

Evidence reuse is stricter than semantic reuse planning.

protected_effect_evidence_reuse_decision returns reusable only if:

- schema is ovk.evidence.v3;
- the evidence digest is valid;
- evidence is signed and the signature validates;
- checker ID and version match;
- policy digest matches;
- configuration digest matches;
- prior guarantee type matches;
- prior claim status is PASS;
- semantic-slice digest matches;
- execution-environment digest matches;
- sub-checker provenance is present;
- any Z3 sub-check has an explicit Z3 version.

Every mismatch yields a named rejection reason.

Optional freshness and revocation controls are supported by the reuse context.

If max_age_seconds is supplied, now_iso must also be supplied and evidence older
than the limit is rejected. A caller may also provide revoked_evidence_ids;
matching evidence is rejected immediately. These controls are inputs to the
reuse decision; OVK does not yet provide a networked revocation service or
trusted time source.

## Boundary

A reuse decision says a previously sealed semantic assurance result is eligible
for reuse under exactly matching declared provenance. It does not make the
Protected Effect lane merge-controlling, and it does not extend the property
beyond the source-to-Assurance-IR extraction and resource-binding model that
produced the evidence.
