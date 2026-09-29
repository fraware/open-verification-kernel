# Incremental Assurance Plan v1

OVK partitions protected effects between fresh semantic verification and semantic
reuse candidates across a base/head Assurance IR transition.

## Classification

A head protected effect enters reverify_effects if any of the following holds:

- it is new in head;
- its canonical semantic support slice changed;
- an interprocedural contract dependency affecting it changed.

A protected effect enters semantic_reuse_candidates only when:

- the same protected-effect ID exists in base and head;
- its complete semantic support slice has the same digest;
- no changed contract dependency reaches it.

Removed base effects are tracked separately.

## Semantic slice

The slice digest includes the protected effect and its relevant:

- semantic paths;
- guards;
- resource bindings;
- contract uses;
- consumed function-contract versions;
- resources and symbolic identity/scope/attribute terms;
- effects and principals;
- path conditions;
- extractor identity;
- extraction coverage and assumptions.

Repository revision SHAs are excluded. A commit changing unrelated source therefore
does not invalidate an identical semantic slice by revision identity alone.

Current extraction coverage is global. A change from complete to partial coverage
therefore changes every slice and conservatively removes every reuse candidate.

## Incremental execution

evaluate_incremental_reverification executes only plan.reverify_effects.

The plan records the exact head Assurance IR digest. Supplying a different head IR
fails closed.

The historical evaluate_protected_effect_integrity API still evaluates all
protected effects by default. Its optional protected_effect_ids parameter provides
the subset mechanism and rejects unknown requested IDs.

## What reuse candidate means

semantic_reuse_candidate is not equivalent to reusable backend evidence.

It states only that OVK found no semantic change in the Assurance IR support slice
for that effect and no changed contract dependency reaches it.

Actual evidence reuse must additionally validate execution-plane provenance such
as:

- backend/checker identity and version;
- tool digest;
- worker/environment fingerprint;
- policy digest;
- accepted guarantee type;
- evidence integrity and expiry/revocation rules.

Until that layer is implemented, semantic reuse candidates are planning outputs,
not authorization to carry a prior PASS into a new release.

## Economic objective

The purpose is to drive marginal verification work toward the changed semantic
surface:

    verification_work(change)
        proportional to
    affected_assurance_surface(change)

rather than repository size.

That is a prerequisite for continuously verifying high-volume agent-generated
software changes.
