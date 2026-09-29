# Incremental Protected Effect Execution v1

This layer turns incremental semantic planning and strict Protected Effect
evidence reuse into an executable workflow.

Its governing rule is simple:

    cache reuse may reduce verification work
    cache reuse may never reduce assurance coverage

## Execution algorithm

Given base and head Assurance IR:

1. build or validate an IncrementalAssurancePlan;
2. place all plan.reverify_effects in the fresh-verification set;
3. attempt authenticated evidence reuse only for semantic_reuse_candidates;
4. promote every cache miss or ineligible reuse candidate into the fresh set;
5. evaluate exactly the final fresh set;
6. require the evaluator to return exactly one result for every requested effect;
7. issue sealed shadow evidence for every fresh result;
8. cache only fresh PASS results with reusable provenance;
9. return one fresh or reused evidence record for every head protected effect.

A cache failure is an optimization failure, never a verification result.

## Fail-closed fallback

Fresh verification is forced by any of the following:

- no evidence cache;
- no runtime fingerprint;
- absent cache entry;
- semantic-slice mismatch;
- policy mismatch;
- invalid or missing required signature;
- expired or revoked evidence;
- runtime fingerprint mismatch;
- checker/tool incompatibility;
- corrupted hardened-cache record.

The executor does not downgrade those conditions to UNKNOWN and does not omit
the affected effect. It runs the Protected Effect evaluator again.

## Fresh result integrity

The fresh evaluator is supplied the explicit protected-effect ID set.

Execution aborts if the evaluator:

- omits a requested protected effect;
- returns an unexpected protected effect;
- returns the same protected effect twice;
- returns a result bound to a different Assurance IR.

This prevents an incremental optimization from silently shrinking verification
coverage.

## Cache writes

Fresh FAIL and UNKNOWN results are emitted as evidence but never installed as
reusable PASS entries.

Fresh PASS is cacheable only when:

- a complete execution fingerprint exists;
- the configured reuse policy is satisfied;
- signed evidence is available when the policy requires authentication.

Cache-write errors are recorded in cache_store_failures. They do not erase or
weaken the freshly computed evidence.

## Evidence authority

Both reused and fresh Protected Effect evidence remain shadow /
non-controlling. This execution layer changes verification cost, not release
authority.

## Economic property

For a repository with many protected effects and a small semantic change, the
target behavior is:

    fresh_verification_count
        =
    size(affected semantic surface)
        +
    reuse candidates lacking eligible cache evidence

With a warm authenticated cache, unchanged protected effects perform zero fresh
checker work.

This is the operational form of:

    VerificationWork(change) proportional to AffectedAssuranceSurface(change)
