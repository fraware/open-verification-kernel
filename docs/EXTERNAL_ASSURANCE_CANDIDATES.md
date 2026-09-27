# External Assurance Candidate Registry

The external candidate registry tracks public security transitions before asking
whether OVK's current Protected Effect semantics can express them.

Its purpose is to make selection bias visible.

A qualification program that reports only cases already known to fit the current
model can have excellent detection metrics and still have poor real-world
semantic coverage. The registry preserves incompatible and incompletely evidenced
cases instead of removing them from the record.

## Triage statuses

### supported_now

The current guarantee family and Protected Effect source profile can represent
the security transition without adding case-specific semantics.

A supported candidate still does not become qualification evidence until it has a
pinned external replay result.

### unsupported_semantics

The security property belongs to the current guarantee family in spirit, while
the source-level mechanism lies outside the present extraction semantics.

Example: direct database ownership lookup followed by a conditional rejection
instead of a modeled dependency guard or supported source-derived contract.

### requires_new_guarantee_family

The candidate concerns a security property that the current
protected_effect_integrity_v1 guarantee does not express.

Such cases stay in the external product-coverage record even though extending the
system requires a separate semantic family.

### insufficient_public_evidence

Public material identifies a candidate vulnerability, but there is no defensible
pinned base/head transition or adjudicated repair from which to build a replay.

This status is excluded from the representational-coverage denominator because it
does not yet establish whether the current model could express a repaired
transition.

## Current initial registry

The initial registry deliberately includes incompatible evidence.

### Aegra cross-user run injection

Repository: aegra/aegra

Public fix: PR #337

Pinned transition:
- base d7d80c850010a9c5a3d2be59254c19b9eb0e25dd
- head 9e1fa430b50937177da086bbe26b5787e9b42499

The repair loads ThreadORM by thread_id and conditionally rejects when
existing_thread.user_id differs from user.identity.

This is classified unsupported_semantics under the current
fastapi_dependency_effects_v1 profile. Treating get_current_user as authorization
for the thread resource would be unsound: it establishes caller identity, not
resource ownership.

### Chroma Python cross-tenant IDOR

Repository: chroma-core/chroma

Public issue: #7588

The issue describes a Python FastAPI authorization path in which AuthzResource is
ignored and tenant/database context is discarded. No pinned repaired Python
FastAPI transition is identified in the public issue, so the candidate remains
insufficient_public_evidence.

## Metrics

The summary reports:

- total reviewed candidates;
- semantically evaluable candidates;
- supported candidates;
- unsupported-semantic candidates;
- candidates requiring a new guarantee family;
- candidates lacking enough public evidence;
- candidates already eligible for replay qualification;
- representational coverage rate;
- qualification-ready rate.

Representational coverage is:

    supported_now
    ----------------------------------------------
    supported_now
    + unsupported_semantics
    + requires_new_guarantee_family

This is separate from detection accuracy on supported cases.

## Discipline

Triage is intended to happen before model-specific implementation work on a
candidate.

A candidate must not be changed from unsupported_semantics to supported_now by
declaring a convenient but unsound source-profile mapping. The status changes
only after the general source semantics have been extended and validated as a
reusable capability.

## Second pre-implementation triage round

The second round is frozen in:

    benchmarks/assurance_qualification/external_candidates.round2.v1.json

It was reviewed against OVK revision:

    7f6d38d103625f4d33d8942e4b0b10565a6af3e1

That revision is the head of the protected-effect-local-coverage work. The round
was committed before any source-semantic implementation motivated by these
candidates.

The six candidates deliberately span different mechanisms:

- Apache Airflow backfill authorization/execution parser disagreement;
- Open WebUI request-controlled authorization bypass;
- flyto-core missing FastAPI route-decorator authentication;
- fastapi-users OAuth state/session correlation;
- fastapi-sso OAuth state/session correlation; and
- MLflow job endpoints with a public vulnerability report but no public patched
  transition.

Under the frozen revision, the five semantically classifiable candidates contain
zero supported_now cases:

    supported_now                  0
    unsupported_semantics          3
    requires_new_guarantee_family  2
    insufficient_public_evidence   1

Thus second-round representational coverage is 0 / 5.

This is a negative product result, not a benchmark failure to be edited away.
Any subsequent semantic extension can be evaluated against this frozen starting
point. The round must remain immutable once implementation work starts.

The two OAuth cases expose a separate boundary: their security claims relate an
authorization initiation event, browser/session state, and a later callback.
They require a temporal correspondence guarantee rather than an expansion of
protected_effect_integrity_v1.

The Airflow, Open WebUI, and flyto-core cases remain inside the intended
Protected Effect product scope, while exposing missing source semantics:
interpretation equivalence, trusted-origin/taint-sensitive guard reasoning, and
route-decorator dependency mediation respectively.

