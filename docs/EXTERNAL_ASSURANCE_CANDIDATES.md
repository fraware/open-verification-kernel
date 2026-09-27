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

## Held-out route-mediation cohort

A separate held-out cohort is frozen in:

    benchmarks/assurance_qualification/external_candidates.heldout_route_mediation.v1.json

It was selected after the route-level complete-mediation implementation was
complete and before OVK was run on any selected case. The cohort is bound to
OVK revision:

    af94ae1bac88b15a0db1434727f8401e6922a548

Selection used the following rule:

1. GitHub-reviewed vulnerabilities published in 2026;
2. the affected application uses FastAPI;
3. the vulnerability is missing or bypassed authentication on a protected HTTP
   surface;
4. a public repaired transition can be pinned exactly;
5. use distinct repositories; and
6. exclude repositories or cases already used as OVK development evidence.

The resulting repositories are:

- langflow-ai/langflow
- mlflow/mlflow
- doobidoo/mcp-memory-service

PraisonAI candidates found by the same search are excluded because PraisonAI has
already been used in OVK development evidence.

Pre-replay triage is frozen as:

    supported_now                  1
    unsupported_semantics          2
    requires_new_guarantee_family  0
    insufficient_public_evidence   0

Thus pre-replay representational coverage is 1 / 3.

Langflow is classified supported_now because the repaired protected operation is
directly present in a route handler and the repair adds a direct
`dependencies=[Depends(get_current_active_user)]` route dependency, matching the
bounded static-capability complete-mediation theorem.

MLflow remains unsupported because its repair changes shared permission
middleware and path-to-validator dispatch rather than a modeled route
dependency.

mcp-memory-service remains unsupported because its repair adds parameter-level
read/write dependencies and some protected mutations occur in helper/background
functions. The current static-capability complete-mediation theorem applies only
to direct route-decorator dependencies.

These classifications are fixed before replay. A failed held-out replay must be
reported as a failure of the implementation or its pre-replay triage; it must
not be repaired by editing this cohort.

