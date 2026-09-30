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

Frozen registry labels, denominators, and reviewed revisions must not be rewritten
to match later implementation progress. Prefer UNKNOWN over a false PASS when
source evidence is incomplete.

## Related reusable source semantics

Later FastAPI Protected Effect work adds reusable extraction that is relevant to
external candidates without rewriting frozen triage labels:

- bounded handler control-flow graphs (CFG) with iterative dominance;
- guard-to-sink CFG dominance evidence (incomplete coverage stays UNKNOWN);
- value-origin provenance for FastAPI parameters and `request.state` attributes;
- closed-world bypass authority over `request.state` writers, with an explicit
  accounted-path/source-root proof and repository-local import closure;
- bounded flat `and`/`or` short-circuit CFG expansion (nested or opaque BoolOp
  remains UNKNOWN);
- value-origin evidence assembled into FastAPI IR digests when material.

Identifier shape is never sufficient to establish server-controlled provenance.
Bare ALL_CAPS names, conventional config-shaped names, and settings/config
attributes remain unresolved unless a separate source proof binds them. Literal
values remain in the bounded provenance subset.

### Open WebUI development replay

Open WebUI bypass analysis is an explicitly labeled **development replay**.
Reports set `held_out_success=false` and `frozen_registry_mutated=false`. Default
CI uses synthetic fixtures. An optional gated live pin path
(`OVK_OPEN_WEBUI_LIVE_REPLAY=1`) answers the same questions from pinned public
revisions. Development replay is not held-out success and does not change frozen
registry classifications.

The multi-obligation replay (`open_webui_multi_obligation_replay`) evaluates both
pinned revisions and reports each obligation separately (source extraction, CFG
coverage, bypass predicate, value origin, writer closure, caller provenance,
ordinary guard effectiveness, bypass authority, branch-outcome binding,
collective path coverage, principal/effect/resource binding, and final Protected
Effect status). Repair may correctly remain UNKNOWN when caller provenance or
repository closure is incomplete.

### Apache Airflow obligations (parked)

Apache Airflow backfill parser/authorization obligations remain parked. Support
is not claimed. Remaining work includes, without implying current coverage:

- dependency-factory parser term → resource lookup argument;
- resource lookup result → authorization resource / DAG identity;
- authorization helper → fail-closed security meaning;
- handler-side parser ↔ authorization-side parser compatibility;
- compatibility evidence → dependency/framework semantic identity.

No `output_type == "pydantic.NonNegativeInt"` equivalence shortcut.
