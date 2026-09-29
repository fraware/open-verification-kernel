# Durable Guarantee Graph v1

The Guarantee Graph gives assurance claims identity beyond a single pull request.

A `GuaranteeSpec` is explicit repository intent. It has a stable `guarantee_id`,
a human-readable statement, a typed guarantee family, a semantic selector,
assumptions, and optional dependencies on other guarantees. Source extraction
does not create or edit these objects.

For each Assurance IR revision, OVK resolves every selector against current
Protected Effects. Resolution is fail-closed:

- exactly one match -> `bound`;
- zero matches -> `unresolved`;
- multiple matches -> `ambiguous`.

A bound revision records the Protected Effect ID and the canonical semantic-slice
digest already used by incremental Protected Effect verification. The stable
guarantee identity therefore remains separate from revision-specific source
identity.

## Transition semantics

`compare_guarantee_graphs()` classifies only relations supported by the current
machinery:

- `semantic_support_unchanged`;
- `semantic_support_changed`;
- `newly_bound`;
- `binding_lost`;
- `unresolved`;
- `definition_modified`;
- `new_guarantee`;
- `removed_guarantee`.

The v1 graph deliberately does not call a definition or semantic change a
"strengthening" or "weakening". Such a claim requires an implication proof
between the old and new guarantee semantics.

Dependencies form an acyclic graph. A directly changed guarantee marks all
transitive dependents as `dependency_affected`, while preserving each
dependent's own direct transition classification. This avoids conflating
dependency invalidation with a change to the dependent's local semantic slice.

## Trust boundary

This PR establishes durable identity, revision binding, and semantic transition
classification only. It does not elevate shadow Protected Effect evidence to
merge authority.

The next integration layer can attach provenance-sealed VerificationEvidence to
a bound guarantee and distinguish:

`semantic_support_unchanged`

from the stronger claim:

`prior evidence is eligible for current-head reuse under the active policy and runtime fingerprint`.

That second claim must continue to use the strict evidence-reuse predicate.
