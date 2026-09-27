# Guarantee Assurance Ledger

The Guarantee Assurance Ledger makes the current guarantee state a durable,
content-addressed audit object across repository revisions.

It sits above the existing layers:

```
Repository source
    -> Assurance IR
    -> Protected Effect verification
    -> sealed VerificationEvidence
    -> GuaranteeAssuranceSnapshot
    -> signed GuaranteeAssuranceLedgerEntry
```

The ledger does not replace proof evidence. A snapshot stores the evidence digest
admitted for each guarantee. Independent audit of a guarantee still requires the
referenced VerificationEvidence record and its underlying artifacts.

## Entry identity

Each entry contains:

- repository/base/head-bound GuaranteeAssuranceSnapshot;
- canonical snapshot digest;
- monotonic sequence number;
- previous entry digest;
- previous snapshot digest;
- deterministic per-guarantee deltas;
- canonical entry digest;
- HMAC signature.

The entry digest excludes only the digest field itself and the signature. The
signature covers the full unsigned entry including its content digest.

## Revision continuity

A non-genesis entry is admitted only if:

```
current.snapshot.subject_base_sha
    ==
previous.snapshot.subject_head_sha
```

and both predecessor digest links match exactly.

This intentionally creates a strict linear v1 ledger. Skipped repository
revisions require an explicit intermediate assurance snapshot; v1 does not
silently bridge gaps.

## Snapshot validation

Before signing, the ledger validates structural invariants including:

- graph/snapshot repository, head, and Assurance IR identity agree;
- state, binding, dependency, and definition-digest sets agree;
- each state embeds exactly the graph binding for its guarantee;
- an established guarantee has admitted PASS evidence digest and origin;
- an established guarantee has only established dependencies;
- dependency status projections match the referenced guarantee states;
- unbound guarantees carry no evidence.

These checks protect against accidental construction of internally inconsistent
state objects. They do not independently retrieve or re-run referenced evidence.

## Delta semantics

Deltas are descriptive state transitions only:

- `new_guarantee`
- `removed_guarantee`
- `current_established_fresh`
- `current_established_reused`
- `assurance_established`
- `assurance_lost`
- `violation_observed`
- `violation_no_longer_observed`
- `status_unchanged`
- `status_changed`

`violation_no_longer_observed` deliberately avoids claiming that a historical
bug was "fixed" unless the current assurance state independently establishes the
relevant guarantee.

## Authority boundary

Ledger signatures attest that OVK admitted and recorded a particular assurance
state under the stated policy. They do not elevate shadow Protected Effect
evidence into merge authority and do not broaden the semantics of the underlying
typed guarantee.
