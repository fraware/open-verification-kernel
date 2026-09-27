# Guarantee Assurance State

The Guarantee Graph defines durable assurance intent and binds it to current
source semantics. This layer attaches current evidence to those bindings.

The distinction is intentional:

```
GuaranteeSpec
    |
    v
GuaranteeBinding
    |
    v
sealed current-head VerificationEvidence
    |
    v
GuaranteeAssuranceState
```

An unchanged semantic slice does not establish a guarantee. It only makes prior
Protected Effect evidence a candidate for the separate strict reuse mechanism.
If that mechanism succeeds, it reissues a new sealed current-head evidence
record. Guarantee assurance consumes the reissued record exactly as it consumes
fresh evidence.

## Machine claim versus display statement

For v1, the machine-interpreted claim is:

```
guarantee_type = protected_effect_integrity_v1
selector = <typed GuaranteeSelector>
```

`GuaranteeSpec.statement` is display metadata. It is never interpreted as a
proved proposition. Changing prose therefore changes the explicit guarantee
definition digest, but no theorem is inferred from that prose.

## Admission requirements

A bound guarantee accepts exactly one evidence record for its current Protected
Effect. The record must bind to:

- the current repository and head revision;
- the exact Protected Effect ID;
- the exact current semantic-slice digest;
- the active policy digest;
- the Protected Effect checker ID and version;
- a complete evidence-integrity envelope;
- a valid evidence digest and input digest;
- a valid signature when required by assurance policy;
- matching embedded Protected Effect evaluation data;
- shadow/non-controlling decision semantics.

Fresh evidence must identify the current Assurance IR directly. Reused evidence
must be a current-head reissue carrying an eligible strict-reuse decision and the
prior evidence digest.

## State lattice

Local evidence yields one of:

- `established`
- `violated`
- `unknown`
- `unbound`
- `invalid_evidence`

Guarantee dependencies are conjunctive. A locally established guarantee whose
declared dependency is not established becomes:

- `dependency_unestablished`

This state is assurance metadata only. It does not alter OVK's merge decision
lattice and does not promote shadow Protected Effect evidence into controlling
merge authority.
