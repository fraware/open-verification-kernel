# RTK concrete refinement boundary

Status: research architecture specification. This document introduces no new runtime
authorization path and makes no empirical performance claim.

## Purpose

The Reliance Transport Kernel (RTK) is the abstract research object:

`T(q0, C0, E0; q1, C1, P) -> (D, K, R)`

where:

- `q0` is the source claim;
- `C0` is the source context;
- `E0` is the source evidence;
- `q1` is the target claim;
- `C1` is the target context;
- `P` is the relying profile / admissibility policy;
- `D` is one of VALID, INVALID, REVALIDATION_REQUIRED, or UNRESOLVED;
- `K` is the retained admissible evidence;
- `R` is the repair obligation.

This document identifies the first concrete OVK implementation family that is
intended to refine that object. It does not assert that the refinement theorem has
already been proved.

## Frozen concrete family

This mapping is written against OVK main commit:

`79370539ca9b26a0a6b01f6ac6ab6923243f40f4`

Relevant source blobs:

| Concrete component | Repository path | Git blob |
|---|---|---|
| durable claim / binding graph | `ovk/core/guarantee_graph.py` | `14b412a25e2634d57e8e01171d210e87b22cb89f` |
| semantic change / reverify partition | `ovk/core/incremental_assurance.py` | `520f72e449bd274d5e501d183abca4b14662e27d` |
| strict cross-revision evidence reuse | `ovk/core/protected_effect_evidence.py` | `d0071768eb9cba99c89ce051df2c454a88689101` |
| current guarantee state | `ovk/core/guarantee_assurance_state.py` | `acac04ee9bd32b1c2240c1b4edbe6470aa817ff4` |
| signed longitudinal state | `ovk/core/guarantee_assurance_ledger.py` | `990f6504e7a49c4fcacb87ec1d855b26b8d5d70f` |

The current scope is the Protected Effect / durable guarantee claim family. This is
not yet a generic implementation for arbitrary proof systems or arbitrary claims.

## Abstract-to-concrete mapping

### Claim

Abstract `q` maps to a durable `GuaranteeSpec` plus its exact definition digest
and revision-specific `GuaranteeBinding`.

Stable claim identity is `guarantee_id`. Claim meaning is not identified by that
string alone. The definition digest and binding are part of the semantic object.

A definition change is a claim change. It must not be silently treated as evidence
transport for the same proposition.

### Context

Abstract `C` currently maps to the tuple containing, at minimum:

- exact repository identity and revision;
- Assurance IR digest;
- guarantee binding;
- protected-effect semantic-slice digest;
- transitive contract dependencies;
- extraction / coverage status;
- policy digest;
- Protected Effect checker identity and version;
- runtime execution fingerprint;
- observed binding-checker identities where applicable.

The context mapping is intentionally larger than a source revision SHA. Revision
identity alone is neither sufficient to license reuse nor sufficient to invalidate
otherwise unchanged support.

### Evidence

Abstract `E` maps to sealed `VerificationEvidence` admitted by the Protected
Effect evidence path.

Admissibility currently checks, among other fields:

- supported schema;
- evidence integrity envelope;
- evidence digest and input digest;
- signature policy;
- subject repository and revision;
- exact protected-effect identity;
- semantic-slice identity;
- policy identity;
- checker identity/version;
- execution fingerprint;
- recorded resource-binding checker compatibility;
- evidence expiry / revocation policy;
- required coverage for PASS.

A semantic-reuse candidate is not evidence by itself.

### Relying profile

Abstract `P` is presently distributed across:

- `GuaranteeAssurancePolicy`;
- `ProtectedEffectReusePolicy`;
- exact policy digest;
- signature requirements;
- evidence-reuse horizon and revocations;
- execution / checker compatibility requirements.

A later generic RTK interface should make this relying profile explicit as one
typed object. This document does not introduce such an object into production code.

## Concrete decision semantics

The existing components support the following refinement interpretation.

### VALID

VALID is justified only if all required claim and context identities continue to
match and prior evidence passes the strict cross-revision reuse predicate.

For the durable guarantee family, this includes:

1. the target guarantee still binds uniquely;
2. the guarantee definition has not changed;
3. its semantic support is unchanged under the typed dependency analysis;
4. the prior evidence is integrity-valid and applicable under the target policy,
   checker, runtime, expiry, and revocation context;
5. any guarantee dependencies needed for final established state are themselves
   established.

Eligible prior evidence may then be reissued as head-bound evidence with explicit
provenance to the prior evidence digest.

### INVALID

Reuse ineligibility does not imply INVALID.

INVALID requires affirmative target-side evidence establishing violation of the
same target claim, such as a fresh target evaluation with a failing native or
authoritative checker result under the frozen claim semantics.

The current reuse predicate is an admissibility predicate, not an invalidity oracle.

### REVALIDATION_REQUIRED

REVALIDATION_REQUIRED is the appropriate transport verdict when prior evidence
does not license continued reliance under the target context and no affirmative
target contradiction has been established.

Concrete causes include:

- semantic support changed;
- dependency impact reaches the protected effect;
- policy/checker/runtime identity changed;
- prior evidence expired or was revoked;
- evidence integrity or applicability cannot be established;
- the guarantee was modified while a successor claim is still meaningful.

The existing `IncrementalAssurancePlan.reverify_effects` supplies a conservative
concrete repair surface.

### UNRESOLVED

UNRESOLVED covers cases where the concrete system cannot construct a defensible
claim/context/evidence relation, including ambiguous or absent bindings and
unsupported / incomplete semantic material.

Fail-closed review states in OVK are compatible with this abstract category.

## Retained evidence K

For VALID transport, `K` is not an unqualified copy of the old PASS.

The concrete retained object consists of:

- the exact prior evidence digest;
- a successful, content-addressed reuse decision under target context;
- a new head-bound evidence record referencing the prior evidence;
- the target guarantee state that admits that reissued record.

This preserves the historical evidence while making current reliance explicit.

For REVALIDATION_REQUIRED, unaffected evidence associated with other independent
guarantees may remain retained; the affected guarantee requires fresh evidence.

## Repair R

The concrete implementation currently supplies:

- exact reason codes for reuse rejection;
- a typed set of protected effects selected for fresh re-verification;
- dependency roots that explain transitive invalidation.

This is a repair plan, not yet a proof of minimal repair.

The research-level claim of minimal repair remains open until there is a formal
sufficiency relation and a cost model under which the returned repair is shown
sufficient and minimal (or its regret is measured against an independently
established optimum).

## Required refinement obligations

The following are the high-value formal obligations.

### R1 — claim identity preservation

If concrete transport emits VALID, the abstract source and target claim mapping
must denote the same claim under the declared abstraction.

### R2 — context abstraction completeness

Every concrete field that can change applicability must either appear in the
abstract context / relying profile or be proved irrelevant to the claimed result.

### R3 — concrete VALID soundness

`ConcreteValid(I, K) -> AbstractValid(alpha(I), alpha(K))`

This is the central concrete-to-abstract bridge.

### R4 — fail-closed applicability

Missing, ambiguous, stale, incompatible, or unverifiable applicability material
must never refine to abstract VALID.

### R5 — retained-evidence provenance

Every concrete retained evidence object must trace to an admitted source evidence
object plus an explicit target-context reuse decision.

### R6 — repair sufficiency

Executing the declared repair under the target context must produce evidence
sufficient to re-establish or refute the target claim.

### R7 — repair minimality or regret

Where a minimal repair set is identifiable, compare the concrete repair against
that set. Otherwise report UNKNOWN for global minimality and measure cost regret
against the best independently known repair.

### R8 — ledger consistency

A signed guarantee-ledger transition marked as reused must correspond to a valid
concrete transport decision for the exact predecessor evidence and target context.

## Current non-claims

This mapping does not establish:

- the concrete-to-abstract theorem;
- semantic adequacy of OVK extraction against arbitrary program behavior;
- external calibration of evidence reuse;
- repair minimality;
- observation/world-model grounding;
- generality to hardware or scientific instrumentation.

Those are research obligations, not documentation gaps.

## Architectural rule

RTK is the abstract theory of evidence applicability under change.

OVK's guarantee graph, incremental invalidation, evidence-reuse decision, guarantee
state, and signed ledger are the first concrete implementation family.

Future domains should implement the abstract contract through typed adapters. They
should not create parallel, incompatible RTK semantics.
