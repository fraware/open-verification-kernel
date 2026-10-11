# Predecessor-bound guarantee transport admission

**Status:** research implementation; non-controlling; no independently established
soundness theorem. Implementation: `ovk/core/guarantee_transport.py`.

## Claim boundary

`GuaranteeAssuranceSnapshot.status == established` represents establishment of
the *typed Protected Effect machine assertion* under OVK's extraction/checking
model. `GuaranteeSpec.statement` is descriptive metadata. A snapshot status is
not a formal proof of the entire English declaration.

An additional, different assertion is needed for *guarantee-definition
continuity*: whether a predecessor's durable guarantee and its signed evidence
have been carried into the target context without silently redefining the
guarantee. This is what the new admission function checks.

## Function contract

`evaluate_guarantee_transport_admission(source, target, guarantee_id,
source_spec, target_spec, source_evidence, target_evidence, signature_key)`
returns
`GuaranteeTransportAdmission(eligible, reason_codes, ...)`.

A successful result is conditional on supplied snapshots being authentic
outputs of the OVK evidence-admission machinery. In particular, it checks:

1. Structurally consistent source and target snapshots and the same repository.
2. Exact immediate-predecessor revision linkage.
3. Independently supplied source and target `GuaranteeSpec` declarations
   matching their own snapshot definition digests, typed machine-claim fields,
   descriptive statements, and dependency lists.
4. Identical policy digests and identical full `GuaranteeSpec` definition
   digests for the selected stable guarantee ID.
5. Unique bound Protected Effect identity, identical semantic-support digests,
   and unchanged typed machine claim.
6. Source establishment and target establishment specifically from **reused**
   evidence.
7. Supplied evidence digests matching the source and target snapshot records,
   typed PASS claims, supported schemas, complete integrity envelopes,
   expected checker identity/version, complete signed coverage,
   non-controlling decision scope, and signature/input-digest integrity.
8. Exact semantic-artifact identity and signed direct reuse lineage from the
   target reissue artifact to the supplied predecessor evidence digest.

A rejected admission is **neither an INVALID proof nor a counterexample** to
the target claim. Fresh target verification could independently establish the
target machine assertion.

## Important boundaries

This function does not determine whether a prior formal proof remains
semantically admissible under an independently specified target native verifier.
In particular, it does not prove extraction completeness, checker soundness,
the adequacy of human intent, environmental correspondence, or global repair
minimality. It recomputes both supplied `GuaranteeSpec` digests and cross-checks
the recorded claim fields, yet it does not independently establish that these
declarations were selected from the governing repository manifest at the
specified source and target revisions. Both declaration authority and the
snapshot producer remain external trust assumptions; evidence and snapshot
signatures alone are insufficient to authenticate them. The manifest governance,
extractor, snapshot producer, and signer need distinct validity arguments.

The function checks direct source-to-target evidence lineage. A cache returning
an evidence record reissued from an older ancestor is conservatively rejected
unless the caller supplies a directly linked predecessor. General transitive
evidence ancestry is out of scope.

It does not replay expiry/revocation checks for an arbitrary evaluation time.
The target reuse decision is a signed *historical* admission record. Any future
live authorization must check temporal applicability under a specified
current-time relying policy. The function is not wired to the deployment gate.

**Do not equate `eligible=True` with the abstract RTK theorem
`Applicable(E0, q1, C1, P)`.** That implication is an unproved refinement
obligation depending on the validity of the concrete extractor, verifier,
binding and policy abstractions.

## Positive and negative tests

`tests/test_guarantee_assurance_state.py` exercises direct signed reuse and
conservative rejection on changed guarantee definition or assumptions,
missing signature key, altered evidence digests or reuse lineage, revision
discontinuity, supplied-declaration/snapshot inconsistencies, mismatched signed
semantic artifacts, and conflation of fresh evidence with reused evidence.

The PR guard still evaluates the active base manifest and reviews proposed
changes separately; the new research function preserves that existing
protection. Confirmation on independent repository-native evidence and
paired verifier-cost measurements belong to a prospective experiment
(#177), not to this implementation test.
