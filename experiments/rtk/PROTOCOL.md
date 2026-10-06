# Reliance Transport Kernel sealed evaluation protocol

Status: methods freeze draft. This document contains no benchmark results.

Companion freeze artifacts (pre-oracle): `RTK_EVAL_FREEZE.json`,
`SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v1.md` (immutable exhausted-procedure record),
`SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v2.md` (adapter-interface methodology amendment),
`SOURCE_REPOSITORY_CANDIDATES.v1.json`,
`schemas/CanonicalDecisionInput.v1.schema.json`.
Oracle labeling remains blocked until expansion finishes and a human reviews
the checkpoint.

## Objective

Evaluate whether claim-conditioned evidence applicability under repository or verifier change correctly identifies evidence that remains valid, evidence that becomes invalid, and evidence that requires revalidation, while limiting unnecessary revalidation.

The experimental unit is a repository transition, not an individual claim. Claim-level observations within one transition are correlated and must not be treated as independent samples for primary uncertainty estimates.

## Data separation

All examples, counterexamples, regression cases, audit probes, and hand-constructed programs previously used to change RTK or adjacent verification implementations are development data and are excluded from the sealed test set.

The sealed set is derived only from historical transitions selected by the frozen census procedure. RTK outputs must not be inspected during census construction, eligibility determination, oracle adjudication, or sealing.

## Source repositories

The initial intended source repositories are CertifyEdge and pcs-core. Exact repository URLs, cutoff SHAs, and cutoff timestamps must be written into RTK_EVAL_FREEZE.json before any case is generated.

No repository may be added after the first oracle label is created.

## Transition census

Enumerate all first-parent transitions within each frozen repository interval unless the analysis plan explicitly specifies another deterministic history traversal. Each census record must contain source and target SHAs, timestamps, changed paths, inclusion status, and an exclusion reason when excluded.

Eligibility must be computable from repository state alone and must not depend on RTK output or oracle verdict.

If the full eligible set is computationally feasible, use every eligible transition. If deterministic subsampling is required, the sampling algorithm, seed, and target size must be frozen before any RTK or oracle output is produced.

## Case derivation

Cases are derived deterministically from an eligible transition using a frozen case generator. Every case must bind:
- transition_id
- source and target repository identities
- claim identity
- evidence snapshot identity
- changed context relevant to applicability
- exact material required by RTK and the oracle

A case generator revision changes the evaluation interface and requires a new freeze.

## Evidence snapshot semantics

Each evidence snapshot is a closed evaluation object:

S_E = (registry, revision, digest, completeness_policy).

The completeness policy states which artifacts are claimed to constitute the evidence available at the source revision. Missing artifacts outside the declared policy are outside the snapshot. Missing artifacts required by the declared policy make the snapshot incomplete and must be represented explicitly.

Evidence snapshots must be content-addressed.

## Verdict space

The frozen verdict set is:
- VALID
- INVALID
- REVALIDATION_REQUIRED
- UNRESOLVED

VALID means the claim remains supported by the source evidence under the target context according to the frozen oracle rules.

INVALID means the source evidence is incompatible with the target context or the claim is no longer supported.

REVALIDATION_REQUIRED means applicability cannot be carried across the transition from the existing evidence alone and a specified additional verification action is required.

UNRESOLVED means the available historical material is insufficient for a defensible oracle verdict under the frozen rules.

UNRESOLVED cases are retained and reported. They are excluded only from metrics whose estimand explicitly conditions on resolved oracle labels.

## Oracle construction

Oracle labeling must be independent of RTK predictions.

Each case receives two independent adjudications when feasible. Disagreements are resolved by a documented adjudication procedure. The oracle record must cite source-native validators, repository artifacts, tests, proofs, or other concrete evidence supporting the verdict.

Annotators must not inspect RTK predictions before adjudication is sealed.

## Repair evaluation

For REVALIDATION_REQUIRED cases, the oracle may specify a set of acceptable repair equivalence classes. A predicted repair is sufficient if it restores the frozen validation condition. Minimality is evaluated against the declared cost model, not string identity.

The cost model must be frozen before RTK outputs are inspected.

## Baselines

Every baseline must have a stable identifier, exact implementation SHA, exact input contract, and output mapping into the frozen verdict space. Baseline names and implementation identities must be recorded in RTK_EVAL_FREEZE.json before execution.

No baseline may be added or modified after unblinding except in a separately labeled exploratory analysis.

## Sealing

Before execution, create a seal manifest covering:
- protocol files
- schemas
- analysis plan
- transition census
- case manifests
- evidence snapshots
- oracle records
- implementation freeze
- baseline registry

The seal records SHA-256 digests and the Git commit containing the sealed material.

Any substantive change after sealing creates a new evaluation version. Corrections must preserve the prior seal and document the reason for the new version.

## Execution

Run the frozen RTK implementation against the sealed cases without modifying code, thresholds, mappings, or case material during execution.

Operational failures are recorded. They are not silently converted to favorable verdicts.

## Reporting

Primary results use only predeclared metrics from ANALYSIS_PLAN.md. Transition-level uncertainty is reported for primary estimates. Claim-level descriptive statistics may be included but must not be presented as independent-sample confidence estimates.

All deviations from this protocol must be enumerated explicitly.
