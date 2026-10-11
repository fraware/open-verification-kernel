# RTK confirmatory evaluation protocol

Status: pre-outcome protocol design. No confirmatory corpus or outcome is claimed
by this document.

## Scientific question

For a previously established typed claim and historical source evidence, does the
frozen concrete transport system correctly determine whether that evidence still
licenses reliance under a later target context?

The experiment is intended to test applicability, not merely internal consistency
between two representations of the same decision rule.

## Independence requirement

The oracle must separately evaluate **target claim truth** and **historical
applicability of the exact source evidence**. A fresh native PASS alone does not
establish that a prior certificate remains applicable. See the mandatory
[oracle identifiability contract](RTK_ORACLE_IDENTIFIABILITY.md).

A sealed prediction sequence is insufficient if the oracle and SUT are functions
of the same decision statistic.

The confirmatory oracle must use target-side information that is not derived from
RTK's applicability decision.

Preferred sources include:

- exact source evidence replayed against a target-revision native verifier;
- target-revision proof / model-checker execution;
- target integration or behavioral tests that independently exercise the same
  typed claim;
- an affirmative same-subject counterexample;
- an independently specified semantic-continuity rule whose inputs do not include
  RTK predictions, footprints, repair suggestions, or rationale codes.

A fresh execution of the same abstraction is not sufficient to test abstraction
adequacy if both paths share all semantically relevant extracted inputs.

## Separation of roles

The experiment has four frozen roles.

1. **SUT** — exact OVK / RTK transport implementation under evaluation.
2. **Source adapter family** — materializes source claim, context, and source
   evidence without target outcome information.
3. **Oracle adapter family** — executes an independent target-side adjudication
   path and never imports SUT applicability output.
4. **Scorer** — joins committed predictions and committed oracle labels only after
   both are sealed.

A repository that requires oracle or source-adapter semantics to be invented after
its target outcomes are inspected becomes development material.

## Repository eligibility

Eligibility must be frozen before candidate selection.

A repository is eligible only when all of the following are established
source-side:

- public, immutable history with exact source / target identities;
- historical changes predate this confirmatory study;
- a stable typed claim identity can be defined without looking at target outcome;
- source evidence exists and can be reconstructed or replayed;
- at least one pre-frozen source adapter family applies;
- at least one pre-frozen, independent target-oracle adapter family applies;
- source and target environments are reconstructable enough to distinguish
  semantic failure from operational failure;
- licensing permits evaluation artifacts to be retained;
- repository selection does not depend on RTK prediction or target label.

Repositories previously used to design or repair the same adapter family are
development repositories for that family.

## Case qualification

A source-side case is frozen before target adjudication with:

- repository identity;
- source and target revisions;
- transition identity;
- typed claim identity;
- source context identity;
- exact source evidence digest;
- source-native acceptance record;
- frozen source adapter family and version;
- frozen oracle adapter family and version;
- SUT input digest;
- predeclared partition.

Target verdict is absent from this object.

## Oracle verdicts

Transport adjudication records two distinct axes: target claim truth
(ESTABLISHED, REFUTED, UNKNOWN) and historical evidence applicability
(ADMISSIBLE, INADMISSIBLE, UNDETERMINED). The oracle must use target-side
information that is not functionally determined by the SUT's decision statistic.

### VALID

The *exact historical* source evidence remains admissible for the typed target
claim under the target context and relying policy. Confirm by independent
certificate replay or independently justified semantic continuity. Fresh target
verification alone does not establish VALID reuse.

### INVALID

An authoritative same-subject target counterexample or refutation establishes
violation of the exact target claim. A certificate replay failure alone does not
establish INVALID.

### REVALIDATION_REQUIRED

Independent target adjudication establishes loss of a historical evidence
applicability condition, without an affirmative target-claim contradiction.
Fresh target evidence may still independently establish the claim.

### UNRESOLVED

Historical admissibility cannot be determined, including a fresh native PASS
without evidence of historical applicability, operational failure, or conflict
between purported authorities. Keep UNRESOLVED cases in attrition and safety
sensitivity analyses. The SUT may revalidate conservatively, but the oracle
must preserve uncertainty.

See [RTK_ORACLE_IDENTIFIABILITY.md](RTK_ORACLE_IDENTIFIABILITY.md) for the
derivation table, conflict handling and mandatory adversarial controls.

## Frozen sequence

The confirmatory sequence is:

1. freeze SUT identity;
2. freeze source adapter families;
3. freeze independent oracle adapter families;
4. freeze repository eligibility rule;
5. freeze candidate-selection algorithm and ordered candidate list;
6. freeze repository cutoffs;
7. materialize complete transition census;
8. qualify source evidence;
9. freeze case generator and primary unit;
10. freeze SUT inputs / mappings;
11. freeze oracle rules;
12. freeze baseline registry and implementations;
13. freeze cost-measurement schema;
14. run the frozen SUT on committed pre-outcome inputs in a clean, isolated environment; 
15. commit raw SUT predictions and cryptographic digests;
16. run the frozen baselines blind to target outcomes in similarly isolated environments;
17. commit all baseline outputs / digests;
18. execute independent target-native adjudication in a separate, reproducible environment;
19. commit oracle outcomes, evidence and digests without altering already-committed predictions;
20. unblind once for scoring.

The ordering above is the **prospective** default, not a retroactive description
of the historical v1 source selection or the N=10 study. If operational constraints
force the oracle to execute before the SUT, its outcome *bytes and interpretable
labels must remain inaccessible* until SUT and baseline commitments are immutable.
Publicly pushing an oracle JSON file before SUT execution is not sufficient
blinding. A precommitted hash-only oracle record must use a privately retained
high-entropy nonce to prevent enumeration of low-entropy labels; release the
nonce and exact bytes only during unblinding. Check the nonce against the
precommitted digest. Distinct clean worktrees, artifact stores, runner identities,
and restricted tool permissions prevent target-oracle runs from influencing SUT
cache state, prompts, or generated inputs.

Once any confirmatory target outcome is accessed during predictor development,
the associated sample moves to the development partition. Freeze and declare
the revised ordering under a successor preregistration if it modifies the
previously frozen study sequence.

Any semantic modification after the relevant freeze creates a new experiment
version.

## Primary unit

The independent historical transition is the primary statistical unit.

Multiple claims may be nested within one transition. Claim-level results are
secondary and must not be treated as independent observations.

For transition-level false reuse, a transition fails if any evaluated claim on
that transition is falsely reused.

## Primary metrics

### False reuse

`FR_nonvalid = #(SUT=VALID and oracle in {INVALID, REVALIDATION_REQUIRED}) / #(oracle in {INVALID, REVALIDATION_REQUIRED})`

This is the primary safety metric on resolved, independently adjudicated
non-VALID transitions. Also report errors among adjudicated VALID predictions:
`#(SUT=VALID and oracle is non-VALID) / #(SUT=VALID with resolved oracle)`.

Predicted VALID on oracle UNRESOLVED is *unadjudicated reuse*. Report it
separately and include a worst-case sensitivity analysis treating such reuse as
unsafe. Do not count it as confirmed safe reuse.

Report raw numerators, denominators, repository stratification, and nominal
one-sided 95% binomial bounds with the independent-Bernoulli assumption stated.
Adjacent transitions in one repository may be correlated; nominal transition-
level bounds are not dependence-robust confidence guarantees.

### Unnecessary revalidation

`UR = P(predicted REVALIDATION_REQUIRED | independently adjudicated oracle = VALID)`

This is the primary efficiency metric.

### Additional metrics

Report separately:

- INVALID discrimination;
- UNRESOLVED rate;
- operational failure rate;
- transition exact match;
- claim-level confusion matrix;
- repair sufficiency;
- repair set minimality where established;
- repair cost regret where a reference repair is known.

## Sample-size interpretation

The historical 20-transition threshold is a feasibility heuristic, not a validity
threshold.

With zero observed failures, an approximate one-sided 95% binomial upper bound is:

- 20 independent opportunities: about 14%;
- 29: below about 10%;
- 59: below about 5%.

The relevant false-reuse denominator consists of resolved non-VALID
transition opportunities. It may be materially smaller than the total corpus.
Transitions from a shared repository may be dependent; report repository-cluster
summaries and distinguish nominal bounds from dependence-robust inference.

## Baselines

Freeze exact implementations before target outcomes.

At minimum:

- revalidate-all;
- exact claim/context identity invalidation;
- provenance / producer identity;
- typed dependency reachability.

Additional baselines are allowed only if frozen before oracle execution.

An LLM critic is exploratory unless model identity, prompt, temperature, tools,
retry policy, and stochastic replication policy are frozen in advance.

## Contamination rules

The following disqualify a case from the confirmatory partition:

- target outcome inspected during SUT development;
- repository-specific adapter semantics changed because of that case;
- case selected because RTK looked favorable or unfavorable;
- oracle consumes RTK prediction, rationale, repair, footprint, or derived failure
  taxonomy;
- baseline added after unblinding and presented as preregistered;
- target label changed to resolve disagreement without a predeclared adjudication
  rule.

Disqualified cases remain useful development evidence.

## Stopping rule

The candidate-selection rule is frozen in advance.

Walking the ordered candidate list stops only under the frozen rule, for example:

- the preregistered minimum independent opportunity target is reached; or
- the list is exhausted.

Do not weaken source-evidence or oracle requirements to reach a sample-size target.

## Pre-outcome admission gate

Before confirmatory target adjudication, satisfy the five requirements in
[RTK_ORACLE_IDENTIFIABILITY.md](RTK_ORACLE_IDENTIFIABILITY.md), including
independent admissibility evidence and development-only adversarial controls.
The mere existence of repository-native passing tests is insufficient to
adjudicate historical proof or evidence reuse.

## Claim discipline

The first successful confirmatory study would support a bounded claim of the form:

> On the sealed claim families, repositories, adapter families, and historical
> transitions evaluated here, the frozen transport system achieved the reported
> false-reuse / unnecessary-revalidation tradeoff under the stated confidence
> bounds.

It would not establish universal evidence transport, universal software
verification, or semantic adequacy outside the evaluated support contracts.
