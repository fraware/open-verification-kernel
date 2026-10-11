# RTK oracle identifiability and adjudication contract

Status: **methodological gate / pre-outcome**. This document changes no OVK runtime semantics and reports no empirical performance result.

Parent specifications: [RTK concrete refinement](RTK_CONCRETE_REFINEMENT.md) and [confirmatory protocol](RTK_CONFIRMATORY_EVALUATION.md). This gate is mandatory before the first target-side adjudication in a confirmatory partition.

## 1. The two distinct propositions

Fix a typed claim `q0`, source context `C0`, original source evidence `E0`, target claim `q1`, target context `C1`, and relying policy `P`.

**Target truth:** does an appropriately trusted native mechanism establish or refute `q1` in `C1`? A fresh proof or test is potentially evidence about target truth.

**Historical applicability:** does the *same historical evidence* `E0` still license `q1` under `C1` and `P`? This is the property RTK is intended to predict.

These propositions are different. In particular,

`FreshNativePass(q1, C1) !=> Applicable(E0, q1, C1, P)`.

A new proof of a proposition does not certify the continued admissibility of a prior proof. A passing behavioral test is not a proof of an unbounded behavioral property unless the declared claim and its validation semantics specifically justify that inference.

**Core exclusion:** A target-native PASS that reruns verification with newly produced evidence is **not**, by itself, a VALID historical-reuse oracle label.

## 2. Independent adjudication axes

Record both axes, even when only one is decisive:

- `target_claim_status`: `ESTABLISHED`, `REFUTED`, or `UNKNOWN`. Its authority must be scoped to the exact typed claim and the validator's coverage.
- `historical_evidence_applicability`: `ADMISSIBLE`, `INADMISSIBLE`, or `UNDETERMINED`. This judgment must identify its independent, claim-specific basis and the *exact* historical evidence digest.

A claim-specific admissibility argument can use one of the following pre-frozen oracle families:

1. **Exact certificate replay:** Check the original proof/certificate/transcript against the target statement, target trusted checker and all target premises, without substituting a new certificate. Retain verifier and dependency identities, checked statement digest, assumptions, revocation and policy disposition.
2. **Independently checked semantic continuity:** A separately specified proof or witness shows that the original evidence's support and claim interpretation are preserved under the target context. The continuity predicate must not be defined by the SUT's footprint, semantic-slice digest or reuse verdict.
3. **Direct independent inapplicability witness:** A changed, relevant premise, certificate incompatibility, revoked evidence, or target policy restriction is independently demonstrated. The witness must address historical applicability, not just changed file paths.
4. **Sound target contradiction:** A target-native counterexample or refutation establishes that the exact target claim is false under the declared semantics. This supports `REFUTED` and normally implies historical evidence cannot validly establish the target claim.

Native unit/integration tests are appropriate for bounded behavior claims that they actually exercise. Their successful execution is fresh evidence of that bounded result; it does not imply persistence of an earlier test outcome. Test failures are counterexamples only where their fixture, oracle, and claim meaning warrant that interpretation.

Missing dependencies, timeout, inconclusive checker output, unparsable artifacts or inability to reconstruct the target environment must be recorded as `UNKNOWN`/`UNDETERMINED`, not silently converted to confirmed inapplicability.

## 3. Derivation of the transport label

The transport label is derived from the independently adjudicated axes. It is not assigned by reading the RTK prediction.

| Historical applicability | Target truth | Transport oracle verdict | Interpretation |
|---|---|---|---|
| ADMISSIBLE | ESTABLISHED or UNKNOWN | VALID | Exact old evidence admitted under the target policy and context |
| INADMISSIBLE | ESTABLISHED or UNKNOWN | REVALIDATION_REQUIRED | Old evidence demonstrably fails an applicability condition; target truth can still hold |
| INADMISSIBLE or UNDETERMINED | REFUTED | INVALID | Sound, same-subject target refutation |
| UNDETERMINED | ESTABLISHED or UNKNOWN | UNRESOLVED | A new target PASS or lack of result does not establish historical reuse |
| ADMISSIBLE | REFUTED | UNRESOLVED + adjudication conflict | Mutually inconsistent purported authorities; quarantine and investigate |

The `ADMISSIBLE + UNKNOWN` combination is permitted only if the independent admissibility authority is itself sufficient to establish reliance on the exact typed target claim; in that case the unknown target-truth field means *no separate target-truth run*, not uncertainty about the checked certificate's authority.

A source certificate failing to replay does not automatically mean `INVALID`. Failure can indicate incompatible assumptions, out-of-scope verification, timeout, missing dependencies, or a newly changed—but still true—claim.

`REVALIDATION_REQUIRED` here is a confirmed loss of historical admissibility. Lack of data to determine admissibility is `UNRESOLVED`. The SUT's safe operational response to either may be revalidation, while oracle labels must preserve the distinction.

## 4. Non-circularity and capability controls

For each frozen oracle family, document:

- Which evidence bytes from `E0` it consumes and which target-native observations it independently obtains.
- Why its label is **not algebraically implied** by the SUT's decisive inputs.
- Which theorem or behavioral claim is being judged, including quantifiers and boundary conditions.
- The native checker/test command, pinned dependencies, trust assumptions and completion criteria.
- What constitutes valid certificate *replay*, fresh evidence *regeneration*, failure and inconclusiveness.
- At least one adversarial example on which the SUT and independent oracle could disagree.
- Coverage restrictions. A test of one credential/route must not stand in for a universal authorization theorem.

Independence is causal and semantic, not merely organizational. Running a second implementation of the same footprint heuristic, or committing labels before predictions, does not establish independent validity.

Case exclusion rules and oracle-authority hierarchy must be frozen **before** target outcomes. Conflicted cases remain in the attrition report. Corrections following unblinding constitute exploratory analysis or a new experiment version.

## 5. Mandatory adversarial controls before opening the holdout

Development-only controls must distinguish at least:

1. Irrelevant textual change, exact certificate still accepted (VALID).
2. Changed support with a fresh target proof that succeeds, old certificate inadmissible (REVALIDATION_REQUIRED).
3. Unchanged paths with revoked or expired prior evidence (REVALIDATION_REQUIRED).
4. Policy/checker version shift, absent compatibility proof (UNRESOLVED or REVALIDATION_REQUIRED only with confirmed mismatch).
5. Same-subject target refutation with an authoritative counterexample (INVALID).
6. Fresh target test PASS, historical evidence applicability undetermined (UNRESOLVED).
7. Target checker timeout or missing toolchain (UNRESOLVED).
8. Apparently admissible historical certificate plus independent refutation (UNRESOLVED; authority conflict requiring investigation).
9. Old evidence valid for a weakened or changed claim only; demonstrate the necessary claim-implication direction before VALID.
10. Independent verifier and SUT use different extraction semantics, with a constructible disagreement.

Do not select confirmatory repositories or revise the oracle because of their performance on these controls. Controls are development checks, not holdout observations.

## 6. Metrics, abstentions and dependence

Preserve the historical-transition statistical unit, grouping transitions by repository.

For confirmed resolved labels, report both:

- **False-reuse sensitivity on non-VALID opportunities:** `#(SUT=VALID and oracle in {INVALID, REVALIDATION_REQUIRED}) / #(oracle in {INVALID, REVALIDATION_REQUIRED})`.
- **Invalid-reuse fraction among VALID predictions:** `#(SUT=VALID and oracle in {INVALID, REVALIDATION_REQUIRED}) / #(SUT=VALID with resolved oracle)`.

Report `SUT=VALID, oracle=UNRESOLVED` separately as *unadjudicated reuse*, with count and denominator, not as a verified successful reuse. Include an adverse-case sensitivity analysis that treats every unadjudicated reuse as unsafe. Report oracle-resolution rate, operational exclusions and attrition by repository and claim family.

A one-sided exact binomial bound assumes independent Bernoulli opportunities under the sampled population. Adjacent transitions in a single repository share semantics and errors. Report the nominal bound **with that assumption explicitly stated**; provide repository-cluster summaries and avoid presenting a transition-count bound as a dependence-robust guarantee. Five source repositories do not by themselves supply precise cluster-robust tail inference.

Zero observed false reuse does not establish zero risk. Avoid unqualified `X% safely saved` claims until both oracle validity and measurement coverage are established.

## 7. Protocol-version integrity

Selection v0 has already been closed without qualifying repositories. Selection
v1 has an existing frozen code-search design and discovery snapshot. This
identifiability audit was written **after** those design records. It must not be
misrepresented as part of their original preregistration.

If any v1 oracle-family definition is insufficient to distinguish historical
applicability from fresh target verification, the affected candidates must
remain feasibility/development cases or be excluded under the original frozen
rules. New qualification conditions, adapter semantics or outcome adjudication
rules belong in an explicitly versioned **prospective** protocol (for example,
selection v2). Never rewrite v1 selection/order or retroactively call a new
oracle rule precommitted. Preserve the frozen v1 artifacts and record the
methodological reason for the successor protocol.

## 8. Holdout admission gate

The next confirmatory run is blocked until its signed/versioned protocol includes:

1. Exact historical-evidence and target-claim identity requirements.
2. Independently reviewable oracle implementations with a target-native admissibility basis.
3. A recorded non-circularity witness or argument for each oracle family.
4. Passing development adversarial controls, with no held-out cases used for tuning.
5. A frozen adjudication/abstention rule, repository order, stopping rule, SUT identity, baselines and cost protocol.

This gate is narrower than a proof of general RTK soundness. Passing it authorizes an informative empirical test, not a claim that transport is formally verified or commercially calibrated.
