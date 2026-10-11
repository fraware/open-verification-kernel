# Methodological audit — RTK Tier-A pilot N=10

Status: **PILOT_N10_STRUCTURAL_CONSISTENCY_ONLY_POST_AUDIT**

This document is an append-only methodological correction to the sealed Tier-A
pilot. It does not alter the historical oracle, prediction, scoring, source-universe,
or implementation-binding objects.

## Audited identities

- audited PR head: `78595e6a17cf591f3202e9e234637ab784f9438a`
- oracle commitment: `ef90e4674aabfc5438e2eac49a4e80dc03cc0275`
- prediction commitment: `62e140e97000ac7a199216240341333267112281`
- scoring commitment: `8346d4c96adc48282fd79032b4f64859d408a4b5`
- evaluated reference implementation: `2c97b59b8b546ac9392a279970a8c25573c30296`

The historical ordering oracle → committed predictions → scoring is preserved.

## Finding

The pilot does not provide an independent empirical estimate of RTK applicability
accuracy.

For every one of the 16 Tier-A cases:

1. `evidence_snapshot.completeness == "COMPLETE"`;
2. the set of `context_footprint.elements` equals the set of
   `evidence_snapshot.artifact_refs[*].path`;
3. the oracle maps an empty/non-empty intersection between evidence artifact paths
   and `transition.changed_paths` to VALID/REVALIDATION_REQUIRED;
4. `rtk.reference_implementation.v0` maps the corresponding empty/non-empty
   intersection between context-footprint paths and `transition.changed_paths`
   to the same two verdicts;
5. the oracle and predictor agree.

Hence, on this corpus, the oracle decision statistic and the reference predictor
decision statistic are extensionally identical. The observed 16/16 agreement is
mechanically implied by the construction once the shared path sets are fixed.

The deterministic reproducer is:

`python experiments/rtk/tools/audit_pilot_n10_circularity.py`

It exits non-zero if any of the conditions above fail.

## Correct interpretation

The pilot establishes a narrower result:

> The frozen CanonicalDecisionInput representation, the path-identity oracle, and
> `rtk.reference_implementation.v0` are internally consistent on the 16 sealed
> Tier-A cases.

It does **not** independently establish that RTK correctly determines whether
historical verification evidence remains applicable under a changed target
context.

Accordingly, the previously reported false-reuse and unnecessary-revalidation
point estimates remain historical scoring outputs, not independent reliability
estimates for the transport hypothesis.

## What remains valid

This audit does not invalidate:

- the recovered source-universe-v0 bytes and provenance;
- the Tier-A/Tier-B source-evidence separation;
- the v1 and v2 expansion records;
- the implementation identity and non-claim regarding the unrecovered Go checker;
- the historical oracle/prediction/scoring commit order;
- the value of the corpus as development, conformance, and representation evidence.

## Consequences

1. The N=10 pilot is permanently classified as structural-consistency evidence.
2. It must not support a generalization, calibration, or independent false-reuse
   reliability claim.
3. Baselines added after this audit are post-hoc exploratory on this corpus.
4. `rtk.reference_implementation.v0` must remain unchanged if reused as the
   frozen SUT for a new confirmatory study.
5. A new confirmatory oracle must contain target-side information capable of
   disagreeing with RTK for reasons independent of RTK's own decision statistic.
6. Repositories or adapter families used to develop the v2 machinery belong to
   development/feasibility evidence, not a pristine confirmatory holdout.

## Requirement for the next confirmatory experiment

The next oracle must answer the substantive question:

> Does the source evidence still license the same typed claim under the target
> revision and relying context?

Preferred adjudication evidence includes target-revision native validator
execution, target proofs/tests/checkers, same-subject counterexamples, or an
independently established semantic-continuity rule. Path change may trigger
investigation; it is not by itself the target truth label.

The next experiment must freeze adapter families, repository eligibility,
candidate selection, source evidence, case generation, CDI mappings, oracle
rules, baselines, and SUT identity before outcome-bearing target adjudication.
