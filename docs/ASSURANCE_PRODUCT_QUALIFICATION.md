# Durable Assurance Product Qualification

This qualification layer measures the product behavior of OVK's automatic
durable-assurance path. It is separate from theorem-level unit tests and from
the existing generic pilot metrics.

The qualification runner executes the ordinary `run_check` entrypoint inside
ephemeral Git repositories with real base and head commits, governed guarantee
manifests, governed Protected Effect profiles, authenticated evidence, and the
normal evidence-reuse path.

## Primary metrics

### Unsafe false assurance

An unsafe case is a false-assurance event if every active durable guarantee is
reported `established` at the unsafe head revision.

This is the highest-priority error metric.

    unsafe_false_assurance_rate
      = unsafe false-assurance cases / unsafe cases

An unavailable result does not count as a false assurance. It also does not
count as detection.

### Unsafe detection

    unsafe_detection_rate
      = unsafe cases with an available non-established head state
        / unsafe cases

This distinguishes a real semantic detection from a pipeline that simply became
unavailable.

### Benign open rate

For a human-adjudicated safe case, any head state short of fully established is
an economically relevant open case:

    benign_open_rate
      = safe non-established cases / safe cases

A conservative UNKNOWN may be epistemically correct and still create review
cost. The metric intentionally captures that burden.

### Semantic coverage

    semantic_coverage_rate
      = cases with complete head source-to-Assurance-IR coverage
        / all cases

Unsupported semantics are not removed from the denominator.

### Verification work

The report separately counts fresh and strictly reused head evidence:

    fresh_verification_fraction
      = fresh effects / (fresh + reused effects)

    reuse_rate
      = reused effects / (fresh + reused effects)

These are product-economics metrics. They do not change proof validity.

### Latency

The harness records end-to-end `run_check` latency for every case and reports
P50 and nearest-rank P95.

### Human assurance minutes

Human timing is recorded only when actually observed:

    human_review_minutes_per_pr

Missing timing data remains null. Synthetic fixtures never receive invented
human-review times.

## Evidence classes

Every case is labeled as exactly one of:

- `synthetic`
- `production_shaped_internal`
- `public_upstream_reduction`
- `independent_external`

Only the last category contributes to production-gate eligibility.

The committed v1 suite contains internal production-shaped cases, adversarial
synthetic cases, and the public PraisonAI upstream reduction. It contains zero
independent external cases.

Accordingly, even perfect scores in the committed suite produce:

    qualification.status = internal_signal_only
    production_gate_met = false

## Production qualification policy

The current qualification policy requires all of the following before the
report is eligible to mark the external gate satisfied:

- at least 2 independent external repositories;
- at least 30 human-adjudicated PRs per qualifying repository;
- zero unsafe false-assurance observations;
- 100% unsafe detection on the labeled external unsafe sample;
- at least 90% complete semantic coverage on the external sample;
- at most 5% benign-open rate on the labeled external safe sample.

These are qualification thresholds, not claims that the current system already
meets them in production.

Latency and human-review time remain reported decision variables rather than hard
gate thresholds until enough real pilot data exists to set defensible limits.

## Current committed suite

The v1 suite exercises:

1. an unrelated documentation change with semantic evidence reuse;
2. direct workspace-scope omission;
3. a transitive route -> facade -> service -> repository regression;
4. guarantee self-redefinition plus vulnerable code;
5. extraction-profile self-redefinition plus vulnerable code;
6. a benign change outside the supported control-flow envelope;
7. the public PraisonAI repaired-to-vulnerable regression;
8. the public PraisonAI vulnerable-to-repaired transition;
9. the public LocalChat P0-1 scoped-delete repair reversed to the historical unscoped shape;
10. the public LocalChat P0-1 unscoped-delete shape repaired with request-scope propagation.

The benign unsupported-control-flow case is expected to remain open. It is
included to make the review burden visible rather than optimizing the benchmark
by excluding unsupported safe cases.

The LocalChat cases are reductions of the documented security repair in
jwvanderstam/LocalChat PR #380. They preserve the relevant route-level mechanism:
the same fail-closed workspace guard appears on both sides, while the repaired
database operation carries `scope=get_scope(request)` and the historical shape
does not. They remain public-development evidence, not independent pilot data.

## Running

    python scripts/run_assurance_qualification.py

Default output:

    .verification/assurance-qualification-report.json

The dedicated GitHub Actions workflow runs the same suite with the Z3 solver
installed and uploads the report as the `assurance-product-qualification`
artifact.

Every report records the OVK version, exact source revision, UTC collection
timestamp, Python/platform identity, Z3 version, runner OS, and the fact that
latency measures the end-to-end `run_check` path. Timing numbers are therefore
traceable to the environment that produced them.

## What this report cannot establish

The committed suite does not measure:

- false-assurance incidence over an unbiased population of real PRs;
- real maintainer review time;
- organization-specific semantic coverage;
- deployment reliability across heterogeneous CI fleets;
- willingness to pay;
- integration friction at independent organizations.

Those require independent pilot repositories and human adjudication. The schema
and production gate are designed so those measurements can be added without
changing the metric definitions.
