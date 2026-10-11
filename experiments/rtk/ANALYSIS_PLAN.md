# RTK sealed evaluation analysis plan

Status: pre-result specification.

## Primary safety estimand

Let D* be the resolved oracle verdict and D-hat the RTK verdict.

False reuse rate:

FR = P(D-hat = VALID | D* != VALID)

computed over resolved cases for which the oracle verdict is INVALID or REVALIDATION_REQUIRED.

The primary point estimate is the pooled case ratio. Uncertainty is computed by transition-level bootstrap or an exact transition-level procedure chosen before execution. Resampling individual claims as independent observations is prohibited for the primary interval.

## Primary efficiency estimand

Unnecessary revalidation rate:

UR = P(D-hat = REVALIDATION_REQUIRED | D* = VALID).

Use the same transition-level uncertainty principle as the primary safety estimand.

## Secondary metrics

Report:
- four-way verdict confusion matrix including UNRESOLVED
- three-way accuracy over resolved oracle labels
- VALID precision
- VALID recall
- REVALIDATION_REQUIRED precision and recall
- transition-level exact-match rate
- repair sufficiency rate on oracle REVALIDATION_REQUIRED cases
- repair cost regret under the frozen repair cost model
- unresolved rate
- operational failure rate

## Transition aggregation

Each transition contributes one cluster to uncertainty calculations. Where a transition contains multiple cases, case outcomes may be summarized within transition and then aggregated across transitions.

Report the distribution of cases per transition and repository.

## Repositories

Report metrics separately by source repository in addition to the pooled estimate. Repository-stratified results are secondary unless the freeze declares a repository-specific primary estimand.

## Oracle uncertainty

UNRESOLVED oracle cases are included in the confusion matrix and unresolved-rate reporting. They are excluded from resolved-label estimands by definition.

If adjudicator disagreement is available, report raw agreement and adjudication rate descriptively.

## Repair analysis

A repair is sufficient only if the frozen oracle validation condition passes after applying the repair under the declared evaluation procedure.

Cost regret is:

predicted_repair_cost - minimum_acceptable_oracle_repair_cost.

Negative regret indicates the oracle equivalence set or cost model is inconsistent and must be investigated rather than clipped silently.

## Baseline comparison

For each frozen baseline, report the same primary and secondary metrics under the same cases and oracle.

Pairwise differences from RTK must use transition-paired resampling or another predeclared paired procedure.

## Missing and failed executions

Tool crashes, parse failures, missing outputs, or invalid output schemas are operational failures. They must not be mapped to VALID.

The freeze must declare the deterministic mapping from each failure category to the evaluation record before execution.

## Multiple analyses

Primary inference is limited to FR and UR. Other metrics are secondary. Exploratory analyses created after unblinding must be labeled exploratory and must not be presented as preregistered findings.
