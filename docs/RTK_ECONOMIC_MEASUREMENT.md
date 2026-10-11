# RTK economic measurement protocol

Status: measurement specification. This document does not claim measured savings.

## Purpose

Correctness alone is insufficient to establish the practical value of evidence
transport.

For every confirmatory transition, measure the resources consumed by:

1. full fresh revalidation;
2. the RTK transport decision;
3. any repair / selective revalidation RTK requests.

The economic question is whether selective transport reduces real verification
cost while preserving the measured safety bound.

## Measurement unit

Measurements are attached to the same immutable transition / claim identities used
by the confirmatory study.

Do not benchmark on a different synthetic workload and transfer the cost result to
the confirmatory corpus.

## Required raw measurements

Where measurable, record separately:

- wall-clock duration;
- CPU time;
- peak resident memory;
- accelerator time;
- CI billed duration;
- external verifier / API charge;
- bytes downloaded;
- bytes read from evidence stores;
- human adjudication / review time;
- retry count;
- cache-hit status;
- operational failures.

Dollar-denominated fields are observations of actual billed cost where available.
Do not convert compute to dollars using an unstated rate.

## Paths

### Full revalidation path

Execute the frozen target-native verification path without RTK reuse.

### RTK transport path

Measure construction of target context, applicability checking, evidence lookup,
reuse decision, and any head-bound evidence reissue.

### Repair path

Where RTK returns REVALIDATION_REQUIRED, execute exactly the frozen repair plan and
record its cost.

If global minimal repair is unknown, do not call the measured repair minimal.

## Derived quantities

For cases where both costs are comparable:

`saved_cost = full_revalidation_cost - (transport_cost + repair_cost)`

and, for a selected scalar cost measure:

`relative_savings = 1 - (transport_cost + repair_cost) / full_revalidation_cost`

Report wall-clock, compute, billed cost, and human effort separately. A single
weighted total is allowed only when its weights are frozen before outcomes.

## Paired execution

Prefer paired measurements on the same target revision and comparable runner
class.

Record order and warm/cold state. Where caching, JIT compilation, or network state
can materially affect cost, randomize or counterbalance run order under a frozen
protocol.

Do not use the same cache state for one arm and a clean state for the other without
reporting the asymmetry.

## Safety first

Economic savings are secondary to false reuse.

A method with lower compute cost and unacceptable false reuse is not a successful
transport system.

Headline savings only on cases covered by the primary safety analysis or clearly
label the economic subset.

## Human effort

Human review is a real cost.

Measure active review time separately from waiting time. Record reviewer role and
whether the review was required by:

- source reconstruction;
- oracle adjudication;
- RTK UNRESOLVED;
- repair approval;
- operational failure.

Research-author time spent constructing the benchmark is not product runtime cost
and must be reported separately.

## Reporting

Report distributions, not only means:

- median;
- interquartile range;
- 90th percentile where sample size permits;
- total resource consumption;
- per-repository stratification.

Also report the fraction of transitions where RTK itself costs more than full
revalidation.

## Non-claims

Until paired measurements exist, the repository must not claim that RTK reduces
verification cost in production.

A normalized repair-count proxy is not a substitute for observed execution cost.
