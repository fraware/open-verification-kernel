# Incremental contract-composition scaling benchmark

This public development benchmark measures deterministic function-contract
composition work after dependency-aware composition is enabled.

Timing fields are observational only. CI asserts semantic equivalence and work
counts.

## Repository-width experiment

For width N, the workload contains:

- one target chain: TargetRepo -> TargetService -> TargetFacade;
- N-1 independent Repo_i -> Service_i chains.

Only TargetRepo changes its direct return contract.

Expected warm composition work at every tested width:

    changed seeds = 1
    invalidated stable names = 3
    recomposed contracts = 2

The number of reused composed contracts grows with repository width:

    N - 1

Thus increasing unrelated contract graph width from 8 to 256 does not increase
the recomposition count for the same semantic edit.

## Dependency-depth experiment

The workload contains one edited target repository followed by D transparent
wrapper layers plus 32 independent side chains.

Only the target repository contract changes.

Expected work:

    changed seeds = 1
    invalidated stable names = D + 1
    recomposed contracts = D
    reused unrelated composed contracts = 32

This demonstrates the intended dependency-closure behavior: work grows with the
affected forwarding depth, not with unrelated contract count.

## Correctness

Every incremental result is compared against compose_function_contracts() from a
fresh full composition. Exact typed FunctionContract payload equality is
required.

The head source-index path also reuses the base parsed index; each case changes
one source file and asserts one fresh parse.

These workloads are synthetic public development benchmarks, not protected
holdouts.
