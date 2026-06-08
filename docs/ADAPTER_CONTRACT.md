# Adapter Contract

OVK adapters connect verification intents to concrete formal methods tools. An adapter may wrap a policy engine, SMT solver, model checker, proof assistant, static analyzer, bounded verifier, or runtime monitor.

Adapters must be explicit about guarantees. No adapter may return a bare boolean.

## Interface

```typescript
interface VerificationAdapter {
  manifest(): CapabilityManifest;

  canHandle(input: {
    intent: VerificationIntent;
    context: RepositoryContext;
    change: Change;
  }): Promise<CapabilityScore>;

  compile(input: {
    intent: VerificationIntent;
    context: RepositoryContext;
    change: Change;
  }): Promise<ProofObligation>;

  run(input: {
    obligation: ProofObligation;
    budget: VerificationBudget;
  }): Promise<RawBackendResult>;

  normalize(input: {
    raw: RawBackendResult;
    obligation: ProofObligation;
  }): Promise<VerificationResult>;

  explain(input: {
    result: VerificationResult;
    context: RepositoryContext;
  }): Promise<HumanExplanation>;

  generateRegressionArtifact?(input: {
    result: VerificationResult;
    context: RepositoryContext;
  }): Promise<GeneratedArtifact[]>;
}
```

## Manifest requirements

Every adapter must ship a capability manifest declaring:

- backend name and version;
- adapter name and version;
- backend class;
- supported domains;
- supported property kinds;
- supported input languages;
- guarantee type;
- meaning of pass;
- meaning of fail;
- meaning of unknown;
- assumptions;
- limits;
- counterexample format;
- timeout behavior.

## Required result statuses

Adapters must normalize results to:

- `pass`
- `fail`
- `unknown`
- `error`
- `skipped`

Timeouts must become `unknown`, not `pass`.

## Adapter examples

### OPA adapter

Use for CI/CD, infrastructure, authorization, data-boundary, and policy checks.

Guarantee type: `policy_evaluation`.

Pass means the structured input satisfies the selected Rego policy under the supplied data model.

Fail means the policy emitted at least one violation.

### Z3 adapter

Use for reachability, satisfiability, symbolic constraints, graph abstractions, and small finite models.

Guarantee type: `smt_satisfiability` or `smt_unsat` depending on query shape.

Pass must state whether the query checked absence of a counterexample or satisfiability of a desired condition.

### Kani adapter

Use for Rust safety and bounded correctness obligations.

Guarantee type: `bounded_model_checking`.

Pass means no violation was found under configured bounds and harness assumptions.

### TLA+ adapter

Use for state-machine, protocol, concurrency, deployment, approval-flow, and workflow properties.

Guarantee type: `model_checking`.

Pass means no violation was found in the configured model. It does not automatically prove arbitrary implementation correctness.

## Forbidden adapter behavior

Adapters must not:

- claim generic verification without guarantee details;
- hide assumptions;
- collapse unknown into pass;
- silently skip checks;
- generate evidence not bound to input digests;
- allow an agent-authored PR to alter adapter trust settings without human review;
- execute arbitrary untrusted commands outside the adapter sandbox.
