# Architecture

## Architectural role

OVK is the thin waist between AI-agent engineering workflows and formal methods backends.

```text
AI agents, CI systems, reviewers, security bots
                    │
                    ▼
        Open Verification Kernel
                    │
                    ▼
OPA, Z3, Kani, TLA+, Dafny, Verus, Lean, Cedar, CBMC, Alloy, runtime monitors
```

OVK should make many formal tools easier to use without flattening their guarantees.

## Primary interfaces

### GitHub Action

The first production surface is a GitHub Action that runs on pull requests, emits status checks, comments with verification evidence, and uploads evidence artifacts.

### CLI

The CLI provides local reproducibility for developers and CI runners.

```bash
ovk init
ovk infer --base origin/main --head HEAD
ovk plan --intents .verification/intents/inferred.json
ovk run --plan .verification/plan.json
ovk explain --evidence .verification/evidence/latest.json
ovk ci --mode enforce
```

### MCP server

The MCP server exposes verification as agent-callable tools.

```text
ovk.extract_intents
ovk.rank_intents
ovk.list_capabilities
ovk.select_backends
ovk.compile_obligation
ovk.run_verification
ovk.explain_result
ovk.generate_regression_artifact
ovk.create_evidence_bundle
ovk.get_merge_recommendation
```

## Internal data flow

```text
Change
  ↓
Repository Context
  ↓
Verification Intents
  ↓
Risk-ranked Plan
  ↓
Backend-specific Obligations
  ↓
Raw Backend Results
  ↓
Normalized Results
  ↓
Evidence Bundle
  ↓
PR Decision / Attestation / Repo Memory
```

## Adapter model

Each backend adapter implements this contract.

```text
manifest() -> CapabilityManifest
can_handle(intent, context, change) -> CapabilityScore
compile(intent, context, change) -> ProofObligation
run(obligation, budget) -> RawBackendResult
normalize(raw, obligation) -> VerificationResult
explain(result, context) -> HumanExplanation
generate_regression_artifact(result, context) -> GeneratedArtifact[] optional
```

No adapter may return a bare boolean. Every result must include guarantee type, assumptions, limits, and status.

## Repository-local memory

OVK-enabled repositories should contain a `.verification/` directory.

```text
.verification/
  config.yml
  invariants.yml
  risk-policy.yml
  intents/
  capabilities/
  templates/
  evidence/
  counterexamples/
  generated_tests/
  memory/
```

This directory becomes machine-readable memory for future agents.

## Backend neutrality

OVK is backend-neutral, but it is not semantics-neutral.

A policy evaluation, bounded model check, SMT satisfiability query, TLA+ trace, Dafny proof, Verus proof, Lean theorem, and runtime monitor are different guarantee classes. OVK records those distinctions in every capability manifest and evidence object.
