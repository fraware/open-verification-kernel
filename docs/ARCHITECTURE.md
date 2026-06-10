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

The CLI provides local reproducibility for developers and CI runners. **`ovk check`** is the primary autonomous path: it infers intents from a diff, compiles obligations, routes to backends, and writes standard artifacts (`ovk-evidence.json`, PR comment, attestation, quality report).

```bash
ovk init
ovk check --changed-files pr.patch --advisory
ovk repair-suggest --evidence ovk-evidence.json
ovk ci --metadata <metadata.json> --advisory
ovk verify --manifest examples/verification_manifests/full_mvp.json --advisory
ovk infer --changed-files pr.patch
ovk plan --changed-files changed.txt
ovk release-bundle --lane infrastructure --input <input.json> --output-dir ovk-bundle
ovk validate-outputs ovk-bundle
```

See [STATUS.md](STATUS.md) for the full command surface.

### MCP server

`ovk-mcp` exposes verification as agent-callable tools over stdio JSON-RPC:

```text
ovk.extract_intents
ovk.plan_from_diff
ovk.extract_workflow_yaml
ovk.extract_workflows_from_diff
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

Repair hints and regression artifacts are available via CLI (`ovk repair-suggest`, `ovk generate-test`) until dedicated MCP tools ship.

## Runner flows

### Single-lane

1. Load lane input.
2. Evaluate via `ovk.core.multi_lane.evaluate_lane`.
3. Build bundle with `make_bundle`.
4. Write standard artifacts via `write_standard_run_outputs` or full release bundle via `write_release_bundle`.

### Multi-lane verify

1. Load verification manifest; schema-validate.
2. Evaluate each lane; combine evidence.
3. Write release bundle with material provenance.

### Kernel check (`ovk check`)

1. Ingest changed files or unified diff; optional GitHub event and check metadata.
2. Detect surfaces and candidate intents via planner.
3. Route obligations through `ovk.core.kernel` and `ovk.core.router` (policy from `.verification/config.yml`).
4. Evaluate affected lanes; merge evidence and merge recommendation.
5. Write standard run outputs; enforce exit code in strict mode.

On block, agents call `ovk repair-suggest` (or MCP `ovk_repair_suggest`) for counterexample-derived fix classes. See [AGENT_REPAIR_LOOP.md](AGENT_REPAIR_LOOP.md).

### Planning

1. Ingest changed files (JSON, paths, or unified diff).
2. Detect surfaces and candidate intents.
3. Route to backends; for diffs, reconstruct workflow YAML for CI-secrets inputs.

### GitHub Action

Install OVK → `ovk init` → `ovk check` (default via `use-check: "true"`) or legacy `ovk ci` / `ovk verify` → optional PR comment → upload artifacts.

Details: [INTEGRATION.md](INTEGRATION.md).

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
