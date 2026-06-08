# Roadmap

## v0 objective

Create a handoff-ready open-source foundation for a solver-agnostic verification kernel that AI agents and CI systems can use in pull-request workflows.

## Phase 0: Project bootstrap

Deliverables:

- README and license.
- System specification.
- Architecture document.
- Formal specification.
- Adapter contract.
- Threat model.
- Initial JSON schemas.
- Starter Python package.
- GitHub Action scaffold.
- MCP server scaffold.
- Initial templates and examples.

Exit criterion:

- Engineers can clone the repository, understand the design, run schema validation tests, and begin implementing adapters.

## Phase 1: Schemas and validation

Deliverables:

- `verification.intent.schema.json`
- `verification.capability.schema.json`
- `verification.obligation.schema.json`
- `verification.result.schema.json`
- `verification.evidence.schema.json`
- `verification.bundle.schema.json`
- Golden valid and invalid examples.
- CLI command: `ovk validate`.

Exit criterion:

- All core objects validate against schemas.
- CI runs schema validation.

## Phase 2: Local CLI

Deliverables:

- `ovk init`
- `ovk infer`
- `ovk plan`
- `ovk run`
- `ovk explain`
- `ovk ci`

Exit criterion:

- The no-agent-self-disable example can be run locally and returns a block decision when the verification gate is removed.

## Phase 3: OPA adapter and first template

Deliverables:

- OPA capability manifest.
- OPA adapter runner.
- CI self-protection Rego template.
- Regression fixture for gate removal.

Exit criterion:

- OVK blocks a PR-like fixture that removes its own required check.

## Phase 4: GitHub Action

Deliverables:

- `action.yml`
- Docker or composite action wrapper.
- PR markdown renderer.
- Evidence artifact upload path.
- Enforce/advisory modes.

Exit criterion:

- A demo repository PR receives an OVK comment and correct status conclusion.

## Phase 5: Z3 adapter

Deliverables:

- Z3 capability manifest.
- Simple reachability abstraction.
- Authorization-route example.

Exit criterion:

- Non-admin admin-route bypass fixture returns a counterexample.

## Phase 6: Kani and TLA+ adapters

Deliverables:

- Kani manifest and bounded model-check runner.
- TLA+ manifest and TLC runner.
- Rust safety example.
- Workflow approval model example.

Exit criterion:

- OVK shows multiple guarantee classes across policy evaluation, SMT, bounded model checking, and model checking.

## Phase 7: MCP server

Deliverables:

- MCP tool definitions.
- Agent-facing methods for intent extraction, backend selection, verification, explanation, and evidence creation.

Exit criterion:

- Coding agents can call OVK as a verification tool without invoking raw solvers directly.

## Phase 8: Benchmark seed

Deliverables:

- FormalPR-Bench fixture format.
- 20 to 50 seed tasks.
- Scoring harness for intent recall, backend selection, evidence honesty, counterexample usefulness, and merge decision.

Exit criterion:

- Baseline OVK run produces benchmark scores on the seed set.

## One-year target

- Stable schemas.
- 10 to 15 backend adapters.
- 100 reusable property templates.
- Public benchmark for agentic PR verification.
- External contributors from formal methods and agent-building communities.
- First enterprise or OSS pilot repositories.
