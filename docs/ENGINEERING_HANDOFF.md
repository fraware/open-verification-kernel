# Engineering Handoff

This document gives the implementation team a concrete starting queue.

## Immediate tasks

### 1. Schema validation

- Add missing schemas for obligation and result.
- Add golden valid and invalid examples under `tests/fixtures/`.
- Extend `ovk validate` to support schema discovery.

### 2. OPA adapter MVP

- Implement `ovk/adapters/opa/`.
- Load `adapters/opa/capability.json`.
- Compile `agent-cannot-disable-own-ci-gate` into a Rego input object.
- Run OPA CLI or library.
- Normalize violations into `VerificationEvidence`.

### 3. Static workflow parser

- Parse GitHub Actions workflow YAML.
- Detect trigger removal, required job removal, permission escalation, and OVK config changes.
- Treat missing metadata as `unknown`.

### 4. GitHub Action runner

- Replace placeholder action with `ovk ci`.
- Generate `ovk-evidence.json`.
- Render PR markdown.
- Map OVK decisions to exit codes.

### 5. Z3 authorization example

- Implement a small route reachability abstraction.
- Encode non-admin admin-route bypass as a satisfiability problem.
- Normalize model output as counterexample evidence.

### 6. MCP server

- Choose official SDK and wire the tool surface in `ovk/mcp_server.py`.
- Expose high-level tools only. Avoid raw arbitrary shell execution.

## First demo milestone

The first demo is successful when:

1. a fixture simulates an agent-authored PR that removes the OVK check;
2. OVK selects the self-protection intent;
3. OPA/static policy returns `fail`;
4. OVK emits evidence with a counterexample;
5. `ovk ci --mode enforce` exits non-zero;
6. the PR comment explains the failure in engineering language.

## Engineering principles

- Keep the core small.
- Put backend-specific logic in adapters.
- Make evidence more conservative than marketing language.
- Prefer explicit `unknown` to misleading `pass`.
- Write tests for every security invariant in `docs/THREAT_MODEL.md`.
