# Open Verification Kernel

Open Verification Kernel (OVK) is an open-source, solver-agnostic verification layer for AI-agent engineering workflows.

OVK sits between AI coding agents and existing formal methods tools. It does not replace Lean, Dafny, TLA+, Kani, Verus, Z3, OPA, Cedar, CBMC, Alloy, or other backends. It gives agents and CI systems a common way to ask what must remain true after a change, route that obligation to the right backend, and attach structured evidence to a pull request.

## Core thesis

AI agents are becoming routine participants in software engineering. They open pull requests, edit infrastructure, modify CI, change authorization paths, and make architecture decisions. Those actions need external reasoning loops that are stronger than natural-language self-critique.

OVK provides the missing thin waist:

```text
engineering change
→ verification intent
→ backend-specific obligation
→ formal check
→ normalized evidence
→ pull-request decision
```

The project is solver-agnostic, but never guarantee-agnostic. Every backend must declare what it can check, what assumptions it makes, what a pass means, what a failure means, and when the result is unknown.

## What OVK provides

- Verification Intent IR for engineering obligations.
- Capability Manifest schema for formal tools and analyzers.
- Evidence Bundle schema for pull-request and attestation workflows.
- Backend router for selecting appropriate verification tools.
- Adapter SDK for OPA, Z3, Kani, TLA+, Dafny, Verus, Lean, Cedar, CBMC, Alloy, and others.
- GitHub Action for PR-level verification evidence.
- MCP server so agents can call verification workflows directly.
- Property templates for common agentic engineering risks.
- Counterexample-to-test and counterexample-to-repair workflow.
- Benchmark scaffolding for agent-authored PR verification tasks.

## First wedge

Every agent-authored pull request should carry structured verification evidence before merge.

The initial MVP focuses on five property classes:

1. Agent-authored PRs cannot weaken their own verification gate.
2. Authorization-sensitive changes cannot create admin-route bypasses.
3. Infrastructure changes cannot expose sensitive resources publicly.
4. Workflow or CI changes cannot expose secrets to untrusted contexts.
5. State-machine and deployment changes cannot skip required approval states.

## Repository map

```text
schemas/            JSON schemas for OVK objects
docs/               architecture, formal spec, roadmap, threat model
ovk/                starter Python package for the kernel
adapters/           reference adapter specifications and future code
templates/          reusable verification-intent templates
examples/           end-to-end demo scenarios
.github/workflows/  CI scaffolding
```

## Status

This repository is in project-bootstrap state. The initial commits define the system architecture, formal contracts, starter schemas, and engineering roadmap so implementation work can begin immediately.

## License

Apache-2.0. See `LICENSE`.
