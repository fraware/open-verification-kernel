# Open Verification Kernel

Open Verification Kernel (OVK) is an open-source, solver-agnostic verification layer for AI-agent engineering workflows.

[![FormalPR-Bench](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/fraware/open-verification-kernel/main/docs/benchmarks/leaderboard-badge.json)](docs/benchmarks/latest-leaderboard-summary.json)

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
- MCP server wrappers for agent-facing verification workflows.
- Property templates for common agentic engineering risks.
- Counterexample-to-test and counterexample-to-repair workflow.
- Benchmark scaffolding for agent-authored PR verification tasks.

## MVP property classes

1. Agent-authored PRs cannot weaken their own verification gate.
2. Authorization-sensitive changes cannot create admin-route bypasses.
3. Infrastructure changes cannot expose sensitive resources publicly.
4. Workflow or CI changes cannot expose secrets to untrusted contexts.
5. State-machine and deployment changes cannot skip required approval states.

## Quick start

```bash
# PyPI
pip install open-verification-kernel==1.1.0

# development
pip install -e '.[dev]'
ovk init

# Default PR path: diff-aware multi-lane check
ovk check --changed-files examples/multi_surface/pr_combined.diff --advisory
ovk doctor

# Multi-lane verify + release bundle
ovk verify --manifest examples/verification_manifests/full_mvp.json --output-dir ovk-bundle --advisory
ovk validate-outputs ovk-bundle

# Pilot program (five adoption manifests)
ovk pilot

# FormalPR-Bench leaderboard
ovk bench --leaderboard .verification/formal-pr-bench-leaderboard.json

# Release gate
ovk release-preflight

# MCP agent server (official SDK transport when mcp extra is installed)
ovk-mcp
```

Lane-by-lane commands (`ovk ci`, `ovk auth-obligation`, `ovk infra-exposure`, `ovk ci-secrets`, `ovk deployment-state`) remain available for focused workflows. See [docs/INTEGRATION.md](docs/INTEGRATION.md).

Set `OVK_SIGNING_KEY` to HMAC-sign attestation envelopes in release bundles.

## Repository map

```text
schemas/            JSON schemas for OVK objects
docs/               documentation index, status, integration, specs
ovk/                Python package for the kernel and adapters
adapters/           reference capability manifests and Rego policies
templates/          reusable verification-intent templates
examples/           end-to-end demo scenarios
scripts/            runners, preflight, and release tooling
.github/workflows/  CI and example workflows
```

## Status

OVK **v1.1.0** is a local-runner-first verification kernel with five MVP evidence lanes, ten backend adapters (OPA, Z3, Cedar, TLA+, Kani, Dafny, Verus, Lean, CBMC, Alloy), `ovk check` diff-aware orchestration, FormalPR-Bench v1, optional Sigstore signing, MCP SDK transport, and a hardened GitHub Action. See [docs/STATUS.md](docs/STATUS.md) and [docs/INTEGRATION.md](docs/INTEGRATION.md).

## License

Apache-2.0. See `LICENSE`.
