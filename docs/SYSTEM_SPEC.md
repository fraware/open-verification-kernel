# Open Verification Kernel System Specification

## Purpose

Open Verification Kernel (OVK) is a solver-agnostic verification kernel for AI-agent engineering workflows. It receives an engineering change, derives verification intents, selects appropriate formal backends, runs backend-specific obligations, normalizes results, and produces evidence for pull-request decisions.

OVK is not a prover, solver, static analyzer, or policy language. It is the routing and evidence layer that lets existing formal methods tools plug into coding agents and CI/CD workflows.

## Core separation

OVK separates four layers that are often conflated.

| Layer | Object | Meaning |
|---|---|---|
| Engineering | Change | What the agent or developer changed |
| Intent | Verification Intent | What must remain true |
| Backend | Proof Obligation | What a specific tool must check |
| Evidence | Verification Evidence | What was actually established |

The system must never jump directly from a natural-language issue to a prover without preserving these intermediate objects.

## End-to-end flow

```text
1. AI agent or developer opens a pull request.
2. OVK reads the diff, repository metadata, local invariants, and workflow configuration.
3. OVK creates or selects verification intents.
4. OVK ranks intents by risk and confidence.
5. OVK consults backend capability manifests.
6. OVK routes each intent to one or more formal backends.
7. Backends run proof obligations or policy checks.
8. OVK normalizes backend results into evidence.
9. OVK emits a PR comment, status decision, evidence JSON, and optional attestation.
10. If a counterexample exists, the agent can repair the PR and rerun OVK.
```

## Core components

| Component | Responsibility |
|---|---|
| Change Reader | Reads diffs, changed files, PR metadata, branch policy, workflow config, and IaC plans |
| Context Builder | Builds a typed repository context from code, configs, docs, tests, and local memory |
| Intent Engine | Generates or selects verification intents |
| Risk Ranker | Scores intents by severity, affected surface, agent authority, and confidence |
| Capability Registry | Stores backend capability manifests |
| Backend selector | Chooses backend and budget for each intent |
| Adapter Runtime | Runs OPA, Z3, Kani, TLA+, Dafny, Verus, Lean, Cedar, CBMC, Alloy, and others |
| Result Normalizer | Converts backend-specific outputs into common results |
| Counterexample Translator | Converts traces, models, and violations into engineering explanations |
| Evidence Attestor | Emits PR comments, JSON evidence, and in-toto-compatible predicates |

## Required result semantics

All backend results must normalize to one of five outcomes.

| Result | Meaning |
|---|---|
| pass | No violation found under stated semantics, assumptions, and bounds |
| fail | Concrete violation, model, trace, policy violation, or proof failure found |
| unknown | Backend could not decide within budget or lacked sufficient context |
| error | Tool or adapter failed |
| skipped | OVK intentionally skipped the backend and recorded why |

OVK must never treat `unknown`, `error`, or `skipped` as `pass` in strict mode.

## Default merge policy

```text
if any critical intent fails:
    block
elif any critical intent is unknown, error, or skipped:
    require_human_review
elif all required intents pass:
    allow
elif low-risk intents are skipped with justification:
    allow_with_warning
else:
    require_human_review
```

## Design principle

Every agentic engineering action that changes authority, deployment, data flow, security, or control logic should produce a structured answer to four questions.

1. What must remain true?
2. What checked it?
3. Under which assumptions and bounds?
4. What should happen if the check fails?
