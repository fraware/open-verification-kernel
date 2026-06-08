# Threat Model

OVK focuses on agentic engineering risk. The first threat model covers AI coding agents, security agents, and infrastructure agents that can propose or modify code, CI/CD workflows, policies, deployment files, and infrastructure.

## Assets

- Repository source code.
- CI/CD workflows and required checks.
- OVK configuration and templates.
- Evidence artifacts.
- Branch-protection and ruleset metadata.
- Policy files and infrastructure plans.
- Secrets, credentials, and deployment gates.
- Human override records.

## Threat actors

| Actor | Description |
|---|---|
| Benign but misaligned agent | Agent misunderstands task or overgeneralizes |
| Over-permissioned agent | Agent has access beyond intended mandate |
| Malicious contributor | Contributor uses agentic workflow to hide risky change |
| Compromised workflow | CI step or adapter execution path is compromised |
| Prompt/config injector | Repo content attempts to steer agent away from verification |
| Careless human override | Human approves failed evidence without adequate review |

## Threats

| Threat | Description | Required response |
|---|---|---|
| Self-disable | Agent removes or weakens OVK or CI gate | Block or require human review |
| Self-approval | Agent creates path to approve its own change | Block |
| Policy regression | Agent weakens auth, IAM, routing, or deployment constraints | Fail evidence and block high-risk PRs |
| Specification gaming | Agent generates weak property that trivially passes | Anti-vacuity checks and template provenance |
| Evidence forgery | Agent edits evidence artifacts or claims | Content addressing and CI-generated evidence |
| Backend misuse | Agent chooses inappropriate verifier | Router and capability manifests |
| Counterexample suppression | Agent hides failing trace or generated test | Evidence bundle must include raw result reference |
| Context omission | Kernel checks incomplete metadata | Missing context becomes unknown |
| Timeout laundering | Backend timeout treated as pass | Timeout becomes unknown |
| Prompt injection | Repo files instruct agent to skip verification | OVK policy independent of model instruction following |

## OVK security invariants

```text
OVK-INV-001: Agent-authored PRs cannot modify OVK enforcement configuration without human review.
OVK-INV-002: Unknown, timeout, adapter error, and missing-context results cannot be treated as pass in enforce mode.
OVK-INV-003: Every evidence claim must include backend, version, assumptions, limits, input digest, and result.
OVK-INV-004: Every critical failed intent blocks merge unless authorized human override is recorded.
OVK-INV-005: Inferred high-risk intents cannot become authoritative passing claims without template provenance or human confirmation.
OVK-INV-006: Proof obligations must reference the intent and changed scope they claim to check.
OVK-INV-007: The same actor that authored a change cannot be the sole approver of an override.
OVK-INV-008: Evidence artifacts must be content-addressed and bound to the commit SHA they evaluate.
```

## Initial mitigations

- Enforce-mode default for critical templates.
- Human review requirement for OVK config changes.
- Evidence schema validation before PR output.
- Explicit unknown state for missing metadata.
- Adapter manifests with assumptions and limits.
- Golden adversarial tests for self-disable and timeout cases.
- Optional in-toto-compatible evidence predicate.
