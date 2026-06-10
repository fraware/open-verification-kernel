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
| Backend misuse | Agent chooses inappropriate verifier | Backend selection rules and capability manifests |
| Counterexample suppression | Agent hides failing trace or generated test | Evidence bundle must include raw result reference |
| Context omission | OVK checks incomplete metadata | Missing context becomes unknown |
| Timeout laundering | Backend timeout treated as pass | Timeout becomes unknown |
| Prompt injection | Repo files instruct agent to skip verification | OVK policy independent of model instruction following |

## Security rules OVK enforces

1. Agent-authored PRs cannot weaken OVK or CI enforcement without human review.
2. Unknown, timed-out, errored, or incomplete checks cannot count as pass in strict mode.
3. Every evidence claim states which backend ran, its version, assumptions, limits, input digest, and result.
4. Critical failures block merge unless an authorized human override is recorded.
5. High-risk checks inferred at runtime cannot return pass without template provenance or human confirmation.
6. Each proof obligation references the check and code scope it claims to cover.
7. The change author cannot be the sole approver of their own override.
8. Evidence artifacts are content-addressed and bound to the commit SHA they evaluate.

## Initial mitigations

- Strict mode default for critical templates.
- Human review requirement for OVK config changes.
- Evidence schema validation before PR output.
- Explicit unknown state for missing metadata.
- Adapter manifests with assumptions and limits.
- Adversarial regression tests for self-disable and timeout cases.
- Optional in-toto-compatible evidence predicate.
