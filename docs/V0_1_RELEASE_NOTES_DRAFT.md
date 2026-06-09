# OVK v0.1 Release Notes Draft

OVK v0.1 establishes a small, auditable verification kernel for pull-request evidence, agent self-protection checks, authorization obligations, and infrastructure exposure checks.

## Highlights

- Evidence bundle model for normalized verification outputs.
- Markdown rendering for pull-request review.
- Unsigned in-toto-style attestation statements.
- Deterministic artifact manifests for release outputs.
- Attestation envelopes that bind statements to artifact-manifest digests.
- Self-protection lane for agent-authored changes to high-risk verification and workflow files.
- Authorization obligation lane with validated route abstractions, optional Z3 execution, deterministic fallback behavior, and regression artifact generation.
- Infrastructure exposure lane with native input, Terraform-style normalization, Kubernetes-style normalization, graph-style normalization, configurable policy, and regression artifact generation.

## Commands

- `ovk init`
- `ovk ci`
- `ovk auth-obligation`
- `ovk infra-exposure`

## Release artifacts

A complete release-oriented run should produce:

- evidence bundle;
- Markdown report;
- unsigned attestation statement;
- artifact manifest;
- attestation envelope;
- generated regression artifacts when counterexamples exist.

## Optional integrations

- OPA is optional for policy execution.
- Z3 is optional for solver-backed authorization checks.
- Deterministic fallback paths keep core examples usable without optional solver binaries.

## Current limitations

- The infrastructure CLI accepts native OVK infrastructure input; the standalone infrastructure runner supports native, Terraform-style, and Kubernetes-style input.
- Terraform and Kubernetes support is intentionally narrow in v0.1 and should be treated as normalization hooks rather than full parsers.
- Some GitHub workflow edits remain blocked and should be applied manually by repository maintainers when ready.
- Artifact manifest generation is implemented; deeper manifest verification remains a follow-up hardening item.

## Release bar

Do not tag v0.1 until local installation succeeds, tests pass, and release artifacts can be generated from representative self-protection and infrastructure exposure runs.
