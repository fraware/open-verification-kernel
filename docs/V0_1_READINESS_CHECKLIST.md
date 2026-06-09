# OVK v0.1 Readiness Checklist

This checklist defines the minimum bar for tagging an OVK v0.1 release.

## Core package

- Package installs with `pip install -e .`.
- `ovk init` creates the verification directory layout.
- `ovk ci` runs the self-protection path.
- `ovk auth-obligation` runs the authorization path.
- `ovk infra-exposure` runs the native infrastructure exposure path.

## Evidence paths

- Self-protection evidence is generated.
- Authorization evidence is generated.
- Infrastructure exposure evidence is generated.
- Unknown states require human review.
- Invalid input never produces `allow`.

## Release artifacts

- Evidence bundle is written.
- Markdown report is written.
- Unsigned attestation statement is written.
- Artifact manifest is written.
- Attestation envelope is written.
- Generated regression artifacts are written when counterexamples exist.

## Documentation

- Installation guide is current.
- Artifact manifest guide is current.
- Attestation envelope guide is current.
- Release artifact layout guide is current.
- Sprint status documents are current.

## Known v0.1 limitations

- OPA and Z3 are optional backends.
- Infrastructure Terraform and Kubernetes hooks support narrow normalized subsets.
- The first-class infrastructure CLI accepts native infra input; the standalone runner supports multiple formats.
- Some CI workflow edits remain blocked and are documented as manual follow-up items.

## Release rule

Do not tag v0.1 unless the package installs, tests pass locally, and all required release artifacts can be generated from at least one self-protection run and one infrastructure exposure run.
