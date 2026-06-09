# OVK v0.1 Tagging Checklist

This checklist is for maintainers preparing a v0.1 tag.

## Before tagging

- Confirm the package installs locally.
- Confirm the test suite passes locally.
- Confirm `ovk init` creates the expected verification directories.
- Confirm the release metadata consistency check passes.
- Confirm the command-surface consistency check passes.
- Confirm the local release smoke check passes.
- Confirm the self-protection path writes evidence, Markdown, and attestation outputs.
- Confirm the authorization path writes evidence, Markdown, and attestation outputs.
- Confirm the infrastructure path writes evidence, Markdown, attestation, and artifact-manifest outputs.
- Confirm the standard manifest wrapper works for any runner that emits the standard three files.
- Confirm the attestation envelope writer works from an attestation statement and artifact manifest.

## Documentation to review

- `docs/V0_1_READINESS_CHECKLIST.md`
- `docs/V0_1_RELEASE_NOTES_DRAFT.md`
- `docs/ARTIFACT_MANIFEST.md`
- `docs/ATTESTATION_ENVELOPE.md`
- `docs/RELEASE_ARTIFACT_LAYOUT.md`
- `docs/STANDARD_RUN_MANIFEST.md`
- `docs/RELEASE_INDEX.md`
- `docs/RELEASE_INDEX_ADDENDUM.md`
- `docs/REPOSITORY_HEALTH_CHECKLIST.md`

## Known limitations to keep in release notes

- OPA and Z3 are optional integrations.
- Terraform and Kubernetes support is intentionally narrow.
- Multi-format infrastructure input is supported by the standalone runner.
- The first-class infrastructure CLI currently accepts native OVK infrastructure input.
- Some workflow edits remain manual follow-up items.

## Tagging rule

Only tag v0.1 after the release notes, readiness checklist, artifact documentation, and command-surface checks agree with the actual repository state.
