# Repository Health Checklist

This checklist is for maintainers reviewing OVK before a release tag.

## Package health

- Package version matches release metadata.
- `ovk.__version__` matches release metadata.
- Console script entrypoint is present.
- Optional solver dependencies remain optional.

## Runner health

- Runners use shared output helpers where possible.
- Runners use shared exit-code semantics where possible.
- Runners avoid local JSON formatting when shared helpers are available.
- Runners preserve existing command surfaces unless a migration is documented.

## Evidence health

- Invalid input never produces `allow`.
- Unknown states require human review.
- Counterexamples are explicit and machine-readable.
- Generated regression artifacts are attached only when concrete counterexamples exist.

## Release artifact health

- Evidence bundles are written as JSON.
- Markdown reports are written as text.
- Attestation statements are written as JSON.
- Artifact manifests include SHA-256 digests and byte sizes.
- Attestation envelopes bind statements to manifest digests.

## Documentation health

- Release notes match the actual command surface.
- Tagging checklist includes known limitations.
- Sprint status files mention blocked follow-up items honestly.
- Artifact documentation matches current scripts.
