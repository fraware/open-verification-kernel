# Release Artifact Layout

OVK v0.1 release outputs should be reproducible and hash-addressable.

## Default files

```text
ovk-evidence.json
ovk-pr-comment.md
ovk-attestation.json
ovk-artifact-manifest.json
ovk-attestation-envelope.json
```

## Kinds

- `evidence`: normalized OVK evidence bundle.
- `markdown`: pull-request or review report.
- `attestation`: unsigned in-toto-style statement.
- `artifact_manifest`: deterministic file manifest with SHA-256 digests.
- `attestation_envelope`: wrapper that binds the attestation statement to the manifest digest.

## Helper module

```text
ovk.core.release_layout
```

The helper exposes the default artifact layout and a missing-required-artifact check.

## Release rule

A release bundle is incomplete when any required artifact is missing. The manifest should be generated after the evidence, Markdown, and attestation files are written.
