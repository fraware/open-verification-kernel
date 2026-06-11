# OVK Release Artifacts

Formats and layout for OVK release bundles.

## Release bundle layout

A complete release bundle contains:

```text
ovk-evidence.json
ovk-pr-comment.md
ovk-attestation.json
ovk-artifact-manifest.json
ovk-evidence-quality.json
ovk-provenance.json
ovk-attestation-envelope.json
```

### Artifact kinds

| Kind | File | Description |
|---|---|---|
| `evidence` | `ovk-evidence.json` | Normalized evidence bundle |
| `markdown` | `ovk-pr-comment.md` | Pull-request review summary |
| `attestation` | `ovk-attestation.json` | in-toto-style attestation statement |
| `artifact_manifest` | `ovk-artifact-manifest.json` | SHA-256 digests for all artifacts |
| `evidence_quality` | `ovk-evidence-quality.json` | Evidence quality report |
| `provenance` | `ovk-provenance.json` | SLSA-style provenance statement |
| `attestation_envelope` | `ovk-attestation-envelope.json` | Statement bound to manifest digest |

Helper module: `ovk.core.release_layout`

Generate and verify:

```bash
ovk release-bundle --lane infrastructure --input examples/infrastructure_exposure/input_private_sensitive_resource.json --output-dir ovk-bundle
ovk verify --manifest examples/verification_manifests/full_mvp.json --output-dir ovk-bundle --advisory
ovk validate-outputs ovk-bundle
```

Set `OVK_SIGNING_KEY` for HMAC-SHA256 envelope signing.

## Attestation statement

Schema: in-toto Statement shell with OVK verification predicate — see `schemas/attestation.statement.schema.json`.

Unsigned attestation produced by `bundle_to_statement()`. Validated at write time and by `ovk validate-outputs`.

## Artifact manifest

Schema: `ovk.artifact_manifest.v1` — see `schemas/artifact.manifest.schema.json`.

```json
{
  "schema_version": "ovk.artifact_manifest.v1",
  "artifacts": [
    {
      "path": "ovk-evidence.json",
      "kind": "evidence",
      "sha256": "...",
      "size_bytes": 1234
    }
  ]
}
```

Entries are sorted by kind and path. No wall-clock timestamps. Digests hash exact bytes on disk.

## Attestation envelope

Schema: `ovk.attestation_envelope.v1`

Binds an attestation statement to the artifact manifest digest. Optional HMAC signature when `OVK_SIGNING_KEY` is set.

```json
{
  "schema_version": "ovk.attestation_envelope.v1",
  "statement": {},
  "artifact_manifest": {
    "path": "ovk-artifact-manifest.json",
    "kind": "artifact_manifest",
    "sha256": "..."
  },
  "signature": {
    "algorithm": "hmac-sha256",
    "digest": "..."
  }
}
```

## Provenance

Schema: `ovk.provenance.v1` — see `schemas/provenance.schema.json`.

Records builder identity, bundle digest, input materials, git metadata, and invocation context.

## Evidence quality report

Schema: `ovk.evidence_quality.v1`

Records whether an evidence bundle satisfies OVK quality rules:

- at least one evidence item;
- unique evidence IDs;
- backend claims present;
- merge recommendation present;
- unknown/error/fail claims do not produce `allow`.

```bash
ovk evidence-quality ovk-evidence.json
python scripts/check_evidence_invariants.py ovk-evidence.json
```

Quality reports are included in artifact manifests under kind `evidence_quality`.

## Standard run manifest

For runs that emit evidence, Markdown, and attestation without a full release bundle:

```bash
python scripts/write_standard_run_manifest.py \
  --evidence ovk-evidence.json \
  --markdown ovk-pr-comment.md \
  --attestation ovk-attestation.json \
  --output ovk-artifact-manifest.json
```

Use `--root` for portable relative paths in the manifest.

## Validation

`ovk validate-outputs <directory>` schema-checks evidence, attestation statement, artifact manifest, quality, provenance, and attestation envelope files. Write-time Pydantic validation applies when runners emit evidence bundles. `write_release_bundle()` validates the release layout schema before writing artifacts. Release layout schema coverage and adapter capability manifests are required `ovk release-preflight` checks.

Schema index: [SCHEMA_INDEX.md](SCHEMA_INDEX.md).
