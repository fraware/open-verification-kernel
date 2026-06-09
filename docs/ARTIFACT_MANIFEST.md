# Artifact Manifest

OVK release hardening starts with deterministic artifact manifests.

## Purpose

An artifact manifest records the files emitted by an OVK run, their kinds, sizes, and SHA-256 digests. This makes evidence outputs easier to archive, compare, and audit.

## Schema version

```text
ovk.artifact_manifest.v1
```

## Manifest shape

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

## Command

```bash
python scripts/write_artifact_manifest.py \
  --artifact ovk-evidence.json \
  --kind evidence \
  --artifact ovk-pr-comment.md \
  --kind markdown \
  --artifact ovk-attestation.json \
  --kind attestation \
  --output ovk-artifact-manifest.json
```

## Determinism

Entries are sorted by kind and path. The manifest does not include wall-clock timestamps.

## Safety rule

The manifest hashes the exact bytes on disk. If an artifact changes, the digest changes.
