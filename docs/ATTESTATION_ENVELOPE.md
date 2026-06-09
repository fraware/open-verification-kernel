# Attestation Envelope

OVK produces unsigned in-toto-style attestation statements. Sprint 5 adds a lightweight envelope that binds such a statement to an artifact manifest digest.

## Schema version

```text
ovk.attestation_envelope.v1
```

## Shape

```json
{
  "schema_version": "ovk.attestation_envelope.v1",
  "statement": {},
  "artifact_manifest": {
    "path": "ovk-artifact-manifest.json",
    "kind": "artifact_manifest",
    "sha256": "..."
  }
}
```

## Command

```bash
python scripts/write_attestation_envelope.py \
  --statement ovk-attestation.json \
  --manifest ovk-artifact-manifest.json \
  --output ovk-attestation-envelope.json
```

## Safety rule

The envelope hashes the manifest bytes on disk. If the manifest changes, the envelope digest reference becomes stale and must be regenerated.
