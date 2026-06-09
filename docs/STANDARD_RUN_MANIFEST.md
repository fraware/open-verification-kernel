# Standard Run Manifest

Some OVK runners write evidence, Markdown, and attestation files but do not yet write a manifest directly. The standard run manifest writer covers those runs.

## Command

```bash
python scripts/write_standard_run_manifest.py \
  --evidence ovk-auth-evidence.json \
  --markdown ovk-auth-comment.md \
  --attestation ovk-auth-attestation.json \
  --output ovk-auth-artifact-manifest.json
```

## Portable relative paths

Use `--root` when the manifest should contain paths relative to a release-artifact directory.

```bash
python scripts/write_standard_run_manifest.py \
  --evidence dist/ovk-auth-evidence.json \
  --markdown dist/ovk-auth-comment.md \
  --attestation dist/ovk-auth-attestation.json \
  --root dist \
  --output dist/ovk-auth-artifact-manifest.json
```

## Output

The command writes a deterministic artifact manifest with three entries:

- evidence;
- Markdown report;
- unsigned attestation statement.

## Use case

Use this after `scripts/run_authorization_obligation.py`, `ovk auth-obligation`, or any runner that emits the standard three output files without emitting a manifest itself.
