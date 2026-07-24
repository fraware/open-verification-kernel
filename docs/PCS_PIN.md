# PCS pin for OVK verifier-assurance

OVK pins portable verifier-assurance schemas from `pcs-core`. OVK never forks those schemas under `schemas/` or invents parallel `VerifierProfile` / `VerificationResult` types.

## Gate status

| Gate | Status |
|---|---|
| Development against this pin | **OPEN** |
| Pin identity (merge-to-main for pin purposes) | **SATISFIED** — OVK pins committed pcs-core revision below |
| PyPI / registry publish of pcs-core | **Pending** — optional extra still uses git/path until a versioned release ships |

See [ADR 0001](adr/0001-verifier-assurance-architecture.md) for ownership and ordinary-vs-assurance doctrine.

## Authoritative pin

| Field | Value |
|---|---|
| Repository | `https://github.com/SentinelOps-CI/pcs-core` |
| Commit SHA | `fb588a41a7eab68064429e3c4dfb26c328b9863d` |

**Pinned commit:** `fb588a41a7eab68064429e3c4dfb26c328b9863d`

This SHA is the merge commit of PR #26 on pcs-core (VA schemas + OVK pin-surface + conformance). Prefer the full SHA in CI and install URLs. Pin by SHA, not branch name. PyPI publish is still pending.

**Important:** a sibling `../pcs-core` checkout on a newer `main` tip is **not** automatically valid for OVK. After pcs-core changes that remove or rename pin-surface schemas, `verify_pin_digests()` fails closed. Always install or check out the SHA above (or set `OVK_PCS_CORE_PATH` to that revision). Do not assume “latest pcs-core main” equals this pin.

Install from the pin (until PyPI):

```bash
pip install "pcs-core @ git+https://github.com/SentinelOps-CI/pcs-core@fb588a41a7eab68064429e3c4dfb26c328b9863d#subdirectory=python"
# or sibling editable:
pip install -e "../pcs-core/python"
```

## Pin resolution order

OVK resolves the PCS checkout root in this order:

1. Environment variable `OVK_PCS_CORE_PATH` (preferred for CI)
2. Environment variable `PCS_CORE_PATH`
3. Sibling directory `../pcs-core` relative to the OVK repository root
4. Installed `pcs-core` package (when a published wheel is available)

If no pin root is found, assurance validation and PCS export integrity sealing fail closed.

## Install options

### Path / editable (local development)

```bash
# from open-verification-kernel
pip install -e ".[assurance]"
# or explicitly:
pip install -e "../pcs-core/python"
```

Optional extra `assurance` in `pyproject.toml` documents the git commit pin. Sibling path remains the local fallback.

### Future published pin

When pcs-core releases a version that includes the VA schemas:

```toml
assurance = ["pcs-core==<published-version>"]
```

Update this document with the exact version and schema digests from that release, then record the pin in CI.

## Artifact types (pinned names)

| Artifact type | Schema path under pcs-core |
|---|---|
| `VerifierProfile.v1` | `schemas/VerifierProfile.v1.schema.json` |
| `VerificationResult.v1` | `schemas/VerificationResult.v1.schema.json` |
| `VerifierInvocationRecord.v1` | `schemas/VerifierInvocationRecord.v1.schema.json` |
| `VerifierReplayReport.v1` | `schemas/VerifierReplayReport.v1.schema.json` |
| `VerifierMutationManifest.v1` | `schemas/VerifierMutationManifest.v1.schema.json` |

Shared definitions: `schemas/verifier_assurance.defs.json`.

`VerificationResult.v1` is distinct from `VerificationResult.v0`. Do not auto-upgrade.

Field-shape notes (do not invent local forks):

- Profiles use `verifier_profile_id` and nested `configuration.*_digest`, plus `integrity.{canonicalization_version,artifact_digest}`.
- Results use `decision` (`accept` / `reject` / `indeterminate_*`) and `execution_status`.
- Digests are `sha256:` + 64 lowercase hex. Integrity is nested; top-level `signature_or_digest` is forbidden on VA roots.

## Schema digests at pinned commit

Recorded against pcs-core commit `fb588a41a7eab68064429e3c4dfb26c328b9863d` (2026-07-24). Schema file digests (SHA-256 of file bytes):

| Schema file | Digest |
|---|---|
| `VerifierProfile.v1.schema.json` | `sha256:a657a63eee47a00419f31008f0adee5559e37fdba2544831e8b297c0a2dbe9bd` |
| `VerificationResult.v1.schema.json` | `sha256:146534a7ebf8ee8cdaecaa57258c0ce11224f50aed1a71196bc7b72d2c5b6d17` |
| `VerifierInvocationRecord.v1.schema.json` | `sha256:3ee1384cd5fae5e08b87870100609a9a9b8cf2502b2c4d92de9dedc1f9ffbc3d` |
| `VerifierReplayReport.v1.schema.json` | `sha256:06660ef51c89385869306c2f1c7f1364bec129b783007cc7a8caa4322582bd3b` |
| `VerifierMutationManifest.v1.schema.json` | `sha256:b82952c1d41ddd151cd71440a5a38f7e768c468c3ff4ae11f3a80325d4cb4819` |
| `verifier_assurance.defs.json` | `sha256:c417accb1b4bc08d6e6f0f98e71ee6e7c87a923d19c5054a18841e7e04eadabb` |

Recompute digests after any pcs-core schema change:

```bash
python -c "from pathlib import Path; from hashlib import sha256; root=Path(r'../pcs-core/schemas');
files=['VerifierProfile.v1.schema.json','VerificationResult.v1.schema.json','VerifierInvocationRecord.v1.schema.json','VerifierReplayReport.v1.schema.json','VerifierMutationManifest.v1.schema.json','verifier_assurance.defs.json'];
[print(f, 'sha256:'+sha256((root/f).read_bytes()).hexdigest()) for f in files]"
```

Unknown schema versions and missing pin roots fail closed. Digests are enforced by `ovk.assurance.pin.verify_pin_digests()`.

## Validation commands

From a pcs-core checkout (or installed package with bundled schemas):

```bash
pcs schema check
pcs validate examples/verifier_assurance/VerifierProfile.v1.valid.json
pcs validate examples/verifier_assurance/VerificationResult.v1.valid.json
pcs validate examples/verifier_assurance/VerifierInvocationRecord.v1.valid.json
pcs validate examples/verifier_assurance/VerifierReplayReport.v1.valid.json
pcs validate examples/verifier_assurance/VerifierMutationManifest.v1.valid.json
pcs conformance run --suite verifier-assurance
```

From OVK (after pin resolution):

```bash
ovk verifier validate-evidence path/to/evidence/
python -c "from ovk.assurance.pin import require_pcs_pin, verify_pin_digests; print(require_pcs_pin()); verify_pin_digests()"
```

## Dependency for assurance

Assurance CLI (`ovk verifier …`) and PCS export/validation require a resolved pin. Ordinary `ovk check` / MCP / Action paths do not require pcs-core.

## Non-claims

Pinning PCS schemas does not assert checker correctness. Profiles and results bind digests and decisions only. See pcs-core `docs/verifier-assurance/non-claims.md` and ADR 0001 exclusions. PyPI publish of pcs-core remains a separate release step and is not implied by this pin.
