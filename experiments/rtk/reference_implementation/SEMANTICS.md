# RTK reference implementation semantics (v0)

Status: explicit **reference predictor**, not a recovered historical checker.

## Non-claims

- This is **not** the unrecovered historical Go production checker.
- Go checker status remains **UNVERIFIED** (see `GO_CHECKER_PROVENANCE.v0.md`).
- No 30/30 Go parity claim is made or implied.
- Holdout / Tier-A sealed cases must not drive semantics or act as development oracles.
- This package does not authorize oracle labeling, baseline execution, or unblinding.

## Interface

- **Input:** `CanonicalDecisionInput.v1` (frozen schema + canonicalization).
- **Output:** sealed-verdict-shaped prediction records with verdict space
  `VALID | INVALID | REVALIDATION_REQUIRED | UNRESOLVED`, plus operational
  failure records that are never mapped to `VALID`.

## Decision procedure (derived only from frozen protocol text)

The predictor uses only fields present on CanonicalDecisionInput.v1 and the
verdict definitions in `PROTOCOL.md` / `ANALYSIS_PLAN.md`.

1. **Structural gate.** Validate against the CDI schema and recompute
   `canonical_digest` per
   `specs/CanonicalDecisionInput.v1.canonicalization.md`. Schema or digest
   failure → `OPERATIONAL_FAILURE` (not a favorable verdict).
2. **Material sufficiency (`UNRESOLVED`).** If evidence completeness is
   `UNKNOWN`, historical material is insufficient for a defensible
   applicability judgment under the frozen rules → `UNRESOLVED`.
3. **Incomplete evidence (`REVALIDATION_REQUIRED`).** If completeness is
   `INCOMPLETE`, applicability cannot be carried from the existing evidence
   alone → `REVALIDATION_REQUIRED`. When `repair_catalog_ref` is present, its
   `catalog_id` is surfaced as the predicted repair reference.
4. **Internal incompatibility (`INVALID`).** If completeness is `COMPLETE`
   but declared `context_footprint.elements` are not covered by
   `evidence_snapshot.artifact_refs` paths, the snapshot is incompatible with
   its claimed footprint → `INVALID`.
5. **Applicability across the transition.**
   - Let `impacted = changed_paths ∩ footprint.elements` (exact path set
     intersection; arrays are treated as the uniqueItems sets defined by the
     schema).
   - Empty `impacted` → `VALID` (no claim-relevant context path changed; claim
     remains supported by source evidence under the target context for this
     structural reference).
   - Non-empty `impacted` → `REVALIDATION_REQUIRED` (applicability cannot be
     carried across from existing evidence alone). Repair catalog reference is
     attached when present.

Exact path intersection is intentional: prefix/heuristic expansion is not in
the frozen CDI contract and must not be invented here.

## Development / test policy

Conformance tests use only synthetic fixtures under `fixtures/`. Do not load
sealed Tier-A holdout targets as development oracles.
