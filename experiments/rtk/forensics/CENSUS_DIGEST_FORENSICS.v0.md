# Census digest forensics (source-universe-v0)

Status: **HARD_STOP_DIGEST_MISMATCH**

Machine-readable twin: `CENSUS_DIGEST_FORENSICS.v0.json`.

## Verdict

| Check | Result |
|---|---|
| FIRST_PARENT cardinality at frozen cutoffs | **248** (50 CertifyEdge + 198 pcs-core) — matches sealed |
| Sealed census SHA-256 | **NOT reproduced** under any honest local serialization attempted |
| Anchors / semantic projection | **Not materialized** (stopped; would invent semantics) |
| `SOURCE_EVIDENCE_V1_BINDING.json` | **UNCREATED** |

## Immutable targets (unchanged)

- CertifyEdge: `6ef02d54c4697886b20577f10eec683861475db2`
- pcs-core: `9c971f5f9da8a424924dd8f48d6a3b71a1009e1b`
- Census: 248 / `b1816276176297adf345981fe5d9c8271cf00f5b71653d59a21d8261d64a6b11`
- Anchors: 541 / `44cb1f2701705375e9354b4a51a07064d2dba2d33f757e0955fc03db00d4d5cc`
- Projection: `7ea32cb2c579077f281a3356683a3e926872492b6e756b44c0c39d077358f1fe`

## What was ruled out

Local full (non-shallow) clones of the public cutoffs produce the sealed **cardinality**. Digests still miss for:

- JSON array / wrapped `source_universe_census.v0` object / NDJSON
- `sort_keys` compact vs pretty ± trailing newline
- Dropping null `exclusion_reason`; schema-required fields only
- Sorted unique `changed_paths` vs git diff order
- Two-dot vs three-dot path diffs
- Committer vs author ISO timestamps
- Short-12 vs full-SHA `transition_id`
- CSV / SHA-pair reductions

Candidate artifact (not sealed): `CENSUS_CANDIDATE.source_universe_census.v0.json`.

## Why byte-level diff is unavailable

The sealed census **bytes** are not on this repository and were not recovered from public CertifyEdge/pcs-core trees or public digest search. Without sealed bytes, only candidate SHA-256 values can be compared to the published digest. A true byte-level diff requires the sealed artifact or the historically intended `generate_transition_census` implementation and its canonicalization contract.

## Why the pipeline was not invented

Porting `generate_transition_census` / `extract_historical_anchors` / `materialize_source_evidence` / `project_source_evidence_semantics` / `tier_source_evidence_v1` from private prior trees is out of scope for this pass. Reconstructing those modules until a hash matches would create **new** semantics to chase digests, which is forbidden. Anchor cardinality probes over public trees did not yield an honest rule that produces exactly 541 without additional private extraction rules.

## Binding rule applied

Create `SOURCE_EVIDENCE_V1_BINDING.json` only after a full pipeline run at one SHA matches all frozen cardinalities **and** digests. That condition is not met.

## Prohibitions honored

No oracle, no RTK prediction, no baseline execution, no unblinding, no criterion weakening, no fabricated CI/run IDs.
