# expansion_v2 adapter package

Status: `V2_EXPANSION_EXHAUSTED_BELOW_20`

This package defines the **generic source-repository adapter contract** and
repository-specific adapters for source-universe expansion protocol v2. It is
**new** code. It is not recovered authentic `generate_transition_census.py` /
v0 extractor material.

Protocol: `experiments/rtk/SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v2.md`

## Layout

| Path | Role |
|---|---|
| `adapter_contract.py` | ABC + record types for the seven required operations |
| `reason_codes.py` | Frozen exclusion reason-code set |
| `prohibitions.py` | Guards against RTK / oracle / target-validator / unblind |
| `registry.py` | Concrete v0 + five frozen expansion adapters |
| `adapters/` | CertifyEdge, pcs-core, and five candidate adapters |
| `generate_transition_census_v2.py` | New census helpers (not authentic v0) |
| `pipeline.py` | census → extract → materialize → project → tier |
| `run_expansion_materialization.py` | Authorized walk of the five frozen candidates |
| `tests/` | Contract, prohibition, reason-code, and v0 compatibility harness |

## Required adapter operations

1. Deterministic transition enumeration (`enumerate_transitions`)
2. Governed-artifact discovery (`discover_governed_artifacts`)
3. Historical claim-anchor extraction (`extract_claim_anchors`)
4. Source-evidence candidate discovery (`discover_source_evidence_candidates`)
5. Source-revision native-validator execution (`execute_source_revision_native_validator`)
6. Subject binding (`bind_subject`)
7. Evidence-snapshot construction (`construct_evidence_snapshot`)

## Compatibility and expansion

- v0 compatibility harness requires CertifyEdge / pcs-core adapters to match
  sealed transition identities and the sealed HISTORICAL_ANCHORS digest, and
  decision-surface semantic equivalence via the authentic materializer bridge.
- Only after that gate may the five frozen candidates be processed under
  identical admission rules.
- Binding / walk outputs: `experiments/rtk/SOURCE_UNIVERSE_V2_BINDING.json`,
  `experiments/rtk/SOURCE_UNIVERSE_V2_EXPANSION_WALK.json`.

## Authentic v0 modules

Do not edit:

- `../extract_historical_anchors.py`
- `../materialize_source_evidence.py`
- `../project_source_evidence_semantics.py`
- `../tier_source_evidence_v1.py`
