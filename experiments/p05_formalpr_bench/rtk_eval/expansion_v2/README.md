# expansion_v2 adapter package

Status: `V2_METHODOLOGY_INTERFACE_FROZEN_PENDING_MATERIALIZATION`

This package defines the **generic source-repository adapter contract** for
source-universe expansion protocol v2. It is **new** code. It is not recovered
authentic `generate_transition_census.py` / v0 extractor material.

Protocol: `experiments/rtk/SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v2.md`

## Layout

| Path | Role |
|---|---|
| `adapter_contract.py` | ABC + record types for the seven required operations |
| `reason_codes.py` | Frozen exclusion reason-code set |
| `prohibitions.py` | Guards against RTK / oracle / target-validator / unblind |
| `registry.py` | v0 + five frozen expansion identities (placeholders) |
| `generate_transition_census_v2.py` | New census skeleton; refuses live overlay writes |
| `tests/` | Contract, prohibition, reason-code, and v0 compatibility harness |

## Required adapter operations

1. Deterministic transition enumeration (`enumerate_transitions`)
2. Governed-artifact discovery (`discover_governed_artifacts`)
3. Historical claim-anchor extraction (`extract_claim_anchors`)
4. Source-evidence candidate discovery (`discover_source_evidence_candidates`)
5. Source-revision native-validator execution (`execute_source_revision_native_validator`)
6. Subject binding (`bind_subject`)
7. Evidence-snapshot construction (`construct_evidence_snapshot`)

## Freeze-before-materialization

- Interface + tests land first (this package).
- v0 compatibility harness must pass semantic equivalence on CertifyEdge /
  pcs-core overlapping surface before external expansion.
- Only then may repository-specific semantic mapping process the five frozen
  candidates. This package does **not** perform that processing.

## Authentic v0 modules

Do not edit:

- `../extract_historical_anchors.py`
- `../materialize_source_evidence.py`
- `../project_source_evidence_semantics.py`
- `../tier_source_evidence_v1.py`
