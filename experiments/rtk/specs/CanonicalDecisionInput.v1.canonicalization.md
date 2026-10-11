# CanonicalDecisionInput.v1 canonicalization

Status: frozen specification. Implementation-independent.

## Principle

`CanonicalDecisionInput.v1` defines the sealed evaluation input corpus
independent of any checker language or serialization convenience format.
Go struct tags, protobuf encodings, or Python `json.dumps` defaults must not
define corpus identity.

## Digest algorithm

- Hash: SHA-256
- Encoding: UTF-8
- Field excluded from the preimage: `canonical_digest`

## Canonical JSON preimage

1. Take the decision-input object with `canonical_digest` removed.
2. Emit JSON with:
   - recursive key sort at every object
   - no insignificant whitespace (`separators=(',', ':')` equivalent)
   - arrays preserve declared order (do not sort array elements unless a field
     explicitly defines a sorted set representation)
   - `uniqueItems` string arrays in this schema are stored in lexicographic
     ascending order before hashing: `changed_paths`, `elements`, and
     `artifact_refs` sorted by `path`
3. UTF-8 encode the compact JSON string.
4. SHA-256 hex digest (lowercase) becomes `canonical_digest`.

## Mapping order

1. Freeze this schema and canonicalization text.
2. Materialize source evidence / mappings
   (`CONTEXT_FOOTPRINT_MAPPING.v0` → `RELYING_PROFILE_MAPPING.v0` →
   `REPAIR_CATALOG_MAPPING.v0`).
3. Emit CDI instances.
4. Only then bind an evaluated implementation identity for execution.

Go checker recovery is **not** a prerequisite for steps 1–3.

## Non-claims

This specification does not authorize RTK prediction, oracle labeling, baseline
runs, or unblinding.
