# Oracle rules — Tier-A pilot N=10

Status: frozen for sealed pilot adjudication under `rtk.oracle.pilot_n10.path_identity_carry.v0`.

## Scope

Primary Tier A (`REPLAY_VERIFIED`) only. Tier B is out of scope for confirmatory labels.

## Independence

Adjudicators must not receive:

- RTK predictions or certificates
- baseline predictions
- aggregate RTK results
- RTK-derived failure taxonomies

Allowed materials: historical anchors, source-evidence / CDI records, frozen mappings,
transition census (including v2 overlays), and repository-native historical artifacts
recorded in those sealed objects.

## Verdict rule (path-identity carry)

For each Tier-A case with sealed `native_accept=true` on the selected candidate:

1. Let **A** be the claim evidence artifact paths from the sealed evidence snapshot.
2. Let **C** be `changed_paths` from the sealed census record for the transition.
3. If **A ∩ C = ∅**: verdict **VALID** — source-native accept plus path-identical claim
   evidence across the transition under this carry rule.
4. If **A ∩ C ≠ ∅** and `target_native_validator_executed` is false: verdict
   **REVALIDATION_REQUIRED** — claim evidence paths changed; applicability cannot be
   carried from existing source evidence alone.
5. Otherwise: **UNRESOLVED** with an explicit reason. UNRESOLVED is legitimate and must
   not be forced into VALID/INVALID/REVALIDATION_REQUIRED to inflate N.

## Non-claims

These rules do not weaken Tier A admission predicates, do not promote Tier B, and do
not authorize unblinding or holdout-driven RTK semantic patches.
