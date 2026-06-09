# Evidence Invariants

OVK now includes conservative evidence bundle invariant checks.

## Purpose

Evidence generation is only useful if the resulting bundle is internally consistent. The invariant checker gives maintainers a local quality gate for release artifacts and future CI integration.

## Current checks

- Evidence bundles must contain at least one evidence item.
- Evidence identifiers must be unique inside a bundle.
- Each evidence item must include at least one backend claim.
- Evidence decisions must include a merge recommendation.
- Unknown or error backend claims must not produce an allow recommendation.
- Unknown or error backend claims must require human review.
- Failing backend claims must not produce an allow recommendation.
- Bundle decisions must include a merge recommendation.

## Script

```text
scripts/check_evidence_invariants.py
```

The script reads an evidence bundle JSON file and exits non-zero when invariant issues are found.

## Tests

```text
tests/test_evidence_invariants.py
tests/test_check_evidence_invariants_script.py
```
