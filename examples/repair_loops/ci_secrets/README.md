# CI secrets repair loop

This directory demonstrates the OVK agent repair loop for the **ci_secrets** lane.

## Files

| File | Role |
|------|------|
| `failing.diff` | Agent PR that exposes `secrets.*` on an untrusted `pull_request` trigger |
| `passing.diff` | Repaired PR: secrets removed and trigger moved to `workflow_dispatch` |

## Quick reproduction

```bash
# 1. Initial check blocks
ovk check --changed-files examples/repair_loops/ci_secrets/failing.diff --repo example/repo --head-sha seed

# 2. Inspect repair hints
ovk repair-suggest ovk-evidence.json

# 3. Apply the passing diff (or follow the hint), rerun
ovk check --changed-files examples/repair_loops/ci_secrets/passing.diff --repo example/repo --head-sha repaired
```

Expected outcome: first run `block` with `remove_untrusted_secret_usage`; second run `allow`.
