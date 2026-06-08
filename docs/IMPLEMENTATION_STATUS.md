# Implementation Status

## Completed in current bootstrap

- Core JSON schemas for intents, capabilities, obligations, results, evidence, and bundles.
- Python package skeleton with typed models.
- Conservative decision engine.
- Evidence bundle builder.
- Markdown renderer for PR-readable evidence.
- OPA-style self-protection adapter.
- Z3-style authorization reachability adapter.
- Fixtures for failing and passing self-protection cases.
- Fixtures for failing and passing authorization cases.
- Tests for decision logic, schemas, rendering, self-protection, and authorization.
- Seed benchmark cases and scoring harness.
- CI updated to run tests and seed benchmark scoring.

## Current runnable commands

Self-protection failure:

```bash
python scripts/run_self_protection_demo.py examples/no_agent_self_approval/input_gate_removed.json
```

Self-protection pass:

```bash
python scripts/run_self_protection_demo.py examples/no_agent_self_approval/input_gate_preserved.json
```

Authorization failure:

```bash
python scripts/run_authorization_demo.py examples/auth_regression/input_admin_bypass.json
```

Authorization pass:

```bash
python scripts/run_authorization_demo.py examples/auth_regression/input_admin_protected.json
```

Seed benchmark:

```bash
python benchmarks/formal_pr_bench/score_seed_cases.py
```

## Known limitations

- The first OPA path is implemented as deterministic Python with OPA-style semantics. A real OPA CLI adapter should be wired next.
- The first Z3 path is a deterministic reachability checker that preserves the intended evidence semantics. A real SMT encoding should be wired next.
- GitHub Action enforcement is still scaffolded. Connector controls blocked direct Action rewiring during this session.
- Repository-diff-based intent inference is still a placeholder.
- PR comment posting is implemented as Markdown rendering, not yet as a GitHub API integration.

## Next implementation priorities

1. Wire real OPA CLI execution behind the existing self-protection adapter.
2. Wire real Z3 constraints behind the authorization adapter.
3. Replace the GitHub Action placeholder with `ovk demo-self-protection` or a proper `ovk ci` entry point.
4. Implement repository diff parsing for GitHub Actions workflows and `.verification/` files.
5. Add PR comment posting and artifact upload integration.
6. Add a capability registry loader and adapter router.
