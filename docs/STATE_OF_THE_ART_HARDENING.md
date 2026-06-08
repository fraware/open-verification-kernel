# State-of-the-Art Hardening Plan

This document records the hardening steps required to move OVK from bootstrap to a serious v0.

## 1. Evidence honesty

Every backend result must preserve the distinction between pass, fail, unknown, error, and skipped. Unknown solver coverage, missing metadata, missing binaries, timeouts, parse failures, and unsupported theories must not become passing claims.

## 2. Tool execution

The first deterministic evaluators are intentionally useful for CI portability. The production path should add real tool execution behind the same adapter interfaces.

### OPA path

- Add an OPA CLI runner.
- Keep deterministic evaluator as fallback and fixture oracle.
- Preserve policy evaluation status, assumptions, limits, and raw output references.
- Treat missing OPA binary as unknown.

### Z3 path

- Use `pip install -e '.[solvers]'` to install `z3-solver`.
- Keep deterministic route abstraction for fixtures.
- Encode route reachability as a satisfiability query.
- Record query polarity in the obligation and evidence.
- Treat missing solver as unknown.

## 3. Backend routing

The v0 router is rule-based and manifest-driven. The next version should add:

- repository policy preferences;
- runtime budgets;
- historical adapter success rates;
- risk-tier escalation;
- explicit rejected-backend explanations.

## 4. Attestation

The current attestation helper emits an unsigned in-toto-style statement. The next version should add:

- content-addressed evidence bundles;
- DSSE wrapping;
- GitHub artifact upload;
- optional Sigstore integration;
- immutable linkage to commit SHA and workflow run.

## 5. GitHub Action

The Action is still scaffolded because connector controls blocked direct rewiring during bootstrap. The intended runner is:

```bash
ovk demo-self-protection examples/no_agent_self_approval/input_gate_removed.json \
  --output ovk-evidence.json \
  --markdown-output ovk-pr-comment.md \
  --repo "$GITHUB_REPOSITORY" \
  --head-sha "$GITHUB_SHA"
```

The production Action should later use real PR metadata and repository diff inference instead of demo fixtures.

## 6. Benchmarking

The seed benchmark already scores four cases. The next version should add:

- invalid and adversarial cases;
- weak-spec and vacuity cases;
- missing-metadata cases;
- timeout and unknown cases;
- multi-backend routing cases;
- repair-loop cases.
