# Authorization Obligation Runner

The authorization obligation runner is the Sprint 3 demo path for the Z3-backed authorization architecture.

## Purpose

The runner exercises the new authorization pipeline:

```text
authorization fixture
→ AuthorizationObligation
→ optional Z3 executor
→ normalized Z3 result
→ VerificationEvidence
→ evidence bundle
→ Markdown report
→ unsigned attestation statement
```

## Command

```bash
python scripts/run_authorization_obligation.py \
  examples/auth_regression/input_admin_bypass.json \
  --repo example/repo \
  --head-sha demo-head \
  --evidence-output ovk-auth-evidence.json \
  --markdown-output ovk-auth-comment.md \
  --attestation-output ovk-auth-attestation.json \
  --advisory
```

## Output files

The runner writes:

- `ovk-auth-evidence.json`
- `ovk-auth-comment.md`
- `ovk-auth-attestation.json`

## Result semantics

| Solver result | OVK recommendation |
|---|---|
| violation model found | `block` |
| no violation model found | `allow` |
| solver unavailable or unknown | `require_human_review` |

## Current caveat

The runner uses the optional Z3 executor. If `z3-solver` is not installed, the executor returns `unknown` and the evidence bundle recommends `require_human_review`. This is intentional and preserves the evidence discipline.

## Next step

The remaining Sprint 3 integration work is to expose this path through a first-class `ovk` CLI command and optionally route the existing authorization adapter through the same obligation-backed path.
