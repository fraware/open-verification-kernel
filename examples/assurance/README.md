# Examples: assurance evidence packs

Generated offline packs for assurance-capable backends. Ordinary CI does not consume these. Paths inside packs are repo-relative (no host absolute paths).

| Directory | Backend | Notes |
|---|---|---|
| `auth-state-predicate/` | `auth-state-predicate` | Exact authoritative-state predicates |
| `pytest-suite/` | `pytest-suite` | Observational pytest run |
| `sql-state-diff/` | `sql-state-diff` | SQLite fixture diff |
| `model-judge/` | `model-judge` | Contract-fake stochastic judge |

Each pack includes PCS `VerifierInvocationRecord.v1`, `VerifierProfile.v1`, and `VerificationResult.v1` plus OVK-local sidecars. OPA (`opa-policy`) and Lean (`lean-pfcore`) packs are omitted from the committed tree because those toolchains are optional. Generate locally into a gitignored scratch dir:

```bash
ovk verifier run --backend opa-policy --input <input.json> --evidence-dir .ovk-assurance-opa/
ovk verifier run --backend lean-pfcore --input <input.json> --evidence-dir .ovk-assurance-lean/
```

When `opa` or `lean` is missing, the run must return a typed indeterminate decision — never a fabricated accept.

Validate a committed pack (requires the resolved pcs-core pin from [docs/PCS_PIN.md](../../docs/PCS_PIN.md)):

```bash
ovk verifier validate-evidence examples/assurance/auth-state-predicate
```

See [docs/assurance/GUIDE.md](../../docs/assurance/GUIDE.md).
