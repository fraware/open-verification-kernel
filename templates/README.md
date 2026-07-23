# Verification Intent Templates

Templates are reusable engineering obligations that OVK can apply to agent-authored or human-authored changes.

A template is backend-neutral. It describes what must remain true, expected failure modes, acceptable evidence classes, and merge policy. The router later chooses OPA, Z3, Cedar, CBMC, Kani, TLA+, Dafny, Verus, Lean, Alloy, or another backend.

## Library (100 templates)

The library ships **100** schema-valid intent templates under domain folders.
Domain counts are derived from `docs/benchmarks/template-conformance.json`
(regenerate with `python scripts/build_template_conformance.py --print-domain-counts`):

| Domain | Count | Example templates |
|---|---|---|
| `agent_authority/` | 12 | `agent_cannot_disable_own_gate`, `opa_self_approval_block`, `dafny_authority_invariant` |
| `authorization/` | 18 | `no_admin_route_bypass`, `cedar_iam_admin_deny`, `rust_kani_bounds_check` |
| `ci_cd/` | 19 | `no_secrets_in_untrusted_context`, `kani_no_panic_in_auth_flow`, `z3_secret_flow_check` |
| `data_boundary/` | 15 | `cbmc_buffer_bounds`, `lean_type_safety`, `cbmc_no_use_after_free_auth_cache` |
| `deployment/` | 17 | `no_skipped_approval_state`, `tla_rollback_safety`, `tla_rollout_requires_green_health` |
| `infrastructure/` | 19 | `no_public_sensitive_resource`, `alloy_topology_reachability`, `no_public_egress_alloy` |

Production readiness is tracked in the conformance matrix. A template remains
`catalog_only` unless every required executable link exists; unsupported public
executable claims are downgraded honestly.

Validate the full library:

```bash
python scripts/validate_templates.py
```

List and inspect templates from the CLI:

```bash
ovk template list
ovk template show templates/ci_cd/agent_cannot_disable_own_gate.intent.json
```

Expand or regenerate library entries (maintainers):

```bash
python scripts/expand_ovk_library.py
```

## Template requirements

Each template should include:

- `intent_id`
- domain
- scope
- actor and resource shape
- property kind
- natural-language invariant
- formal hint
- failure modes
- acceptable evidence classes
- risk
- merge policy
- anti-vacuity guidance for high-risk templates

Schema and examples: [docs/SCHEMA_INDEX.md](../docs/SCHEMA_INDEX.md).
