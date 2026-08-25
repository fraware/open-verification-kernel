# Template claim registry

Bridges [template conformance](../docs/benchmarks/template-conformance.json) onto the
normative capability vocabulary (`release_status`, `claim_class`) without inventing
a second status system.

| File | Role |
|---|---|
| `bridge.json` | Maps `conformance_status_v3` → `release_status` (normative maturity field) |
| `entries.json` | Generated per-template claim registry entries |

Regenerate:

```bash
python scripts/build_template_registry.py
```

Freshness gate (CI):

```bash
python scripts/build_template_registry.py --check
```

Honesty: `stable` is not emitted; even `source_profile_strict_eligible` maps to `preview`
until OVK-PR4 conformance gates exist.
